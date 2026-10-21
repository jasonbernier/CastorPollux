"""Bounded, provenance-aware evidence attached to security findings."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from pathlib import Path


MARKER = re.compile(r"/\* ===== (.*?) @ ((?:0x)?[0-9a-fA-F]+) ===== \*/")
ADDRESS = re.compile(r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{8,16}(?![0-9a-fA-F])")
MAX_EXCERPTS = 3
MAX_EXCERPT_LINES = 18


def _address(value: str) -> str:
    return str(value or "").casefold().removeprefix("0x").lstrip("0") or "0"


def _csv_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        return list(csv.DictReader(stream))


def csv_safe(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def export_source_map(folder: Path) -> dict:
    """Map saved pseudocode lines to procedure addresses and available Ghidra symbols.

    Ghidra's symbol export has no original source-file line table, so this map never
    claims to identify original source lines.
    """
    folder = Path(folder)
    source = folder / "rea-pseudocode.c"
    if not source.is_file():
        raise FileNotFoundError("REA pseudocode is not saved yet")
    source_bytes = source.read_bytes()
    lines = source_bytes.decode("utf-8-sig", errors="replace").splitlines()
    symbols = {}
    for row in _csv_rows(folder / "symbols.csv"):
        if row.get("type", "").casefold() == "function" and row.get("external", "").casefold() != "true":
            symbols[_address(row.get("address", ""))] = row
    entries = []
    for number, line in enumerate(lines, 1):
        match = MARKER.fullmatch(line.strip())
        if not match:
            continue
        if entries:
            entries[-1]["end_line"] = number - 1
        name, address = match.groups()
        symbol = symbols.get(_address(address), {})
        symbol_name = str(symbol.get("name") or "")
        entries.append({"file": source.name, "start_line": number, "end_line": len(lines),
                        "address": address, "rea_name": name,
                        "symbol_name": symbol_name, "namespace": symbol.get("namespace", ""),
                        "symbol_source": symbol.get("source", ""),
                        "symbol_kind": "named" if symbol_name and not re.fullmatch(r"FUN_[0-9a-fA-F]+", symbol_name)
                        else "generated" if symbol_name else "absent"})
    document = {"format": "CastorPollux reconstructed-source map v1",
                "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                "limitation": "Lines refer to REA reconstructed pseudocode, not the binary's original source files.",
                "entries": entries}
    (folder / "source-map.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
    with (folder / "source-map.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("file", "start_line", "end_line", "address",
                                                    "rea_name", "symbol_name", "namespace",
                                                    "symbol_source", "symbol_kind"))
        writer.writeheader()
        writer.writerows({key: csv_safe(value) for key, value in entry.items()}
                         for entry in entries)
    return document


def confirmation_steps(finding: dict) -> list[dict]:
    kind = finding.get("vulnerability_type", "other")
    specific = {
        "buffer_overflow": "Verify attacker-controlled length, destination capacity, and every bounds check.",
        "command_injection": "Verify input reaches command construction and inspect argument separation or escaping.",
        "privilege_escalation": "Verify the lower-trust caller, permission boundary, and privileged operation.",
        "memory_safety": "Verify object lifetime, bounds, and the relevant memory access in disassembly.",
    }.get(kind, "Verify the claimed input, trust boundary, and risky operation.")
    labels = ["Confirm the target hash, engine versions, and review scope match this finding.",
              "Locate each cited procedure and compare pseudocode with saved disassembly.",
              specific,
              "Check alternate branches, sanitizers, preconditions, and counter-evidence.",
              "Use an authorized, isolated validation method; record the observed result.",
              "Record the remediation and rescan the changed build to check the same flow."]
    return [{"id": f"step-{index}", "label": label} for index, label in enumerate(labels, 1)]


def enrich_report_evidence(folder: Path, findings: list[dict]) -> None:
    """Attach code excerpts and transparent confidence factors without changing agent labels."""
    from castorpollux_review import coverage_rows, evidence_jump

    folder = Path(folder)
    source_map = export_source_map(folder)
    map_by_address = {_address(item["address"]): item for item in source_map["entries"]}
    rows = coverage_rows(folder)
    by_address = {_address(row["address"]): row for row in rows}
    source = folder / "rea-pseudocode.c"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest() if source.is_file() else ""
    for finding in findings:
        excerpts = []
        reasons = ["The confidence label was assigned by the review agent, not verified by CastorPollux."]
        agent_reason = str(finding.get("confidence_reason") or "").strip()[:2000]
        if agent_reason:
            reasons.append("Agent rationale: " + agent_reason)
        resolved = set()
        for citation in finding.get("evidence", [])[:12]:
            try:
                jump = evidence_jump(folder, citation)
            except (ValueError, OSError):
                continue
            row = by_address.get(_address(jump.get("address", "")))
            if row is None and citation.get("file") == "rea-pseudocode.c":
                generic = re.search(r"\bline\s+(\d+)\b", str(citation.get("location", "")), re.I)
                if generic and not re.search(r"\bprocedure\s+line\b", str(citation.get("location", "")), re.I):
                    number = int(generic.group(1))
                    mapped = next((item for item in source_map["entries"]
                                   if item["start_line"] <= number <= item["end_line"]), None)
                    if mapped:
                        row = by_address.get(_address(mapped["address"]))
            if not row or not row.get("pseudocode"):
                continue
            resolved.add(row["address"])
            if len(excerpts) >= MAX_EXCERPTS:
                continue
            code_lines = row["pseudocode"].splitlines()
            location = str(citation.get("location", ""))
            local_match = re.search(r"\bprocedure\s+line\s+(\d+)\b", location, re.I)
            generic_match = re.search(r"\bline\s+(\d+)\b", location, re.I)
            cited_line = int(local_match.group(1)) if local_match else None
            line_basis = "explicit procedure line" if local_match else ""
            if cited_line is None and generic_match and citation.get("file") == "rea-pseudocode.c":
                aggregate = int(generic_match.group(1))
                mapped = map_by_address.get(_address(row["address"]))
                if ADDRESS.search(location) and 1 <= aggregate <= len(code_lines):
                    cited_line = aggregate
                    line_basis = "addressed line interpreted as procedure-local"
                elif mapped and mapped["start_line"] < aggregate <= mapped["end_line"]:
                    cited_line = aggregate - mapped["start_line"]
                    line_basis = "aggregate reconstructed-source line"
            exact = bool(cited_line and 1 <= cited_line <= len(code_lines))
            first = max(1, cited_line - 5) if exact else 1
            last = min(len(code_lines), first + MAX_EXCERPT_LINES - 1)
            excerpt_lines = [f"{index:>5}  {code_lines[index-1][:240]}"
                             for index in range(first, last + 1)]
            excerpts.append({"file": "rea-pseudocode.c", "function": row["name"],
                             "address": row["address"], "citation": str(citation.get("location", "")),
                             "start_line": first, "end_line": last, "exact_line": exact,
                             "source_sha256": source_hash, "code": "\n".join(excerpt_lines),
                             "note": line_basis if exact else
                             "Function context only; exact statement was not resolved"})
        if resolved:
            reasons.append(f"{len(resolved)} cited REA procedure(s) resolve to saved reconstructed code.")
            for address in sorted(resolved)[:3]:
                row = by_address[_address(address)]
                reasons.append(f"{row['name']} @ {address}: decompiler confidence {row['confidence']} — "
                               f"{row['confidence_reason']}.")
        else:
            reasons.append("No cited REA procedure resolved; inspect the citations before relying on this finding.")
        path = finding.get("reachability", {}).get("path", [])
        reasons.append(f"Saved static call path contains {len(path)} procedure(s)." if path else
                       "No named-entry static call path was established; dynamic calls may be missing.")
        if any(not item["exact_line"] for item in excerpts):
            reasons.append("At least one excerpt is function context rather than an exact cited statement.")
        reasons.append("Runtime behavior and exploitability have not been confirmed.")
        finding["confidence_assessment"] = {"agent_label": finding.get("confidence", "unknown"),
                                             "reasons": reasons}
        finding["code_excerpts"] = excerpts
        finding["confirmation_checklist"] = confirmation_steps(finding)


def render_finding_images(destination: Path, findings: list[dict]) -> None:
    """Create one honest static-call-path PNG per finding, including unresolved routes."""
    from PIL import Image, ImageDraw, ImageFont

    assets = Path(destination) / "finding-assets"
    assets.mkdir(parents=True, exist_ok=True)
    try:
        regular = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 23)
        bold = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 27)
        small = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 18)
    except OSError:
        regular = bold = small = ImageFont.load_default()
    for number, finding in enumerate(findings, 1):
        path = finding.get("reachability", {}).get("path", [])[:14]
        nodes = path or [{"name": (finding.get("affected_functions") or ["Cited procedure"])[0],
                          "address": "unresolved"}]
        height = max(390, 230 + len(nodes) * 90)
        image = Image.new("RGB", (1400, height), "#071017")
        draw = ImageDraw.Draw(image)
        draw.text((52, 38), f"FINDING {number:02d}  /  STATIC CALL PATH", font=bold, fill="#83F7BA")
        draw.text((52, 82), str(finding.get("title", "Potential issue"))[:95], font=regular, fill="#EDF8F5")
        for index, node in enumerate(nodes):
            top = 142 + index * 90
            draw.rounded_rectangle((75, top, 1325, top+62), radius=12,
                                   fill="#152B36", outline="#53CFE0" if index else "#83F7BA", width=2)
            label = f"{str(node.get('name', ''))[:72]}   @   {str(node.get('address', ''))[:28]}"
            draw.text((100, top+16), label, font=regular, fill="#EDF8F5")
            if index < len(nodes)-1:
                draw.line((700, top+63, 700, top+88), fill="#53CFE0", width=3)
                draw.polygon(((692, top+82), (708, top+82), (700, top+91)), fill="#53CFE0")
        note = ("Saved direct-call path from a named entry. Static evidence only."
                if path else "No named-entry path established in saved calls.csv; reachability remains unresolved.")
        draw.text((52, height-54), note[:125], font=small, fill="#9DB8B9")
        filename = f"finding-{number:02d}-call-path.png"
        image.save(assets / filename, optimize=True)
        finding["call_path_image"] = "finding-assets/" + filename


def load_confirmation_state(folder: Path) -> dict:
    try:
        value = json.loads((Path(folder) / "finding-confirmation.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def save_confirmation_state(folder: Path, finding_id: str, checked: dict[str, bool]) -> Path:
    if not re.fullmatch(r"[0-9a-f]{20}", finding_id):
        raise ValueError("Invalid finding identifier")
    allowed = {f"step-{number}" for number in range(1, 7)}
    if set(checked) != allowed or any(type(value) is not bool for value in checked.values()):
        raise ValueError("Invalid confirmation checklist")
    destination = Path(folder) / "finding-confirmation.json"
    data = load_confirmation_state(folder)
    data[finding_id] = checked
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, destination)
    return destination
