"""Bounded supplementary evidence tools. All conclusions remain analyst leads."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_diagnostics import _redact_diagnostic
from castorpollux_core import sha256
from castorpollux_integrity import authenticode_status
from castorpollux_review import coverage_rows


def _rows(folder: Path, name: str) -> list[dict]:
    path = Path(folder) / name
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        return list(csv.DictReader(stream))


def _json(folder: Path, name: str) -> dict:
    path = Path(folder) / name
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def dll_signature_inventory(folder: Path, binary: Path, verify=authenticode_status) -> dict:
    """Inspect only same-directory DLL candidates; import resolution is runtime-dependent."""
    folder, binary = Path(folder), Path(binary)
    namespaces = {str(row.get("namespace", "")).strip() for row in _rows(folder, "imports.csv")}
    names = sorted({Path(name).name for name in namespaces
                    if name.lower().endswith(".dll") and Path(name).name == name}, key=str.casefold)
    neighbours = {item.name.casefold(): item for item in binary.parent.iterdir()
                  if item.is_file() and item.suffix.casefold() == ".dll"}
    entries = []
    for name in names[:512]:
        candidate = neighbours.get(name.casefold())
        row = {"import": name, "resolution": "adjacent candidate" if candidate else "unresolved locally"}
        if candidate:
            row["sha256"] = sha256(candidate)
            row["signature"] = verify(candidate)
            row["file_name"] = candidate.name
        entries.append(row)
    result = {"generated_at": datetime.now(timezone.utc).isoformat(), "dlls": entries,
              "truncated": len(names) > 512,
              "limitation": "Adjacent files are candidates. Windows loader search and runtime-loaded DLLs are not verified."}
    (folder / "dll-signatures.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def cve_reachability(folder: Path) -> dict:
    """Look for graph paths to fingerprinted library functions; CVE-specific paths remain unknown."""
    folder = Path(folder)
    libraries = {row.get("name"): row for row in _json(folder, "embedded-libraries.json").get("libraries", [])}
    calls = _rows(folder, "calls.csv")
    incoming = {}
    for row in calls:
        caller, callee = row.get("caller_name", ""), row.get("callee_name", "")
        if caller and callee:
            incoming.setdefault(callee.casefold(), set()).add(caller)
    results = []
    for item in _json(folder, "known-vulnerabilities.json").get("results", []):
        library = libraries.get(item.get("library"), {})
        targets = library.get("corroborating_functions", [])
        paths = []
        for target in targets:
            matching_names = [name for name in incoming if name.startswith(target.casefold())]
            frontier = [(name, [name]) for name in matching_names] or [(target, [target])]
            seen = set()
            while frontier and len(seen) < 5000:
                node, path = frontier.pop(0)
                if node.casefold() in seen or len(path) > 8:
                    continue
                seen.add(node.casefold())
                parents = sorted(incoming.get(node.casefold(), ()))
                if not parents and len(path) > 1:
                    paths.append(list(reversed(path)))
                else:
                    frontier.extend((parent, path + [parent]) for parent in parents[:30])
            if len(paths) >= 10:
                break
        state = "candidate call path" if paths else "unknown"
        for advisory in item.get("advisories", []):
            results.append({"cve": advisory["id"], "library": item["library"], "version": item.get("version"),
                            "status": state, "call_paths": paths[:10],
                            "limitation": "A generic call path to a library function does not establish reachability of the CVE's vulnerable code or applicability."})
    result = {"generated_at": datetime.now(timezone.utc).isoformat(), "results": results,
              "limitation": "Static call graphs are incomplete under indirect calls, dynamic loading and stripped symbols."}
    (folder / "cve-reachability.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def minimize_candidate_input(folder: Path, sample: Path) -> dict:
    """Trim obvious padding in a sample without running the target or claiming a reproducer."""
    folder, sample = Path(folder), Path(sample)
    if sample.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Candidate input exceeds 16 MiB")
    data = sample.read_bytes()
    if not data:
        raise ValueError("Candidate input is empty")
    reduced = re.sub(rb"([\x00\xff])\1{63,}", lambda m: m.group(1) * 32, data)
    if len(reduced) == len(data):
        reduced = data.rstrip(b"\x00") or data
    destination_dir = folder / "proofs-of-concept"
    destination_dir.mkdir(exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()[:12]
    output = destination_dir / f"candidate-input-{digest}.bin"
    output.write_bytes(reduced)
    result = {"source_sha256": hashlib.sha256(data).hexdigest(), "source_bytes": len(data),
              "candidate_sha256": hashlib.sha256(reduced).hexdigest(), "candidate_bytes": len(reduced),
              "candidate_file": str(output.relative_to(folder)), "verified_reproducer": False,
              "limitation": "Only repeated zero/FF padding or trailing zeros were shortened. The result may not reproduce the observation."}
    (destination_dir / f"candidate-input-{digest}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def link_crash_log(folder: Path, log: Path) -> dict:
    """Map literal absolute crash addresses to decompiled procedure ranges."""
    folder, log = Path(folder), Path(log)
    content = log.read_text(encoding="utf-8", errors="replace")[:2_000_000]
    functions = []
    for row in _rows(folder, "functions.csv"):
        try:
            start = int(row["entry"], 16)
            size = int(row.get("body_bytes", "0"))
            if size > 0:
                functions.append((start, start + size, row))
        except (ValueError, KeyError):
            continue
    code = {int(row["address"], 16): row for row in coverage_rows(folder)
            if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", row["address"])}
    links = []
    for literal in dict.fromkeys(re.findall(r"\b0x[0-9a-fA-F]{6,16}\b", content)):
        address = int(literal, 16)
        match = next((row for start, end, row in functions if start <= address < end), None)
        if not match:
            continue
        entry = int(match["entry"], 16)
        procedure = code.get(entry, {})
        links.append({"crash_address": literal, "function": match.get("name", ""),
                      "entry": match["entry"], "offset": address - entry,
                      "pseudocode_available": bool(procedure.get("pseudocode")),
                      "confidence": "address range only"})
    result = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "links": links[:200],
              "limitation": "Requires absolute addresses in the same image base as the export. ASLR/module bases and stack quality are not inferred."}
    (folder / "crash-links.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def disclosure_packet(folder: Path, destination: Path) -> Path:
    """Export redacted, hash-verified review evidence without original binary or full pseudocode."""
    folder, destination = Path(folder), Path(destination)
    report = _json(folder, "security-review-data.json") or _json(folder, "security-report.json")
    if not report:
        raise ValueError("Run and save an agent review first")
    manifest = _json(folder, "manifest.json")
    summary = {"input_name": manifest.get("input_name"), "sha256": manifest.get("sha256"),
               "engine_versions": report.get("analysis_context", {}).get("engine_versions", {}),
               "review_created_at": report.get("created_at")}
    findings = report.get("result", {}).get("findings", [])
    packet = {"target": summary, "findings": findings, "disclosure_state": "draft",
              "limitation": "Agent findings and candidate inputs are unverified. Validate before reporting."}
    files = {"disclosure-report.json": json.dumps(packet, indent=2),
             "COVER-LETTER.md": "# Coordinated disclosure draft\n\nAffected product and vendor: [complete]\nContact channel: [complete]\nPrivate report date: [complete]\nRequested acknowledgment date: [complete]\nPublic disclosure date: [coordinate with vendor]\n\nSee disclosure-report.json for evidence and validation limits.\n"}
    for name in ("cve-reachability.json", "crash-links.json"):
        path = folder / name
        if path.is_file():
            files[name] = path.read_text(encoding="utf-8", errors="replace")[:500_000]
    redacted = {name: _redact_diagnostic(value) for name, value in files.items()}
    hashes = {name: hashlib.sha256(value.encode("utf-8")).hexdigest() for name, value in redacted.items()}
    redacted["SHA256.json"] = json.dumps(hashes, indent=2)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in redacted.items():
            archive.writestr(name, value)
    return destination
