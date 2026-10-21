"""Evidence-backed finding metadata and expiring analyst suppressions."""

from __future__ import annotations

import csv
import json
import os
import re
from collections import deque
from datetime import date, datetime, timezone
from pathlib import Path

from castorpollux_tracking import finding_signature


CWE_RULES = (
    ("CWE-120", "Buffer Copy without Checking Size of Input", r"\b(?:strcpy|strcat|sprintf|gets|wcscpy|wcscat)\s*\(", r"overflow|unchecked|unbounded|out.of.bounds|buffer"),
    ("CWE-78", "OS Command Injection", r"\b(?:system|popen|WinExec)\s*\(", r"command.injection|unsanitiz|untrusted|attacker.controlled"),
    ("CWE-22", "Path Traversal", r"\b(?:fopen|CreateFile[AW]?|open)\s*\(", r"path.traversal|directory.traversal|\.\.\/|\.\.\\"),
    ("CWE-190", "Integer Overflow or Wraparound", r"\b(?:malloc|calloc|operator new)\s*\(", r"integer.overflow|wraparound|unchecked.*(?:multiply|add)"),
)


def _evidence_code(folder: Path, finding: dict) -> list[tuple[str, str]]:
    try:
        items = json.loads((Path(folder) / "rea-decompilation.json").read_text(encoding="utf-8"))["items"]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    matches = []
    for evidence in finding.get("evidence", []):
        location = str(evidence.get("location", ""))
        for item in items:
            if item.get("status") != "ok" or not item.get("pseudocode"):
                continue
            address = str(item.get("address", "")).casefold().removeprefix("0x")
            name = str((item.get("procedure") or {}).get("name", ""))
            if address and (re.search(r"(?i)(?:0x)?" + re.escape(address) + r"\b", location) or
                            name and name.casefold() in location.casefold()):
                matches.append((str(item.get("address", "")), item["pseudocode"]))
    return list(dict.fromkeys(matches))


def cwe_mapping(folder: Path, finding: dict) -> dict:
    evidence = _evidence_code(folder, finding)
    claim = " ".join(str(finding.get(key, "")) for key in ("title", "description"))
    claim += " " + " ".join(str(item.get("observation", "")) for item in finding.get("evidence", []))
    for cwe, title, code_pattern, claim_pattern in CWE_RULES:
        if not re.search(claim_pattern, claim, re.I):
            continue
        for address, code in evidence:
            match = re.search(code_pattern, code, re.I)
            if match:
                return {"id": cwe, "name": title, "status": "candidate",
                        "explanation": f"The finding describes this weakness and cited REA procedure {address} calls {match.group(0).strip()}. Review arguments and controls before confirming.",
                        "evidence_address": address,
                        "reference": "https://cwe.mitre.org/data/definitions/" + cwe.split("-")[1] + ".html"}
    return {"id": None, "status": "unmapped",
            "explanation": "No supported CWE mapping was established from the cited reconstructed procedure and finding claim."}


def reachability(folder: Path, finding: dict) -> dict:
    target_codes = _evidence_code(folder, finding)
    targets = {address.casefold().removeprefix("0x") for address, _ in target_codes}
    if not targets:
        return {"rank": "unknown", "distance": None, "path": [],
                "explanation": "No cited REA procedure address was resolved."}
    try:
        with (Path(folder) / "functions.csv").open(newline="", encoding="utf-8-sig") as stream:
            functions = list(csv.DictReader(stream))
        with (Path(folder) / "calls.csv").open(newline="", encoding="utf-8-sig") as stream:
            calls = list(csv.DictReader(stream))
    except OSError:
        return {"rank": "unknown", "distance": None, "path": [],
                "explanation": "Saved function and call exports are unavailable."}
    names = {row.get("entry", "").casefold(): row.get("name", "") for row in functions}
    roots = {address for address, name in names.items() if re.search(
        r"^(?:_?main|wmain|WinMain|wWinMain|DllMain|_start|entry|start|init|efi_main)(?:@\d+)?$", name, re.I)}
    # An explicit entry name is required; a call-graph root alone is not proof of external reachability.
    if not roots:
        return {"rank": "unknown", "distance": None, "path": [],
                "explanation": "No known entry procedure was identified in the saved function export."}
    graph: dict[str, set[str]] = {}
    for row in calls:
        source, dest = row.get("caller_entry", "").casefold(), row.get("callee_entry", "").casefold()
        if source in names and dest in names:
            graph.setdefault(source, set()).add(dest)
    queue = deque((root, [root]) for root in sorted(roots))
    visited = set(roots)
    while queue:
        address, path = queue.popleft()
        if address in targets:
            distance = len(path) - 1
            return {"rank": "direct" if distance == 0 else "near" if distance <= 3 else "distant",
                    "distance": distance,
                    "path": [{"address": item, "name": names.get(item, "")} for item in path],
                    "explanation": "Shortest observed static call path from a named entry procedure; dynamic dispatch and incomplete decompilation can change reachability."}
        for neighbor in sorted(graph.get(address, set()) - visited):
            visited.add(neighbor)
            queue.append((neighbor, path + [neighbor]))
    return {"rank": "unresolved", "distance": None, "path": [],
            "explanation": "No path from a named entry procedure appears in the saved static call graph; this does not prove the procedure is unreachable."}


def enrich_findings(folder: Path, findings: list[dict]) -> None:
    for finding in findings:
        finding["cwe"] = cwe_mapping(folder, finding)
        finding["reachability"] = reachability(folder, finding)


def load_suppressions(folder: Path) -> dict:
    path = Path(folder) / "finding-suppressions.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Invalid suppression file")
    return data


def active_suppression(folder: Path, finding: dict, today: date | None = None) -> dict | None:
    row = load_suppressions(folder).get(finding_signature(finding))
    if not isinstance(row, dict) or not row.get("active"):
        return None
    try:
        expires = date.fromisoformat(row["expires_on"])
    except (KeyError, ValueError):
        return None
    return row if expires >= (today or date.today()) else None


def set_suppression(folder: Path, finding: dict, reason: str, expires_on: str,
                    actor: str) -> dict:
    reason, actor = reason.strip(), actor.strip()
    if not reason or not actor:
        raise ValueError("A suppression needs a reason and reviewer name")
    expiry = date.fromisoformat(expires_on.strip())
    if expiry < date.today():
        raise ValueError("Suppression expiry must be today or later")
    return _save_suppression(folder, finding, {"active": True, "reason": reason,
                                              "expires_on": expiry.isoformat(), "actor": actor})


def clear_suppression(folder: Path, finding: dict, actor: str) -> dict:
    if not actor.strip():
        raise ValueError("Reviewer name is required")
    return _save_suppression(folder, finding, {"active": False, "actor": actor.strip()})


def _save_suppression(folder: Path, finding: dict, change: dict) -> dict:
    folder = Path(folder)
    key = finding_signature(finding)
    rows = load_suppressions(folder)
    previous = rows.get(key)
    change.update({"finding_signature": key, "title": finding.get("title", ""),
                   "updated_at": datetime.now(timezone.utc).isoformat()})
    rows[key] = change
    temporary = folder / "finding-suppressions.json.tmp"
    temporary.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    os.replace(temporary, folder / "finding-suppressions.json")
    with (folder / "findings-audit.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"timestamp": change["updated_at"], "actor": change["actor"],
                                 "action": "suppression_set" if change["active"] else "suppression_cleared",
                                 "finding_signature": key, "before": previous, "after": change}) + "\n")
    return change
