"""SARIF 2.1.0 projection of saved CastorPollux agent findings."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


def _aggregate_line(root: Path | None, location: str, procedure_line: int) -> int | None:
    if root is None:
        return None
    path = Path(root) / "rea-pseudocode.c"
    if not path.is_file():
        return None
    if not re.search(r"(?:0x)?[0-9a-fA-F]{8,16}", location):
        return procedure_line
    address = re.search(r"(?:0x)?[0-9a-fA-F]{8,16}", location)
    if not address:
        return None
    needle = address.group().removeprefix("0x").lstrip("0").casefold()
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for number, text in enumerate(stream, 1):
            marker = re.match(r"/\* ===== .+ @ ((?:0x)?[0-9a-fA-F]+) ===== \*/", text.strip())
            if marker and marker.group(1).lstrip("0").casefold() == needle:
                return number + procedure_line
    return None


def render_sarif(envelope: dict, evidence_root: Path | None = None) -> dict:
    rules = []
    results = []
    for finding in envelope.get("result", {}).get("findings", []):
        title = str(finding.get("title", "Potential vulnerability"))
        rule_id = finding.get("cwe", {}).get("id") or "CASTORPOLLUX-" + hashlib.sha256(title.casefold().encode()).hexdigest()[:12].upper()
        if not any(rule["id"] == rule_id for rule in rules):
            rules.append({"id": rule_id, "shortDescription": {"text": title},
                          "fullDescription": {"text": str(finding.get("description", title))},
                          "properties": {"tags": ["security", "reverse-engineering"],
                                         "cwe_explanation": finding.get("cwe", {}).get("explanation")}})
        severity = str(finding.get("severity", "medium")).lower()
        level = "error" if severity in ("critical", "high") else "warning" if severity == "medium" else "note"
        locations = []
        for evidence in finding.get("evidence", []):
            filename = Path(str(evidence.get("file", ""))).name
            if filename not in {"rea-pseudocode.c", "pseudocode.c", "functions.csv", "strings.csv",
                                "imports.csv", "calls.csv", "xrefs.csv", "disassembly.txt"}:
                continue
            region = {}
            line = re.search(r"\bline\s+(\d+)\b", str(evidence.get("location", "")), re.I)
            if line and int(line.group(1)) > 0:
                absolute = (_aggregate_line(evidence_root, str(evidence.get("location", "")),
                                            int(line.group(1))) if filename == "rea-pseudocode.c"
                            else int(line.group(1)))
                if absolute:
                    region["startLine"] = absolute
            physical = {"artifactLocation": {"uri": filename}}
            if region:
                physical["region"] = region
            locations.append({"physicalLocation": physical,
                              "message": {"text": str(evidence.get("observation", ""))}})
        result = {"ruleId": rule_id, "level": level,
                  "message": {"text": str(finding.get("description", title))},
                  "properties": {"severity": severity, "confidence": finding.get("confidence"),
                                 "vulnerability_type": finding.get("vulnerability_type"),
                                 "proof_of_concept": finding.get("proof_of_concept"),
                                 "evidence": finding.get("evidence", []),
                                 "cwe": finding.get("cwe"), "reachability": finding.get("reachability"),
                                 "confidence_assessment": finding.get("confidence_assessment", {}),
                                 "code_excerpts": finding.get("code_excerpts", []),
                                 "call_path_image": finding.get("call_path_image", ""),
                                 "confirmation_checklist": finding.get("confirmation_checklist", []),
                                 "quality_gate": envelope.get("quality_gate", {}).get("status")}}
        if evidence_root is not None:
            from castorpollux_findings import active_suppression
            suppression = active_suppression(evidence_root, finding)
            if suppression:
                result["suppressions"] = [{"kind": "external", "status": "accepted",
                                           "justification": suppression["reason"] +
                                           " (expires " + suppression["expires_on"] + ")"}]
        if locations:
            result["locations"] = locations
        results.append(result)
    return {"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "CastorPollux", "version": envelope.get("application_version", ""),
                                          "rules": rules}}, "results": results,
                      "properties": {"target_sha256": envelope.get("target", {}).get("sha256"),
                                     "engine_versions": envelope.get("analysis_context", {}).get("engine_versions", {}),
                                     "binary_profile": envelope.get("analysis_context", {}).get("binary_profile", {}),
                                     "embedded_library_leads": envelope.get("analysis_context", {}).get("embedded_libraries", {}),
                                     "known_vulnerability_leads": envelope.get("analysis_context", {}).get("known_vulnerabilities", {}),
                                     "analysis_fingerprint": envelope.get("analysis_fingerprint"),
                                     "agent": envelope.get("agent"),
                                     "quality_gate": envelope.get("quality_gate"),
                                     "limitations": envelope.get("result", {}).get("limitations", [])}}]}


def write_sarif(path: Path, envelope: dict, evidence_root: Path | None = None) -> None:
    Path(path).write_text(json.dumps(render_sarif(envelope, evidence_root), indent=2), encoding="utf-8")
