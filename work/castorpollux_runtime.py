"""Prepare network-off Windows Sandbox runs and correlate coarse telemetry."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from castorpollux_core import resource, sha256


def sandbox_executable() -> Path | None:
    path = Path(r"C:\Windows\System32\WindowsSandbox.exe")
    return path if path.is_file() else None


def prepare_trace(folder: Path, arguments: list[str] | None = None,
                  timeout_seconds: int = 60) -> Path:
    folder = Path(folder).resolve()
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    binary = folder / manifest["saved_binary"]
    if not binary.is_file() or sha256(binary) != manifest["sha256"]:
        raise ValueError("Saved binary is missing or its checksum changed")
    if not 5 <= timeout_seconds <= 600:
        raise ValueError("Sandbox timeout must be 5–600 seconds")
    arguments = arguments or []
    if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
        raise ValueError("Runtime arguments must be a JSON array of strings")
    job = folder / "RuntimeTraces" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    inputs, outputs = job / "input", job / "output"
    inputs.mkdir(parents=True)
    outputs.mkdir()
    shutil.copy2(binary, inputs / binary.name)
    shutil.copy2(resource("scripts", "TraceInSandbox.ps1"), inputs / "TraceInSandbox.ps1")
    (inputs / "trace-config.json").write_text(json.dumps({"binary": binary.name,
        "sha256": manifest["sha256"], "arguments": arguments,
        "timeout_seconds": timeout_seconds}, indent=2), encoding="utf-8")
    root = ET.Element("Configuration")
    for tag in ("VGpu", "Networking", "AudioInput", "VideoInput", "ProtectedClient",
                "PrinterRedirection", "ClipboardRedirection"):
        ET.SubElement(root, tag).text = "Enable" if tag == "ProtectedClient" else "Disable"
    mappings = ET.SubElement(root, "MappedFolders")
    for local, remote, readonly in ((inputs, r"C:\CastorPolluxInput", True),
                                    (outputs, r"C:\CastorPolluxOutput", False)):
        mapping = ET.SubElement(mappings, "MappedFolder")
        ET.SubElement(mapping, "HostFolder").text = str(local)
        ET.SubElement(mapping, "SandboxFolder").text = remote
        ET.SubElement(mapping, "ReadOnly").text = str(readonly).lower()
    command = ET.SubElement(root, "LogonCommand")
    ET.SubElement(command, "Command").text = \
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\CastorPolluxInput\TraceInSandbox.ps1"
    config = job / "CastorPolluxTrace.wsb"
    ET.ElementTree(root).write(config, encoding="utf-8", xml_declaration=True)
    (job / "job.json").write_text(json.dumps({"binary_sha256": manifest["sha256"],
        "sandbox_config": str(config), "networking": "disabled", "input_mapping": "read-only",
        "output_mapping": "writable trace only", "status": "prepared"}, indent=2), encoding="utf-8")
    return job


def launch_trace(job: Path) -> None:
    executable = sandbox_executable()
    if not executable:
        raise RuntimeError("Windows Sandbox is unavailable. Enable it on a supported Windows edition before launching a trace.")
    config = Path(job) / "CastorPolluxTrace.wsb"
    if not config.is_file():
        raise ValueError("Sandbox configuration is missing")
    subprocess.Popen([str(executable), str(config)])


def correlate_trace(folder: Path, trace_file: Path) -> dict:
    folder, trace_file = Path(folder), Path(trace_file)
    trace = json.loads(trace_file.read_text(encoding="utf-8-sig"))
    if trace.get("schema") != 1 or not isinstance(trace.get("events"), list):
        raise ValueError("Unsupported runtime trace format")
    flow_file = folder / "data-flow.json"
    flow = json.loads(flow_file.read_text(encoding="utf-8")) if flow_file.is_file() else {"leads": []}
    child = any(item.get("type") == "process_start" and item.get("parent_pid") != 0
                for item in trace["events"])
    tcp = any(item.get("type") == "tcp_connection" for item in trace["events"])
    observations = []
    for lead in flow["leads"]:
        sink = lead.get("sink_api", "").lstrip("_").casefold()
        category = "process" if sink in {"createprocess", "winexec", "shellexecute", "system", "popen", "execve"} else \
                   "network" if sink in {"recv", "recvfrom", "internetreadfile"} else "other"
        seen = child if category == "process" else tcp if category == "network" else False
        observations.append({"function": lead.get("function"), "sink_api": lead.get("sink_api"),
                             "category": category, "related_behavior_observed": seen})
    findings = []
    report_file = folder / "security-review-data.json"
    if report_file.is_file():
        from castorpollux_review import finding_key
        review = json.loads(report_file.read_text(encoding="utf-8"))
        for finding in review.get("result", {}).get("findings", []):
            citations = " ".join(str(item.get("location", "")) for item in finding.get("evidence", []))
            related = [item for item in flow["leads"]
                       if (item.get("function") and re.search(
                           r"(?<!\w)" + re.escape(item["function"]) + r"(?!\w)", citations, re.IGNORECASE))
                       or (item.get("address") and item["address"].casefold() in citations.casefold())]
            matching = [item for item in observations if any(
                item.get("function") == lead.get("function") and item.get("sink_api") == lead.get("sink_api")
                for lead in related)]
            findings.append({"finding_key": finding_key(finding), "title": finding.get("title", ""),
                             "severity": finding.get("severity", ""), "related_leads": len(related),
                             "related_behavior_observed": any(item["related_behavior_observed"] for item in matching)})
    report = {"trace": str(trace_file), "trace_status": trace.get("status"),
              "events": len(trace["events"]), "observations": observations, "findings": findings,
              "limitations": "Sampled process/TCP metadata is not an API-level trace or proof that a cited static path executed. Missing events do not disprove a finding."}
    report["timeline"] = build_trace_timeline(trace, flow)
    destination = trace_file.parent / "runtime-correlation.json"
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_trace_timeline(trace: dict, flow: dict) -> list[dict]:
    """Attach candidate static citations to timestamped observations by category."""
    timeline = []
    for number, event in enumerate(sorted(trace.get("events", []), key=lambda item: str(item.get("timestamp", ""))), 1):
        category = "process" if event.get("type") == "process_start" and event.get("parent_pid") != 0 else \
                   "network" if event.get("type") == "tcp_connection" else "other"
        citations = []
        for lead in flow.get("leads", []):
            sink = str(lead.get("sink_api", "")).lstrip("_").casefold()
            related = (category == "process" and sink in
                       {"createprocess", "winexec", "shellexecute", "system", "popen", "execve"}) or \
                      (category == "network" and sink in {"recv", "recvfrom", "internetreadfile"})
            if related:
                citations.append({"file": "rea-pseudocode.c",
                                  "location": f"{lead.get('function', '')} @ {lead.get('address', '')}",
                                  "observation": f"Candidate {lead.get('source_api', '')} → {lead.get('sink_api', '')}, procedure line {lead.get('sink_line', '')}"})
        timeline.append({"number": number, "timestamp": event.get("timestamp", ""),
                         "type": event.get("type", "unknown"), "event": event,
                         "candidate_citations": citations[:50]})
    return timeline
