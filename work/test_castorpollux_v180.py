"""Focused checks for rules, plugins, bundles, symbols, and sandbox jobs."""

import json
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).parent))

from castorpollux_bundle import export_bundle, import_bundle, verify_bundle
from castorpollux_flow import load_rules, trace_procedure
from castorpollux_plugins import SAMPLE, load_plugins, plugin_guidance, render_templates
from castorpollux_runtime import correlate_trace, prepare_trace, sandbox_executable
from castorpollux_core import sha256

with tempfile.TemporaryDirectory(prefix="castorpollux-v180-") as temporary:
    root = Path(temporary)
    plugin_folder = root / "plugins"
    plugin_folder.mkdir()
    plugin = {**SAMPLE, "enabled": True}
    (plugin_folder / "policy.json").write_text(json.dumps(plugin), encoding="utf-8")
    plugins = load_plugins(plugin_folder)
    assert len(plugins) == 1 and "MyRiskyApi" in plugin_guidance(plugins)
    rules_file = root / "rules.json"
    rules_file.write_text(json.dumps({"schema": 1, "sources": [], "sinks": [], "sanitizers": []}), encoding="utf-8")
    rules = load_rules(rules_file, plugins)
    row = {"status": "ok", "name": "sample", "address": "0x1000",
           "pseudocode": "MyInputApi(buf);\nMyRiskyApi(buf);\nMySanitizer(buf);\nMyRiskyApi(buf);"}
    # Plugin sanitizer returns a new value; an in-place rule clears the original buffer.
    rules["sanitizers"] = [{"name": "MySanitizer", "output": 0}]
    leads = trace_procedure(row, rules)
    assert len(leads) == 1 and leads[0]["sink_line"] == 2
    envelope = {"target": {"input_name": "sample.exe", "sha256": "a" * 64},
                "created_at": "today", "result": {"summary": "One issue", "findings": [{
                    "severity": "high", "title": "Issue", "description": "Description"}]}}
    names = render_templates(root, envelope, plugins)
    assert names == ["security-report-plugin-example-policy.md"]
    assert "One issue" in (root / names[0]).read_text(encoding="utf-8")

    investigation = root / "investigation"
    investigation.mkdir()
    binary = investigation / "source-binary.exe"
    binary.write_bytes(b"MZ" + b"\0" * 100)
    (investigation / "manifest.json").write_text(json.dumps({
        "sha256": sha256(binary), "saved_binary": binary.name, "input_name": "sample.exe"}), encoding="utf-8")
    (investigation / "data-flow.json").write_text(json.dumps({"leads": [{
        "function": "sample", "address": "0x1000", "sink_api": "CreateProcess"}]}), encoding="utf-8")
    (investigation / "security-review-data.json").write_text(json.dumps({"result": {"findings": [{
        "title": "Possible process creation", "severity": "medium",
        "evidence": [{"file": "rea-pseudocode.c", "location": "sample @ 0x1000"}]}]}}), encoding="utf-8")
    bundle = root / "investigation.zip"
    exported = export_bundle(investigation, bundle)
    assert exported["files"] == 4
    assert verify_bundle(bundle)["status"] == "verified"
    imports = root / "imports"
    imports.mkdir()
    imported = import_bundle(bundle, imports)
    assert sha256(imported / binary.name) == sha256(binary)
    tampered = root / "tampered.zip"
    with zipfile.ZipFile(bundle) as original, zipfile.ZipFile(tampered, "w") as changed:
        for item in original.infolist():
            payload = original.read(item.filename)
            if item.filename == "investigation/data-flow.json":
                payload += b"tampered"
            changed.writestr(item, payload)
    try:
        verify_bundle(tampered)
        assert False, "Tampered bundle was accepted"
    except ValueError as error:
        assert "mismatch" in str(error)

    job = prepare_trace(investigation, ["--test"], 10)
    config = ET.parse(job / "CastorPolluxTrace.wsb").getroot()
    assert config.findtext("Networking") == "Disable"
    assert config.findtext("ClipboardRedirection") == "Disable"
    mappings = config.findall("MappedFolders/MappedFolder")
    assert [item.findtext("ReadOnly") for item in mappings] == ["true", "false"]
    assert (job / "input" / binary.name).is_file()
    trace = job / "output" / "trace.json"
    trace.write_text(json.dumps({"schema": 1, "status": "completed", "events": [{
        "type": "process_start", "pid": 22, "parent_pid": 11}]}), encoding="utf-8")
    correlation = correlate_trace(investigation, trace)
    assert correlation["observations"][0]["related_behavior_observed"]
    assert correlation["findings"][0]["related_behavior_observed"]

print("Rules, plugins, bundle integrity, sandbox settings, and correlation passed")
