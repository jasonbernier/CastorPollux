"""Regression checks for strict review schema and repair diagnostics."""

import json
import io
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_diagnostics import classify_ghidra_failure, export_diagnostics
from castorpollux_workspace import (CODEX_SCHEMA, SECURITY_SCHEMA, CodexReview, analysis_fingerprint,
                                archive_previous_review, probe_agent_stage, review_is_stale,
                                review_readiness, transient_agent_workdir_error)


def assert_strict(value):
    if value.get("type") == "object":
        assert set(value["required"]) == set(value["properties"])
        assert value["additionalProperties"] is False
        for child in value["properties"].values():
            assert_strict(child)
    if value.get("type") == "array":
        assert_strict(value["items"])


assert_strict(CODEX_SCHEMA)
assert "analysis_overview" not in SECURITY_SCHEMA["required"]
assert transient_agent_workdir_error("CreateProcessWithLogonW failed: 267")
assert not transient_agent_workdir_error("Invalid schema: required analysis_overview")

with tempfile.TemporaryDirectory(prefix="castorpollux-v230-") as temporary:
    folder = Path(temporary) / "investigation"
    folder.mkdir()
    manifest = {"input_name": "example.exe", "input_path": "C:\\Private\\example.exe", "sha256": "a" * 64,
                "ghidra_status": "failed", "ghidra_exit_code": 0,
                "ghidra_failure_reason": "ERROR REPORT SCRIPT ERROR: source bundle missing",
                "rea_status": "complete", "rea_decompile_status": "complete",
                "rea_decompile_counts": {"total": 2, "succeeded": 2}, "versions": {"ghidra": "12.1.4"}}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (folder / "rea-pseudocode.c").write_text("int main() { return 0; }", encoding="utf-8")
    (folder / "rea-decompilation.json").write_text(json.dumps({"target_sha256": "a" * 64,
        "total": 2, "succeeded": 2, "failed": 0}), encoding="utf-8")
    saved, warnings = review_readiness(folder)
    assert saved["ghidra_status"] == "failed" and "Supplemental Ghidra exports" in warnings[0]
    assert classify_ghidra_failure(manifest) == "script load"
    before = analysis_fingerprint(folder, manifest)
    review = {"analysis_fingerprint": before, "created_at": "2026-10-16T00:00:00Z"}
    assert not review_is_stale(folder, review, manifest)
    manifest["resumed_at"] = "2026-10-16T01:00:00Z"
    assert review_is_stale(folder, review, manifest)
    (folder / "security-review-data.json").write_text(json.dumps(review), encoding="utf-8")
    (folder / "security-review-manifest.json").write_text(json.dumps(saved), encoding="utf-8")
    archive = archive_previous_review(folder)
    assert (archive / "security-review-manifest.json").is_file()
    (folder / "ghidra.log").write_text("ERROR C:\\Private\\secret-path token=supersecret", encoding="utf-8")
    diag = export_diagnostics(folder, Path(temporary) / "diagnostics.zip")
    with zipfile.ZipFile(diag) as contents:
        assert "source-binary.exe" not in contents.namelist()
        assert "Private" not in contents.read("ghidra.log").decode("utf-8")
        assert "supersecret" not in contents.read("ghidra.log").decode("utf-8")
        assert "input_path" not in contents.read("manifest-redacted.json").decode("utf-8")
    stage = Path(temporary) / "stage"
    stage.mkdir()
    probe_agent_stage(Path(sys.executable), stage)
    assert not (stage / ".castorpollux-stage-probe").exists()

    # A transient Codex working-directory error gets one bounded retry.
    (folder / "rea-decompilation.json").write_text(json.dumps({"target_sha256": "a" * 64,
        "total": 1, "succeeded": 1, "failed": 0,
        "items": [{"address": "0x140001000", "procedure": {"name": "FUN_140001000"},
                   "status": "ok", "pseudocode": "int FUN_140001000() { return 0; }"}]}), encoding="utf-8")
    calls = []
    class FakeProcess:
        def __init__(self, code, message):
            self.returncode = code
            self.stdout = io.StringIO(message)
        def wait(self):
            return self.returncode
        def terminate(self):
            self.returncode = 1
    def fake_launch(args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 1:
            return FakeProcess(1, "CreateProcessWithLogonW failed: 267\n")
        Path(args[args.index("--output-last-message") + 1]).write_text(json.dumps({
            "summary": "No supported findings", "findings": [], "limitations": ["Test"]}), encoding="utf-8")
        return FakeProcess(0, "Review complete\n")
    with patch("castorpollux_preflight.agent_capabilities", return_value={"status": "ready", "missing": []}), \
         patch("castorpollux_workspace.probe_agent_stage"), \
         patch("castorpollux_workspace.subprocess.Popen", side_effect=fake_launch):
        envelope = CodexReview(lambda _message: None, lambda: False, lambda _process: None).run(
            folder, False, Path(sys.executable), {"json"}, "codex", minimum_coverage=0,
            secondary_decompiler=False)
    assert len(calls) == 2 and envelope["agent_workdir_fallback"]
    assert Path(calls[1][1]["cwd"]) == Path(folder.anchor)
    assert (folder / "security-review-manifest.json").is_file()
    assert "working-directory retry" in (folder / "codex-review.log").read_text(encoding="utf-8")

print("CastorPollux 2.3 schema, stale reviews, diagnostics, stage access, and partial Ghidra regression passed")
