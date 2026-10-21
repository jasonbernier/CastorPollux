"""Focused 2.2 checks for review candidates, report projections, and history."""

import csv
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_poc import check_candidate
from castorpollux_workspace import (_stage_cloud_evidence, archive_previous_review,
                                render_security_report, validate_review_result)
from castorpollux_core import AnalysisRunner


with tempfile.TemporaryDirectory(prefix="castorpollux-v220-") as temporary:
    folder = Path(temporary)
    candidate = {"status": "candidate", "python": "from pathlib import Path\nPath('test-input.bin').write_bytes(b'A' * 32)",
                 "setup": "Use an authorized test copy", "expected_observation": "A 32-byte input is written",
                 "limitations": "Does not execute or verify the target"}
    finding = {"title": "Possible bounded-copy error", "severity": "medium", "confidence": "low",
               "description": "A size check may be missing.", "impact": "Potential overwrite",
               "recommendation": "Check bounds before copy", "validation": "Review the target bounds",
               "evidence": [{"file": "rea-pseudocode.c", "location": "FUN_140001000 line 3",
                             "observation": "Length reaches the copy"}],
               "vulnerability_type": "buffer_overflow", "proof_of_concept": candidate}
    result = {"summary": "One potential issue", "findings": [finding], "limitations": ["Static review"]}
    validate_review_result(result)
    assert check_candidate(finding)["syntax_valid"]
    envelope = {"application_version": "2.2.0", "agent": "codex", "codex_mode": "standard",
                "created_at": "2026-10-16T00:00:00Z", "target": {"input_name": "sample.exe", "sha256": "0" * 64},
                "result": result, "quality_gate": {"status": "pass", "succeeded": 1, "total": 1,
                                                   "coverage_percent": 100, "source_chars": 2000, "reasons": []}}
    render_security_report(folder, envelope)
    script = next((folder / "proofs-of-concept").glob("candidate-*.py"))
    assert "write_bytes" in script.read_text(encoding="utf-8")
    assert "unverified" in script.read_text(encoding="utf-8")
    assert "proof-of-concept" in (folder / "security-report.md").read_text(encoding="utf-8")
    assert "<pre><code>" in (folder / "security-report.html").read_text(encoding="utf-8")
    assert (folder / "security-report.pdf").stat().st_size > 1000
    with (folder / "security-report.csv").open(encoding="utf-8-sig", newline="") as stream:
        row = next(csv.DictReader(stream))
    assert row["vulnerability_type"] == "buffer_overflow" and "write_bytes" in row["poc_python"]
    saved = json.loads((folder / "security-report.json").read_text(encoding="utf-8"))
    assert saved["result"]["findings"][0]["proof_of_concept"]["syntax_valid"]
    sarif = json.loads((folder / "security-report.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"][0]["properties"]["vulnerability_type"] == "buffer_overflow"
    archive = archive_previous_review(folder)
    assert archive and (archive / "proofs-of-concept" / script.name).is_file()

    bad = {"proof_of_concept": {"status": "candidate", "python": "def broken(:", "setup": "",
                                "expected_observation": "", "limitations": ""}}
    assert not check_candidate(bad)["syntax_valid"]
    no_code = {"proof_of_concept": {"status": "not_feasible", "python": "", "setup": "",
                                    "expected_observation": "", "limitations": "Input format unknown"}}
    assert check_candidate(no_code)["status"] == "not_feasible"

    # A failed supplemental Ghidra export must retain a useful diagnostic.
    target = folder / "sample.exe"
    target.write_bytes(b"MZtest")
    class FakeStore:
        root = folder / "components"
        def current_version(self, _name):
            return "test"
        def analysis_paths(self, _notify, _cancelled):
            return (folder / "ghidra", folder / "jdk", folder / "node.exe", folder / "rea.mjs")
    def failed_engine(_self, _args, log_path, _env, _output=None, **_kwargs):
        log_path.write_text("ERROR synthetic Ghidra import failure\n", encoding="utf-8")
        return 1
    with patch("castorpollux_preflight.engine_compatibility", return_value={"status": "compatible", "errors": []}), \
         patch("castorpollux_core.home", return_value=folder), \
         patch("castorpollux_diagnostics.home", return_value=folder), \
         patch.object(AnalysisRunner, "_run", failed_engine):
        investigation = AnalysisRunner(FakeStore(), lambda _message: None,
                                       lambda: False, lambda _process: None).run(target, folder / "jobs")
    manifest = json.loads((investigation / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["ghidra_status"] == "failed" and manifest["ghidra_exit_code"] == 1
    assert "synthetic Ghidra import failure" in manifest["ghidra_failure_reason"]
    assert not any(manifest["ghidra_exports"].values())
    assert "synthetic Ghidra import failure" in (investigation / "errors.jsonl").read_text(encoding="utf-8")
    with patch("castorpollux_preflight.engine_compatibility", return_value={"status": "compatible", "errors": []}), \
         patch("castorpollux_core.home", return_value=folder), \
         patch("castorpollux_diagnostics.home", return_value=folder), \
         patch.object(AnalysisRunner, "_run", failed_engine):
        AnalysisRunner(FakeStore(), lambda _message: None, lambda: False,
                       lambda _process: None).run(target, folder / "jobs", resume_folder=investigation)
    assert len(list((investigation / "GhidraAttempts").glob("*.log"))) == 1
    staging = folder / "staging"
    staging.mkdir()
    scope = {"mode": "all", "selection": "", "description": "all", "addresses": ["140001000"],
             "items": [{"name": "FUN_140001000", "address": "140001000", "pseudocode": "return 0;"}]}
    _stage_cloud_evidence(investigation, staging, manifest, scope, "all")
    staged = json.loads((staging / "manifest.json").read_text(encoding="utf-8"))
    assert staged["ghidra_exit_code"] == 1
    assert "synthetic Ghidra import failure" in staged["ghidra_failure_reason"]
    assert "rea-pseudocode.c" in staged["staged_files"]
    assert "Full-scope" in staged["staging_note"]

print("CastorPollux 2.2 candidates, reports, and review history passed")
