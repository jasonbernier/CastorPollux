"""Regression tests for bounded analysis recovery and honest usage display."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from castorpollux_recovery import attempt_agent_recovery, engine_failures, _diagnostics, RECOVERY_PROMPT
from castorpollux_usage import summarize_usage, usage_label


class RecoveryAndUsageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name) / "investigation"
        self.folder.mkdir()
        (self.folder / "source-binary.exe").write_bytes(b"MZexample")
        self.manifest = {"saved_binary": "source-binary.exe", "sha256": "test",
                         "ghidra_status": "failed", "rea_status": "complete",
                         "rea_decompile_status": "blocked", "warnings": []}
        (self.folder / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_diagnostics_redact_local_path_and_prompt_is_defensive(self):
        self.assertIn("for a defensive outcome", RECOVERY_PROMPT)
        self.manifest["ghidra_failure_reason"] = "Script error at C:\\Users\\ExampleUser\\private.log"
        diagnostic = _diagnostics(self.folder, self.manifest)
        self.assertNotIn("ExampleUser", diagnostic)
        self.assertIn("[LOCAL_PATH]", diagnostic)

    def test_agent_retry_is_once_and_verified_by_new_manifest(self):
        executable = self.folder / "codex.exe"
        executable.write_bytes(b"test")
        class Runner:
            calls = 0
            def run(inner, source, destination, resume_folder=None):
                inner.calls += 1
                updated = dict(self.manifest, ghidra_status="complete", rea_decompile_status="complete")
                (self.folder / "manifest.json").write_text(json.dumps(updated), encoding="utf-8")
                return self.folder
        runner = Runner()
        with patch("castorpollux_recovery._agent_decision", return_value={"action": "retry_once", "reason": "Transient staging error"}):
            result = attempt_agent_recovery(runner, self.folder, executable, lambda _: None,
                                            lambda: False, lambda _: None)
        self.assertEqual(runner.calls, 1)
        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(engine_failures(json.loads((self.folder / "manifest.json").read_text())), [])

    def test_agent_stop_preserves_failure(self):
        executable = self.folder / "codex.exe"
        executable.write_bytes(b"test")
        with patch("castorpollux_recovery._agent_decision", return_value={"action": "stop", "reason": "Unsupported format"}):
            result = attempt_agent_recovery(None, self.folder, executable, lambda _: None,
                                            lambda: False, lambda _: None)
        self.assertEqual(result["status"], "not_retryable")
        self.assertTrue(engine_failures(self.manifest))

    def test_optional_scan_error_is_recoverable_status(self):
        complete = dict(self.manifest, ghidra_status="complete", rea_decompile_status="complete",
                        warnings=["Data-flow lead generation failed: temporary file lock"])
        self.assertEqual(engine_failures(complete), complete["warnings"])

    def test_usage_is_clamped_and_missing_values_stay_unavailable(self):
        usage = summarize_usage({"rateLimitsByLimitId": {"codex": {"limitName": "Codex",
            "primary": {"usedPercent": 35, "windowDurationMins": 300, "resetsAt": 1},
            "secondary": {"usedPercent": 140, "windowDurationMins": 10080}}}})
        self.assertEqual(usage["limits"][0]["windows"][0]["remaining_percent"], 65)
        self.assertEqual(usage["limits"][0]["windows"][1]["remaining_percent"], 0)
        self.assertIn("65% left", usage_label(usage))
        self.assertEqual(summarize_usage({"rateLimits": {}})["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
