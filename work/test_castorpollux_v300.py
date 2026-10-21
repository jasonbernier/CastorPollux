"""Regression coverage for indexed evidence and preflight boundaries."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from castorpollux_intelligence import (build_source_index, search_index, line_address,
                                   disagreement_heatmap, review_priority, patch_checklist,
                                   confidence_calibration)
from castorpollux_preflight import engine_compatibility
from castorpollux_recovery import diagnostic_preview, recovery_comparison, attempt_agent_recovery
from castorpollux_usage import read_other_usage, usage_label


class V300Tests(unittest.TestCase):
    def test_index_refresh_and_procedure_precision(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            source = folder / "rea-pseudocode.c"
            source.write_text("/* ===== parse @ 0x401000 ===== */\nint parse() { return 1; }\n", encoding="utf-8")
            self.assertEqual(build_source_index(folder)["lines"], 2)
            self.assertEqual(search_index(folder, "parse")[1]["line"], "2")
            self.assertEqual(search_index(folder, "tur")[0]["line"], "2")
            self.assertEqual(line_address(folder, 1)["precision"], "exact_entry")
            self.assertEqual(line_address(folder, 2)["precision"], "procedure_entry")
            source.write_text(source.read_text(encoding="utf-8") + "int changed = 2;\n", encoding="utf-8")
            self.assertEqual(search_index(folder, "changed")[0]["line"], "3")

    def test_missing_engine_blocks_preflight(self):
        class Store:
            def current_version(self, _): return "12.1.4"
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            paths = tuple(folder / name for name in ("ghidra", "jdk", "node", "rea"))
            result = engine_compatibility(Store(), paths)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(len(result["errors"]), 4)

    def test_heuristics_and_patch_checklist(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "rea-decompilation.json").write_text(json.dumps({"items": [
                {"address": "0x401000", "status": "ok", "procedure": {"name": "parse"},
                 "pseudocode": "void parse() { recv(); strcpy(); }"},
                {"address": "0x402000", "status": "failed", "procedure": {"name": "other"}}]}), encoding="utf-8")
            (folder / "pseudocode.c").write_text("/* ===== parse @ 401000 ===== */\nvoid parse() { recv(); }\n", encoding="utf-8")
            priority = review_priority(folder)
            self.assertEqual(len(priority), 2)
            heat = disagreement_heatmap(folder)
            self.assertTrue(any(item["ghidra_present"] for item in heat))
            checklist = patch_checklist(folder, {"functions": {"changed": [{"function": "parse",
                                                                              "old_entry": "0x401000",
                                                                              "new_entry": "0x401010"}]},
                                                "calls": {"added": ["parse -> copy"], "removed": []}})
            self.assertEqual(checklist["items"][0]["function"], "parse")
            self.assertEqual(checklist["changed_call_edges"]["added"], ["parse -> copy"])
            self.assertTrue((folder / "patch-verification.json").is_file())

    def test_recovery_preview_is_redacted_and_history_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "manifest.json").write_text(json.dumps({"ghidra_status": "failed",
                "warnings": [r"failed C:\\Users\\ExampleUser\\private\\binary.exe token=abc123"]}), encoding="utf-8")
            preview = diagnostic_preview(folder).read_text(encoding="utf-8")
            self.assertNotIn("ExampleUser", preview)
            self.assertEqual(recovery_comparison(folder), [])
            for _ in range(2):
                attempt_agent_recovery(None, folder, None, lambda _message: None,
                                       lambda: False, lambda _process: None)
            self.assertEqual([item["sequence"] for item in recovery_comparison(folder)], [1, 2])

    def test_usage_never_invents_quota(self):
        result = read_other_usage("claude", None)
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("not installed", usage_label(result))

    def test_empty_corpus_cannot_claim_calibration(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = confidence_calibration(Path(temporary) / "corpus.json", [])
            self.assertFalse(result["calibrated"])
            self.assertEqual(result["confidence_bins"], {})


if __name__ == "__main__":
    unittest.main()
