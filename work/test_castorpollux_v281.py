"""Regression tests for review enrichment and staged agent evidence."""

import csv
import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError

from castorpollux_core import optional_symbols_not_found
from castorpollux_findings import reachability
from castorpollux_workspace import _stage_cloud_evidence, build_review_prompt


class ReviewStagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_reachability_handles_entry_without_outgoing_calls(self):
        (self.root / "rea-decompilation.json").write_text(json.dumps({"items": [{
            "status": "ok", "address": "00002000", "procedure": {"name": "target"},
            "pseudocode": "void target(void) {}"}]}), encoding="utf-8")
        with (self.root / "functions.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["entry", "name"])
            writer.writeheader()
            writer.writerows([{"entry": "00001000", "name": "entry"},
                              {"entry": "00002000", "name": "target"}])
        with (self.root / "calls.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["caller_entry", "callee_entry"])
            writer.writeheader()
        finding = {"evidence": [{"file": "rea-pseudocode.c", "location": "target @ 00002000",
                                 "observation": "Potential issue"}]}
        self.assertEqual(reachability(self.root, finding)["rank"], "unresolved")

    def test_every_agent_prompt_states_defensive_purpose(self):
        scope = {"description": "One procedure"}
        for local in (False, True):
            prompt = build_review_prompt(scope, local, plugins=[])
            self.assertTrue(prompt.startswith("This review is for a defensive outcome:"))
        cloud = build_review_prompt(scope, plugins=[])
        self.assertIn("evidence-index.json", cloud)
        self.assertIn("Do not assume rg, Python", cloud)

    def test_stage_identifies_absent_optional_advisories(self):
        stage = self.root / "stage"
        stage.mkdir()
        scope = {"mode": "all", "selection": "", "description": "One procedure",
                 "addresses": ["00002000"], "items": [{"name": "target", "address": "00002000",
                                                       "pseudocode": "void target(void) {}"}]}
        manifest = {"input_name": "example.exe", "sha256": "a" * 64}
        _stage_cloud_evidence(self.root, stage, manifest, scope, "all")
        index = json.loads((stage / "evidence-index.json").read_text(encoding="utf-8"))
        staged = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("rea-pseudocode.c", index["available_files"])
        self.assertIn("known-vulnerabilities.json", index["optional_files_not_staged"])
        self.assertIn("evidence-index.json", staged["staged_files"])

    def test_optional_symbol_404_is_distinct_from_server_error(self):
        self.assertTrue(optional_symbols_not_found(HTTPError("https://example.test/pdb", 404,
                                                             "Not Found", {}, None)))
        self.assertFalse(optional_symbols_not_found(HTTPError("https://example.test/pdb", 500,
                                                              "Server Error", {}, None)))


if __name__ == "__main__":
    unittest.main()
