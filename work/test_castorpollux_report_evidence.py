"""Integration checks for saved finding evidence and all report formats."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from castorpollux_findings import enrich_findings
from castorpollux_report_evidence import (enrich_report_evidence, export_source_map,
                                          load_confirmation_state, save_confirmation_state)
from castorpollux_review import evidence_jump, finding_key
from castorpollux_workspace import archive_previous_review, render_security_report


class ReportEvidenceTests(unittest.TestCase):
    def test_empty_report_csv_keeps_column_count(self):
        with tempfile.TemporaryDirectory() as scratch:
            folder = Path(scratch)
            envelope = {"application_version": "1.0.0", "codex_mode": "default", "agent": "codex",
                        "target": {"input_name": "synthetic.exe", "sha256": "a" * 64},
                        "created_at": "2026-10-19T00:00:00Z", "result": {
                            "summary": "No findings", "findings": [], "limitations": []}}
            render_security_report(folder, envelope)
            with (folder / "security-report.csv").open(newline="", encoding="utf-8-sig") as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(len(rows[0]), len(rows[1]))

    def test_exports_with_symbol_and_cited_procedure(self):
        with tempfile.TemporaryDirectory() as scratch:
            folder = Path(scratch)
            code = "void ParseInput(char *input)\n{\n  copy_data(input);\n}\n"
            (folder / "rea-pseudocode.c").write_text(
                "/* REA reconstructed pseudocode */\n\n"
                "/* ===== ParseInput @ 140001100 ===== */\n" + code, encoding="utf-8")
            (folder / "rea-decompilation.json").write_text(json.dumps({"items": [{
                "address": "140001100", "status": "ok", "procedure": {"name": "ParseInput"},
                "pseudocode": code}]}), encoding="utf-8")
            with (folder / "symbols.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerows([["address", "name", "type", "namespace", "source", "external"],
                                 ["140001100", "ParseInput", "Function", "Parser", "IMPORTED", "false"]])
            with (folder / "functions.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerows([["entry", "name"], ["140001000", "main"],
                                 ["140001100", "ParseInput"]])
            with (folder / "calls.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerows([["caller_entry", "callee_entry", "caller_name", "callee_name"],
                                 ["140001000", "140001100", "main", "ParseInput"]])
            finding = {"title": "Synthetic review lead", "severity": "medium", "confidence": "low",
                       "confidence_reason": "The synthetic citation has no runtime confirmation.",
                       "vulnerability_type": "input_validation", "description": "Synthetic test only.",
                       "evidence": [{"file": "rea-pseudocode.c", "location": "140001100 procedure line 3",
                                     "observation": "Test citation"}],
                       "impact": "Unknown", "recommendation": "Inspect input handling",
                       "validation": "Review the saved code"}
            findings = [finding]
            enrich_findings(folder, findings)
            enrich_report_evidence(folder, findings)
            mapping = export_source_map(folder)
            self.assertEqual(mapping["entries"][0]["symbol_name"], "ParseInput")
            self.assertEqual(mapping["entries"][0]["start_line"], 3)
            self.assertEqual(mapping["entries"][0]["end_line"], 7)
            self.assertTrue(finding["code_excerpts"][0]["exact_line"])
            self.assertIn("6:   copy_data(input)", evidence_jump(folder, finding["evidence"][0])["excerpt"])
            self.assertEqual(len(finding["confirmation_checklist"]), 6)
            self.assertIn("Agent rationale", " ".join(finding["confidence_assessment"]["reasons"]))
            envelope = {"application_version": "1.0.0", "codex_mode": "default", "agent": "codex",
                        "target": {"input_name": "synthetic.exe", "sha256": "a" * 64},
                        "created_at": "2026-10-19T00:00:00Z", "result": {
                            "summary": "Synthetic test", "findings": findings, "limitations": []}}
            render_security_report(folder, envelope, evidence_root=folder)
            self.assertTrue((folder / finding["call_path_image"]).is_file())
            markdown = (folder / "security-report.md").read_text(encoding="utf-8")
            self.assertIn("Confidence reasons", markdown)
            self.assertIn("Report-ready reconstructed code excerpts", markdown)
            self.assertIn("Confirmation checklist", markdown)
            self.assertIn("finding-01-call-path.png", markdown)
            self.assertIn("<img src=\"finding-assets/finding-01-call-path.png\"",
                          (folder / "security-report.html").read_text(encoding="utf-8"))
            self.assertGreater((folder / "security-report.pdf").stat().st_size, 1000)
            self.assertIn("confidence_assessment", json.loads((folder / "security-report.sarif").read_text())
                          ["runs"][0]["results"][0]["properties"])
            self.assertEqual(json.loads((folder / "security-report.sarif").read_text())
                             ["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 6)
            key = finding_key(finding)
            saved = {f"step-{i}": i % 2 == 0 for i in range(1, 7)}
            save_confirmation_state(folder, key, saved)
            self.assertEqual(load_confirmation_state(folder)[key], saved)
            archive = archive_previous_review(folder)
            self.assertTrue((archive / finding["call_path_image"]).is_file())
            self.assertTrue((archive / "source-map.json").is_file())


if __name__ == "__main__":
    unittest.main()
