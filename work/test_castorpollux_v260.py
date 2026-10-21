"""Regression checks for anonymous matching, build rules, paths and assembly triage."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_applicability import evaluate_applicability, load_rules
from castorpollux_callpaths import explore_paths
from castorpollux_consistency import check_consistency
from castorpollux_workspace import compare_investigations


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


class Release260Tests(unittest.TestCase):
    def test_shifted_anonymous_function_matches_and_ambiguity_stays_unmatched(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old", root / "new"
            old.mkdir(); new.mkdir()
            body = "int FUN_ADDR(int param_1) { int iVar1 = param_1 + 7; if (iVar1 > 10) { return iVar1 * 2; } return iVar1 - 3; }\n"
            for folder, entry in ((old, "10001000"), (new, "20002000")):
                save(folder / "manifest.json", {"input_name": "sample.exe", "sha256": "a" * 64})
                (folder / "functions.csv").write_text(f"entry,name,signature,body_bytes\n{entry},FUN_{entry},int FUN_{entry}(),64\n",
                                                        encoding="utf-8")
                (folder / "pseudocode.c").write_text(f"/* ===== FUN_{entry} @ {entry} ===== */\n" +
                                                      body.replace("FUN_ADDR", "FUN_" + entry), encoding="utf-8")
            report = compare_investigations(old, new, root / "diff")
            self.assertEqual(len(report["anonymous_function_matches"]), 1)
            self.assertEqual(report["functions"]["added"], [])
            self.assertEqual(report["functions"]["removed"], [])
            self.assertEqual(report["anonymous_function_matches"][0]["confidence"], "high")
            self.assertIn("Anonymous function matches", (root / "diff" / "comparison.md").read_text())
            # Duplicating an identical body on one side makes an exact match ambiguous.
            (new / "functions.csv").write_text("entry,name,signature,body_bytes\n"
                "20002000,FUN_20002000,int FUN_20002000(),64\n"
                "20003000,FUN_20003000,int FUN_20003000(),64\n", encoding="utf-8")
            with (new / "pseudocode.c").open("a", encoding="utf-8") as stream:
                stream.write("\n/* ===== FUN_20003000 @ 20003000 ===== */\n" +
                             body.replace("FUN_ADDR", "FUN_20003000"))
            ambiguous = compare_investigations(old, new, root / "diff-ambiguous")
            self.assertEqual(ambiguous["anonymous_function_matches"], [])

    def test_build_rules_record_evidence_without_claiming_cve_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            binary = folder / "sample.exe"
            binary.write_bytes(b"MZ\0FEATURE_ON\0")
            save(folder / "binary-profile.json", {"format": "PE", "architecture": "x86_64",
                "optimization": {"level": "-O2"}})
            save(folder / "known-vulnerabilities.json", {"results": [{"library": "OpenSSL",
                "advisories": [{"id": "CVE-2024-12345"}]}]})
            rule_file = folder / "rules.json"
            save(rule_file, {"schema": 1, "rules": [{"id": "specific-build", "enabled": True,
                "cve": "CVE-2024-12345", "library": "OpenSSL", "formats": ["PE"],
                "architectures": ["x86_64"], "optimization_levels": ["-O2"],
                "required_binary_markers": ["FEATURE_ON"], "excluded_binary_markers": []}]})
            report = evaluate_applicability(folder, binary, rule_file)
            self.assertEqual(report["results"][0]["status"], "configuration_candidate")
            self.assertIn("not proof", report["results"][0]["limitation"])
            saved = json.loads(rule_file.read_text())
            saved["rules"][0]["architectures"] = ["ARM64"]
            save(rule_file, saved)
            conflict = evaluate_applicability(folder, binary, rule_file)
            self.assertEqual(conflict["results"][0]["status"], "rule_conflict")
            saved["rules"][0]["architectures"] = ["x86_64"]
            saved["rules"][0]["required_binary_markers"] = ["FEATURE_NOT_OBSERVED"]
            save(rule_file, saved)
            unknown = evaluate_applicability(folder, binary, rule_file)
            self.assertEqual(unknown["results"][0]["status"], "unknown")
            saved["rules"][0].update({"formats": [], "architectures": [],
                "optimization_levels": [], "required_binary_markers": [],
                "excluded_binary_markers": []})
            save(rule_file, saved)
            with self.assertRaises(ValueError):
                load_rules(rule_file)
            saved["rules"][0]["id"] = "invalid?"
            save(rule_file, saved)
            with self.assertRaises(ValueError):
                load_rules(rule_file)

    def test_visual_paths_and_consistency_leads(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "calls.csv").write_text("caller_entry,caller_name,callee_entry,callee_name\n"
                "10001000,entry,10001100,parse\n10001100,parse,10001200,risky\n", encoding="utf-8")
            paths = explore_paths(folder, "entry", "risky")
            self.assertEqual([node["name"] for node in paths["paths"][0]], ["entry", "parse", "risky"])
            with self.assertRaises(ValueError):
                explore_paths(folder, "missing", "risky")
            (folder / "functions.csv").write_text("entry,name,body_bytes,decompiled\n"
                "10001000,entry,32,true\n10001100,parse,32,true\n", encoding="utf-8")
            (folder / "disassembly.txt").write_text("10001000  CALL 0x10001100\n"
                "10001005  RET\n10001100  CMP EAX,0\n10001104  JZ 0x10001110\n", encoding="utf-8")
            save(folder / "rea-decompilation.json", {"items": [
                {"address": "10001000", "status": "ok", "procedure": {"name": "entry"},
                 "pseudocode": "int entry(void) { return 1; }"},
                {"address": "10001100", "status": "ok", "procedure": {"name": "parse"},
                 "pseudocode": "int parse(void) { return 2; }"}]})
            checked = check_consistency(folder)
            self.assertEqual(checked["summary"]["review"], 2)
            self.assertIn("calls", checked["procedures"][0]["reasons"][0])
            self.assertIn("not semantic-equivalence", checked["procedures"][0]["limitation"])


if __name__ == "__main__":
    unittest.main()
