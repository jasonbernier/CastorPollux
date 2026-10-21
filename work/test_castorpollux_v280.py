"""Regression tests for graph, import, call-path, and boundary evidence."""

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from castorpollux_advanced import build_advanced_graph, check_call_edges
from castorpollux_changegate import compare_type_signatures, gate_new_call_paths
from castorpollux_inputs import import_fuzz_coverage, import_vex, verify_sbom_provenance
from castorpollux_overflow import scan_overflows, create_boundary_inputs
from castorpollux_pecheck import decode_call, pe_layout


def table(folder, name, fields, rows):
    with (folder / name).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old = self.root / "old"
        self.new = self.root / "new"
        self.old.mkdir(); self.new.mkdir()
        fields = ["entry", "name", "signature", "body_bytes", "decompiled", "error"]
        table(self.old, "functions.csv", fields, [
            {"entry": "00001000", "name": "entry", "signature": "int entry(char *p)", "body_bytes": "10"},
            {"entry": "00002000", "name": "sink", "signature": "void sink(char *p)", "body_bytes": "10"}])
        table(self.new, "functions.csv", fields, [
            {"entry": "00001000", "name": "entry", "signature": "long entry(char *p)", "body_bytes": "10"},
            {"entry": "00002000", "name": "sink", "signature": "void sink(char *p)", "body_bytes": "10"}])
        table(self.old, "calls.csv", ["caller_entry", "callee_entry"], [])
        table(self.new, "calls.csv", ["caller_entry", "callee_entry"],
              [{"caller_entry": "00001000", "callee_entry": "00002000"}])
        (self.new / "manifest.json").write_text(json.dumps({"sha256": "a" * 64}), encoding="utf-8")
        (self.new / "disassembly.txt").write_text("00001000  MOV RAX,RBX\n00001001  CALL 0x2000\n"
                                                   "00002000  RET\n", encoding="utf-8")
        table(self.new, "xrefs.csv", ["from_address", "to_address", "type", "operand_index"], [
            {"from_address": "00001001", "to_address": "00002000", "type": "UNCONDITIONAL_CALL"},
            {"from_address": "00001002", "to_address": "00001009", "type": "COMPUTED_JUMP"}])

    def test_ssa_alias_virtual_jump_and_edges(self):
        table(self.new, "pcode-ssa.csv", ["function_entry", "address", "opcode", "output", "inputs"], [
            {"function_entry": "00001000", "address": "00001000", "opcode": "COPY", "output": "v2:8", "inputs": "v1:8"},
            {"function_entry": "00001000", "address": "00001001", "opcode": "LOAD", "output": "v3:8", "inputs": "const:1:8;v2:8"},
            {"function_entry": "00001000", "address": "00001002", "opcode": "CALLIND", "output": "", "inputs": "v3:8"}])
        report = build_advanced_graph(self.new)
        self.assertEqual(report["ssa_ops"], 3)
        self.assertEqual(report["pointer_alias_leads"], 1)
        self.assertEqual(report["virtual_dispatch_leads"], 1)
        self.assertEqual(report["jump_tables"], 1)
        self.assertGreaterEqual(report["def_use_edges"], 2)
        edge_report = check_call_edges(self.new)
        self.assertEqual(edge_report["corroborated"], 1)

    def test_independent_pe_decoder(self):
        code = self.root / "call-bytes.bin"
        code.write_bytes(bytes.fromhex("e8fb0f0000e9f60f000048ff15") + b"\x00" * 16)
        layout = {"path": code, "image_base": 0x1000, "sections": [(0, 100, 0, 100)]}
        self.assertEqual(decode_call(layout, 0x1000, 0x2000)["status"], "verified")
        self.assertEqual(decode_call(layout, 0x1005, 0x2000)["status"], "tail_jump_verified")
        self.assertEqual(decode_call(layout, 0x100A, None)["status"], "site_only")

    def test_ssa_source_to_sink(self):
        table(self.new, "pcode-ssa.csv", ["function_entry", "address", "opcode", "output", "inputs"], [
            {"function_entry": "00001000", "address": "00001003", "opcode": "CALL",
             "output": "v9:4", "inputs": "v1:8;v2:8;v3:8"},
            {"function_entry": "00001000", "address": "00001004", "opcode": "COPY",
             "output": "v4:8", "inputs": "v3:8"},
            {"function_entry": "00001000", "address": "00001005", "opcode": "CALL",
             "output": "", "inputs": "v5:8;v6:8;v4:8"}])
        table(self.new, "imports.csv", ["address", "name"], [
            {"address": "EXTERNAL:1", "name": "recv"}, {"address": "EXTERNAL:2", "name": "strcpy"}])
        table(self.new, "xrefs.csv", ["from_address", "to_address", "type", "operand_index"], [
            {"from_address": "00001003", "to_address": "EXTERNAL:1", "type": "COMPUTED_CALL"},
            {"from_address": "00001005", "to_address": "EXTERNAL:2", "type": "COMPUTED_CALL"}])
        report = build_advanced_graph(self.new)
        self.assertEqual(len(report["ssa_source_sink_leads"]), 1)
        self.assertEqual(report["ssa_source_sink_leads"][0]["source_api"], "recv")

    def test_type_diff_and_call_path_gate(self):
        report = compare_type_signatures(self.old, self.new,
                                         [{"old_entry": "00001000", "new_entry": "00001000"}], self.root)
        self.assertEqual(report["count"], 1)
        self.assertTrue(report["changes"][0]["return_type_changed"])
        gate = gate_new_call_paths(self.old, self.new, ["entry"], ["sink"])
        self.assertEqual(gate["status"], "fail")
        self.assertEqual(len(gate["new_pairs"]), 1)
        table(self.old, "calls.csv", ["caller_entry", "callee_entry"],
              [{"caller_entry": "00001000", "callee_entry": "00002000"}])
        self.assertEqual(gate_new_call_paths(self.old, self.new, ["entry"], ["sink"])["status"], "pass")
        table(self.new, "functions.csv", ["entry", "name", "signature", "body_bytes", "decompiled", "error"], [
            {"entry": "00001000", "name": "entry", "signature": "long entry(char *p)", "body_bytes": "10"},
            {"entry": "00002000", "name": "sink", "signature": "void sink(char *p)", "body_bytes": "10"},
            {"entry": "00003000", "name": "middle", "signature": "void middle(void)", "body_bytes": "10"}])
        table(self.new, "calls.csv", ["caller_entry", "callee_entry"], [
            {"caller_entry": "00001000", "callee_entry": "00002000"},
            {"caller_entry": "00001000", "callee_entry": "00003000"},
            {"caller_entry": "00003000", "callee_entry": "00002000"}])
        self.assertEqual(gate_new_call_paths(self.old, self.new, ["entry"], ["sink"])["new_path_count"], 1)

    def test_vex_provenance_and_fuzz(self):
        sbom = {"bomFormat": "CycloneDX", "components": [{"name": "lib", "bom-ref": "pkg:lib@1"}]}
        (self.new / "SBOM").mkdir()
        source = self.new / "SBOM" / "imported.json"
        source.write_text(json.dumps(sbom), encoding="utf-8")
        import hashlib
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(verify_sbom_provenance(self.new, digest)["integrity"], "match")
        self.assertEqual(verify_sbom_provenance(self.new, "0" * 64)["integrity"], "mismatch")
        vex = self.root / "vex.json"
        vex.write_text(json.dumps({"bomFormat": "CycloneDX", "vulnerabilities": [
            {"id": "CVE-2026-1", "affects": [{"ref": "pkg:lib@1"}],
             "analysis": {"state": "not_affected", "justification": "code_not_reachable"}}]}), encoding="utf-8")
        self.assertEqual(import_vex(self.new, vex)["matched"], 1)
        fuzz = self.root / "fuzz.json"
        fuzz.write_text(json.dumps({"binary_sha256": "a" * 64,
                                    "hits": [{"address": "0x1000", "count": 3}]}), encoding="utf-8")
        self.assertGreaterEqual(import_fuzz_coverage(self.new, fuzz)["hit_blocks"], 1)
        fuzz.write_text(json.dumps({"binary_sha256": "b" * 64, "hits": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must match"):
            import_fuzz_coverage(self.new, fuzz)

    def test_overflow_boundary_not_misrepresented(self):
        rows = [{"status": "ok", "name": "parse", "address": "00003000",
                 "pseudocode": "void parse(char *src) {\nchar buf[8];\nstrcpy(buf, src);\n}"}]
        with patch("castorpollux_overflow.coverage_rows", return_value=rows):
            report = scan_overflows(self.new)
        self.assertEqual(report["count"], 1)
        plan = create_boundary_inputs(self.new, 0)
        self.assertFalse(plan["verified_reproducer"])
        self.assertEqual([item["length"] for item in plan["cases"]], [7, 8, 9])
        self.assertEqual(plan["sandbox_status"], "UNTESTED")


if __name__ == "__main__":
    unittest.main()
