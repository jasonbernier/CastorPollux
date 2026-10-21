"""Focused regressions for the 2.0 evidence and release additions."""

import json
import tempfile
import unittest
import zipfile
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

from castorpollux_findings import active_suppression, clear_suppression, enrich_findings, set_suppression
from castorpollux_sarif import render_sarif
from castorpollux_similarity import similar_functions
from castorpollux_symbols import lookup_symbols
from castorpollux_unpack import unpack_binary


class Version200Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def _investigation(self, name, code, address="0x1000", function="entry"):
        folder = self.root / name
        folder.mkdir()
        (folder / "rea-decompilation.json").write_text(json.dumps({"items": [
            {"address": address, "procedure": {"name": function}, "status": "ok", "pseudocode": code}]}))
        (folder / "functions.csv").write_text('entry,name\n1000,entry\n2000,worker\n')
        (folder / "calls.csv").write_text('caller_entry,callee_entry\n1000,2000\n')
        return folder

    def test_unpack_deduplicates_logical_components(self):
        archive = self.root / "firmware.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("a.bin", b"same component")
            output.writestr("nested/b.bin", b"same component")
        folder = self.root / "unpacked"
        report = unpack_binary(archive, folder)
        self.assertEqual((report["unique_files"], report["duplicate_files"], report["bytes_saved"]), (1, 1, 14))
        self.assertEqual(report["files"][1]["duplicate_of"], "files/a.bin")
        self.assertFalse((folder / "files/nested/b.bin").exists())
        self.assertEqual((folder / report["files"][1]["stored_path"]).read_bytes(), b"same component")

    def test_similarity_uses_reconstructed_code(self):
        code = "int entry(char *input) { int length = strlen(input); if (length > 10) return 1; return length; }"
        first = self._investigation("first", code)
        second = self._investigation("second", code.replace("entry", "worker").replace("10", "11"))
        rows = similar_functions(first, "entry", [first, second], minimum=0.5)
        self.assertEqual(len(rows), 1)
        self.assertGreater(rows[0]["similarity"], 0.5)

    def test_cwe_reachability_suppression_and_sarif(self):
        folder = self._investigation("finding", "void worker(char *input) { strcpy(buffer, input); }",
                                     "0x2000", "worker")
        finding = {"title": "Unchecked buffer copy", "description": "Potential buffer overflow",
                   "severity": "high", "confidence": "medium", "impact": "Memory corruption",
                   "recommendation": "Bound the copy", "validation": "Inspect size checks",
                   "evidence": [{"file": "rea-pseudocode.c", "location": "0x2000 line 1",
                                 "observation": "strcpy(buffer, input) copies without a bound"}]}
        enrich_findings(folder, [finding])
        self.assertEqual(finding["cwe"]["id"], "CWE-120")
        self.assertEqual(finding["reachability"]["rank"], "near")
        expiry = (date.today() + timedelta(days=2)).isoformat()
        set_suppression(folder, finding, "Accepted for this test", expiry, "analyst")
        self.assertIsNotNone(active_suppression(folder, finding))
        self.assertIsNone(active_suppression(folder, finding, date.today() + timedelta(days=3)))
        envelope = {"result": {"findings": [finding]}, "target": {}, "quality_gate": {}}
        sarif = render_sarif(envelope, folder)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "CWE-120")
        self.assertIn("suppressions", sarif["runs"][0]["results"][0])
        clear_suppression(folder, finding, "analyst")
        self.assertIsNone(active_suppression(folder, finding))

    def test_symbol_lookup_is_https_and_records_verified_provenance(self):
        binary = self.root / "target.exe"
        binary.write_bytes(b"MZ" + bytes(30))
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def geturl(self): return "https://symbols.example/test.pdb"
            def read(self, _):
                data, self.data = getattr(self, "data", b"PDBDATA"), b""
                return data
        with patch("castorpollux_symbols._pe_codeview", return_value=("12345678-1234-1234-1234-123456789abc", 2, "test.pdb")), \
             patch("castorpollux_symbols.verify_symbols", return_value={"kind": "pdb", "identity":
                   {"guid": "12345678-1234-1234-1234-123456789abc", "age": 2}}), \
             patch("urllib.request.OpenerDirector.open", return_value=Response()) as request:
            path, provenance = lookup_symbols(binary, self.root / "symbols", "https://symbols.example")
        self.assertEqual(path.read_bytes(), b"PDBDATA")
        self.assertIn("12345678123412341234123456789ABC2", provenance["requested_url"])
        self.assertEqual(provenance["bytes"], 7)
        self.assertEqual(request.call_count, 1)
        with self.assertRaises(ValueError):
            lookup_symbols(binary, self.root / "symbols", "http://symbols.example")


if __name__ == "__main__":
    unittest.main()
