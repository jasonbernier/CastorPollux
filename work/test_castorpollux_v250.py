"""Regression checks for advisory provenance and supplementary evidence workflows."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_binary_profile import check_known_vulnerabilities, detect_binary_profile, scan_embedded_libraries
from castorpollux_evidence_tools import (cve_reachability, dll_signature_inventory, minimize_candidate_input,
                                     link_crash_log, disclosure_packet)
from castorpollux_workspace import build_review_prompt, compare_investigations


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


class Release250Tests(unittest.TestCase):
    def test_local_prompt_uses_embedded_code(self):
        prompt = build_review_prompt({"description": "fixture"}, local=True, plugins=[])
        self.assertIn("Use only the included code chunk", prompt)
        self.assertNotIn("Also inspect cve-reachability.json", prompt)

    def test_unversioned_signature_and_optimization_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            binary = folder / "test.bin"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(80) +
                               b"GCC: (GNU) 14\0gcc -O2 -g\0inflateInit_\0deflateInit_\0")
            (folder / "functions.csv").write_text("entry,name\n0x1000,inflateInit_\n", encoding="utf-8")
            profile = detect_binary_profile(binary)
            self.assertEqual(profile["optimization"]["level"], "-O2")
            inventory = scan_embedded_libraries(binary, folder)
            self.assertEqual(inventory["libraries"][0]["name"], "zlib")
            self.assertIsNone(inventory["libraries"][0]["version"])
            result = check_known_vulnerabilities(folder, lambda _: self.fail("No lookup for unknown version"))
            self.assertEqual(result["results"][0]["status"], "version_unknown")

    def test_offline_cache_and_reachability(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            write_json(folder / "embedded-libraries.json", {"libraries": [{"name": "OpenSSL", "version": "3.0.12",
                "nvd_vendor": "openssl", "nvd_product": "openssl", "corroborating_functions": ["SSL_new"]}]})
            response = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024-12345",
                "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                    "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}]}]}]}}]}
            online = check_known_vulnerabilities(folder, lambda _: response, cache_dir=folder / "cache")
            self.assertEqual(online["results"][0]["source"], "NVD live")
            offline = check_known_vulnerabilities(folder, lambda _: self.fail("Offline used network"),
                                                  offline=True, cache_dir=folder / "cache")
            self.assertEqual(offline["results"][0]["source"], "offline cache")
            (folder / "calls.csv").write_text("caller_entry,caller_name,callee_entry,callee_name\n"
                                               "0x1000,main,0x2000,SSL_new\n", encoding="utf-8")
            lead = cve_reachability(folder)["results"][0]
            self.assertEqual(lead["status"], "candidate call path")
            self.assertEqual(lead["call_paths"][0], ["main", "ssl_new"])
            self.assertIn("does not establish", lead["limitation"])

    def test_dll_inventory_crash_links_and_unverified_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            binary = folder / "target.exe"
            binary.write_bytes(b"MZ")
            dll = folder / "helper.dll"
            dll.write_bytes(b"signed fixture")
            (folder / "imports.csv").write_text("namespace,name\nhelper.dll,Api\nmissing.dll,Api\n",
                                                 encoding="utf-8")
            inventory = dll_signature_inventory(folder, binary, lambda _: {"status": "Valid"})
            self.assertEqual(inventory["dlls"][0]["signature"]["status"], "Valid")
            self.assertEqual(inventory["dlls"][1]["resolution"], "unresolved locally")
            (folder / "functions.csv").write_text("entry,name,body_bytes\n0x1000,parse,64\n", encoding="utf-8")
            write_json(folder / "rea-decompilation.json", {"items": [{"address": "0x1000", "status": "ok",
                "procedure": {"name": "parse"}, "pseudocode": "int parse(void) { return 1; }"}]})
            crash = folder / "crash.txt"
            crash.write_text("fault at 0x00001010", encoding="utf-8")
            links = link_crash_log(folder, crash)
            self.assertEqual(links["links"][0]["offset"], 16)
            sample = folder / "input.dat"
            sample.write_bytes(b"HEADER" + b"\0" * 128)
            reduced = minimize_candidate_input(folder, sample)
            self.assertLess(reduced["candidate_bytes"], reduced["source_bytes"])
            self.assertFalse(reduced["verified_reproducer"])
            self.assertEqual(hashlib.sha256(sample.read_bytes()).hexdigest(), reduced["source_sha256"])

    def test_library_comparison_and_disclosure_redaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left, right = root / "old", root / "new"
            left.mkdir(); right.mkdir()
            for folder, version, body in ((left, "1.0.0", "return 1;"), (right, "1.0.1", "return 2;")):
                write_json(folder / "manifest.json", {"input_name": "sample.exe", "sha256": "a" * 64})
                (folder / "functions.csv").write_text("entry,name,signature\n1000,SSL_new,int SSL_new()\n", encoding="utf-8")
                (folder / "pseudocode.c").write_text(f"/* ===== SSL_new @ 1000 ===== */\n{body}\n", encoding="utf-8")
                write_json(folder / "embedded-libraries.json", {"libraries": [{"name": "OpenSSL",
                    "version": version, "corroborating_functions": ["SSL_new"]}]})
            comparison = compare_investigations(left, right, root / "comparison")
            self.assertEqual(comparison["library_code"][0]["functions_changed"], ["SSL_new"])
            self.assertIn("Library code comparison", (root / "comparison" / "comparison.md").read_text())
            write_json(right / "security-review-data.json", {"created_at": "2026-10-16", "result": {
                "findings": [{"title": "Possible issue", "evidence": [], "note": "token=verysecret"}]}})
            packet = disclosure_packet(right, root / "packet.zip")
            with zipfile.ZipFile(packet) as archive:
                names = archive.namelist()
                self.assertIn("SHA256.json", names)
                self.assertNotIn("sample.exe", names)
                content = archive.read("disclosure-report.json").decode()
                self.assertNotIn("verysecret", content)
                self.assertIn("[REDACTED]", content)


if __name__ == "__main__":
    unittest.main()
