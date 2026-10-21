"""Focused checks for fingerprints, REA buttons, confidence, and advisory leads."""

from __future__ import annotations

import csv
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_binary_profile import (check_known_vulnerabilities, detect_binary_profile,
                                     scan_embedded_libraries)
from castorpollux_review import coverage_rows, export_coverage_csv
from castorpollux_workspace import _stage_cloud_evidence, render_security_report, run_rea_query


class Release240Tests(unittest.TestCase):
    def test_pe_profile_and_library_lead(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            binary = folder / "sample.exe"
            data = bytearray(1024)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 0x3c, 0x80)
            data[0x80:0x84] = b"PE\0\0"
            struct.pack_into("<H", data, 0x84, 0x8664)
            struct.pack_into("<H", data, 0x98, 0x20b)
            binary.write_bytes(data + b"GCC: (GNU) 13.2\0OpenSSL 3.0.12 24 Oct 2023\0")
            profile = detect_binary_profile(binary, {"language": "x86:LE:64:default", "compiler": "windows"})
            self.assertEqual((profile["format"], profile["architecture"], profile["bitness"]),
                             ("PE", "x86_64", 64))
            self.assertEqual(profile["compiler"]["name"], "GCC")
            self.assertEqual(profile["ghidra_compiler_spec"], "windows")
            (folder / "functions.csv").write_text("entry,name\n0x10,SSL_new\n", encoding="utf-8")
            leads = scan_embedded_libraries(binary, folder)
            self.assertEqual(len(leads["libraries"]), 1)
            self.assertEqual(leads["libraries"][0]["confidence"], "corroborated")
            self.assertEqual(leads["libraries"][0]["version"], "3.0.12")
            urls = []
            def fake_fetch(url):
                urls.append(url)
                return {"totalResults": 2, "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-12345", "descriptions": [
                        {"lang": "en", "value": "Controlled advisory fixture"}],
                        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}]}]}]}},
                    {"cve": {"id": "CVE-2009-1390", "configurations": [{"nodes": [{"cpeMatch": [
                        {"vulnerable": False, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}]}]}]}}]}
            report = check_known_vulnerabilities(folder, fake_fetch)
            self.assertEqual(report["results"][0]["advisories"][0]["id"], "CVE-2024-12345")
            self.assertEqual(len(report["results"][0]["advisories"]), 1)
            self.assertIn("cpeName=", urls[0])
            self.assertEqual(report["results"][0]["status"], "complete")

    def test_elf_profile_and_procedure_confidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            binary = folder / "sample.elf"
            data = bytearray(100)
            data[:6] = b"\x7fELF\x02\x01"
            data[18:20] = (183).to_bytes(2, "little")
            binary.write_bytes(data)
            self.assertEqual(detect_binary_profile(binary)["architecture"], "ARM64")
            items = [{"address": "0x1000", "status": "ok", "procedure": {"name": "parse_input"},
                      "pseudocode": "int parse_input(char *s) { return s[0]; }\n" * 50},
                     {"address": "0x2000", "status": "failed", "error": "provider timeout"}]
            (folder / "rea-decompilation.json").write_text(json.dumps({"items": items}), encoding="utf-8")
            rows = coverage_rows(folder)
            self.assertEqual([row["confidence"] for row in rows], ["high", "unavailable"])
            output = export_coverage_csv(folder, folder / "coverage.csv")
            with output.open(encoding="utf-8-sig", newline="") as stream:
                self.assertIn("confidence_reason", next(csv.DictReader(stream)).keys())

    def test_rea_actions_build_safe_args(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            binary = folder / "saved.exe"
            binary.write_bytes(b"MZfixture")
            import hashlib
            (folder / "manifest.json").write_text(json.dumps({"input_name": binary.name,
                "saved_binary": binary.name,
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}), encoding="utf-8")
            class Store:
                def analysis_paths(self, *_):
                    return tuple(Path(name) for name in ("ghidra", "jdk", "node", "rea"))
            calls = []
            class Process:
                returncode = 0
                def poll(self): return 0
            def launch(args, **kwargs):
                calls.append(args)
                kwargs["stdout"].write(b"{}")
                return Process()
            with patch("castorpollux_workspace.subprocess.Popen", side_effect=launch):
                run_rea_query(Store(), folder, "inspect", "", lambda _: None, lambda: False, lambda _: None)
                run_rea_query(Store(), folder, "search_procedures", "-entry",
                              lambda _: None, lambda: False, lambda _: None)
                run_rea_query(Store(), folder, "decompile", "0x1000",
                              lambda _: None, lambda: False, lambda _: None)
            self.assertEqual(calls[0][2], "inspect")
            self.assertIn("--kind", calls[1])
            self.assertIn("--pattern=-entry", calls[1])
            self.assertIn("--procedure=0x1000", calls[2])

    def test_library_leads_reach_stage_and_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            library = {"name": "OpenSSL", "version": "3.0.12", "confidence": "version string only",
                       "corroborating_functions": []}
            (folder / "embedded-libraries.json").write_text(json.dumps({"libraries": [library]}), encoding="utf-8")
            (folder / "known-vulnerabilities.json").write_text(json.dumps({"results": [{
                "library": "OpenSSL", "version": "3.0.12", "status": "complete",
                "advisories": [{"id": "CVE-2024-12345", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"}]}]}),
                encoding="utf-8")
            scope = {"mode": "all", "selection": "", "description": "one function",
                     "addresses": ["0x1000"], "items": [{"name": "parse", "address": "0x1000", "pseudocode": "return 0;"}]}
            stage = folder / "stage"
            stage.mkdir()
            _stage_cloud_evidence(folder, stage, {"input_name": "sample.exe", "sha256": "a" * 64}, scope, "all")
            self.assertTrue((stage / "embedded-libraries.json").is_file())
            envelope = {"application_version": "2.4.0", "agent": "codex", "codex_mode": "default",
                        "created_at": "2026-10-16T00:00:00Z", "target": {"input_name": "sample.exe", "sha256": "a" * 64},
                        "readiness_warnings": [], "result": {"summary": "Fixture", "findings": [], "limitations": []},
                        "analysis_context": {"binary_profile": {"format": "PE", "architecture": "x86_64",
                            "compiler": {"name": "Microsoft toolchain"}},
                            "embedded_libraries": {"libraries": [library]},
                            "known_vulnerabilities": json.loads((folder / "known-vulnerabilities.json").read_text())}}
            render_security_report(folder, envelope)
            report = (folder / "security-report.md").read_text(encoding="utf-8")
            self.assertIn("CVE-2024-12345", report)
            self.assertIn("Third-party library leads", report)
            self.assertTrue((folder / "security-report.pdf").is_file())


if __name__ == "__main__":
    unittest.main()
