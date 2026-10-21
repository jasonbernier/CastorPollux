"""Regression checks for cross-function flow, blocks, indirect calls and SBOMs."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_blocks import build_basic_block_diff
from castorpollux_callpaths import explore_paths
from castorpollux_indirect import resolve_indirect_calls
from castorpollux_interflow import build_cross_function_flow
from castorpollux_sbom import compare_sbom


class Release270Tests(unittest.TestCase):
    def test_cross_function_flow_follows_direct_parameter_and_stops_without_edge(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "calls.csv").write_text("caller_entry,caller_name,callee_entry,callee_name\n"
                "10001000,entry,10001100,parse\n", encoding="utf-8")
            rows = {"items": [
                {"address": "10001000", "status": "ok", "procedure": {"name": "entry"},
                 "pseudocode": "void entry(void) {\n  recv(fd,buffer,32);\n  parse(buffer);\n}"},
                {"address": "10001100", "status": "ok", "procedure": {"name": "parse"},
                 "pseudocode": "void parse(char *param_1) {\n  strcpy(dst,param_1);\n}"}]}
            (folder / "rea-decompilation.json").write_text(json.dumps(rows), encoding="utf-8")
            report = build_cross_function_flow(folder, plugins=[])
            self.assertEqual(len(report["leads"]), 1)
            self.assertEqual(report["leads"][0]["sink_api"], "strcpy")
            self.assertEqual(len(report["leads"][0]["call_path"]), 2)
            (folder / "calls.csv").write_text("caller_entry,caller_name,callee_entry,callee_name\n", encoding="utf-8")
            self.assertEqual(build_cross_function_flow(folder, plugins=[])["leads"], [])
            (folder / "calls.csv").write_text("caller_entry,caller_name,callee_entry,callee_name\n"
                "10001000,entry,10001100,getvalue\n", encoding="utf-8")
            rows["items"][0]["pseudocode"] = "void entry(void) {\n  value = getvalue();\n  system(value);\n}"
            rows["items"][1]["procedure"]["name"] = "getvalue"
            rows["items"][1]["pseudocode"] = "char *getvalue(void) {\n  char *x;\n  x = getenv(NAME);\n  return x;\n}"
            (folder / "rea-decompilation.json").write_text(json.dumps(rows), encoding="utf-8")
            returned = build_cross_function_flow(folder, plugins=[])
            self.assertEqual(len(returned["leads"]), 1)
            self.assertEqual([node["name"] for node in returned["leads"][0]["call_path"]],
                             ["getvalue", "entry"])

    def test_indirect_target_confidence_and_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "functions.csv").write_text("entry,name,body_bytes\n"
                "10001000,entry,32\n10001100,target,16\n", encoding="utf-8")
            (folder / "calls.csv").write_text("caller_entry,caller_name,callee_entry,callee_name\n",
                                             encoding="utf-8")
            (folder / "disassembly.txt").write_text("10001002  CALL RAX\n10001008  CALL RBX\n",
                                                      encoding="utf-8")
            (folder / "xrefs.csv").write_text("from_address,to_address,type,operand_index\n"
                "10001002,10001100,COMPUTED_CALL,0\n", encoding="utf-8")
            report = resolve_indirect_calls(folder)
            self.assertEqual(report["resolved"][0]["confidence"], "medium")
            self.assertEqual(len(report["unresolved"]), 1)
            path = explore_paths(folder, "entry", "target")
            self.assertEqual(path["paths"][0][1]["incoming"]["confidence"], "medium")

    def test_block_map_and_sbom_match_and_conflict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old", root / "new"
            old.mkdir(); new.mkdir()
            for folder, base, constant in ((old, "10001000", "1"), (new, "20002000", "2")):
                (folder / "functions.csv").write_text(f"entry,name,body_bytes\n{base},parse,32\n",
                                                       encoding="utf-8")
                address = int(base, 16)
                (folder / "disassembly.txt").write_text(
                    f"{address:x}  CMP EAX,{constant}\n{address+2:x}  JZ {address+8:x}\n"
                    f"{address+4:x}  ADD EAX,1\n{address+8:x}  RET\n", encoding="utf-8")
                (folder / "xrefs.csv").write_text("from_address,to_address,type,operand_index\n"
                    f"{address+2:x},{address+8:x},CONDITIONAL_JUMP,0\n", encoding="utf-8")
            report = build_basic_block_diff(old, new, [{"name": "parse", "old_entry": "10001000",
                "new_entry": "20002000"}], root / "diff")
            self.assertEqual(report["procedure_count"], 1)
            self.assertGreaterEqual(report["procedures"][0]["counts"]["unchanged"], 1)
            self.assertTrue((root / "diff" / "basic-block-diff.json").is_file())
            repeated = build_basic_block_diff(old, old, [{"name": "parse", "old_entry": "10001000",
                "new_entry": "10001000"}], root / "same")
            self.assertEqual(repeated["procedures"][0]["counts"]["changed"], 0)
            (new / "embedded-libraries.json").write_text(json.dumps({"libraries": [
                {"name": "OpenSSL", "version": "3.0.1", "confidence": "candidate signature"},
                {"name": "zlib", "version": "1.2.13", "confidence": "version string only"}]}), encoding="utf-8")
            sbom = root / "sbom.json"
            sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
                {"name": "openssl", "version": "3.0.1", "bom-ref": "one"},
                {"name": "zlib", "version": "1.2.12", "bom-ref": "two"}]}), encoding="utf-8")
            compared = compare_sbom(new, sbom)
            statuses = {row["library"]: row["status"] for row in compared["detected_libraries"]}
            self.assertEqual(statuses, {"OpenSSL": "name_and_version_match", "zlib": "version_conflict"})
            self.assertEqual(compare_sbom(new)["source_sha256"], compared["source_sha256"])
            spdx = root / "spdx.json"
            spdx.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [
                {"name": "openssl", "versionInfo": "3.0.1", "SPDXID": "SPDXRef-openssl"}]}),
                encoding="utf-8")
            self.assertEqual(compare_sbom(new, spdx)["format"], "SPDX")


if __name__ == "__main__":
    unittest.main()
