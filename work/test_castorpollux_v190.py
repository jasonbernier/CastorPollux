"""Focused regression tests for symbol identity, SARIF, unpacking and rule gates."""

import io
import json
import struct
import sys
import tarfile
import tempfile
import uuid
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import castorpollux_flow
from castorpollux_flow import activate_rule_change, evaluate_rule_change
from castorpollux_runtime import build_trace_timeline
from castorpollux_sarif import render_sarif
from castorpollux_symbols import verify_symbols
from castorpollux_unpack import unpack_binary
from castorpollux_core import sha256
from castorpollux_tracking import set_flow_answers
from castorpollux_workspace import render_security_report


def pe_fixture(guid, age):
    blob = bytearray(1024)
    blob[:2] = b"MZ"
    struct.pack_into("<I", blob, 60, 0x80)
    blob[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", blob, 0x86, 1)
    struct.pack_into("<H", blob, 0x94, 224)
    struct.pack_into("<H", blob, 0x98, 0x10b)
    struct.pack_into("<II", blob, 0x98 + 96 + 48, 0x1000, 28)
    section = 0x80 + 24 + 224
    struct.pack_into("<IIII", blob, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<IIII", blob, 0x200 + 12, 2, 24, 0, 0x300)
    blob[0x300:0x304] = b"RSDS"
    blob[0x304:0x314] = guid.bytes_le
    struct.pack_into("<I", blob, 0x314, age)
    return bytes(blob)


def pdb_fixture(guid, age):
    block = 4096
    blob = bytearray(block * 6)
    blob[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    struct.pack_into("<6I", blob, 32, block, 1, 6, 16, 0, 3)
    struct.pack_into("<I", blob, block * 3, 4)
    struct.pack_into("<4I", blob, block * 4, 2, 0, 28, 5)
    struct.pack_into("<III", blob, block * 5, 20000404, 0, age)
    blob[block * 5 + 12:block * 5 + 28] = guid.bytes_le
    return bytes(blob)


def elf_fixture(build_id):
    blob = bytearray(512)
    blob[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", blob, 16, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", blob, 64, 4, 0, 0x100, 0, 0, 36, 36, 4)
    struct.pack_into("<III", blob, 0x100, 4, len(build_id), 3)
    blob[0x10c:0x110] = b"GNU\0"
    blob[0x110:0x110 + len(build_id)] = build_id
    return bytes(blob)


with tempfile.TemporaryDirectory(prefix="castorpollux-v190-") as temporary:
    root = Path(temporary)
    guid = uuid.uuid4()
    binary = root / "sample.exe"
    symbol = root / "sample.pdb"
    binary.write_bytes(pe_fixture(guid, 2))
    symbol.write_bytes(pdb_fixture(guid, 2))
    assert verify_symbols(binary, symbol)["identity"] == {"guid": str(guid), "age": 2}
    symbol.write_bytes(pdb_fixture(guid, 3))
    try:
        verify_symbols(binary, symbol)
        assert False, "PDB age mismatch accepted"
    except ValueError as error:
        assert "mismatch" in str(error)
    real_pair = Path(__file__).parent / "runtime/node_modules/@lydell/node-pty-win32-x64"
    if (real_pair / "conpty.node").is_file() and (real_pair / "conpty.pdb").is_file():
        assert verify_symbols(real_pair / "conpty.node", real_pair / "conpty.pdb")["status"] == "verified"
    elf = root / "app.elf"
    debug = root / "app.debug"
    elf.write_bytes(elf_fixture(bytes(range(20))))
    debug.write_bytes(elf_fixture(bytes(range(20))))
    assert verify_symbols(elf, debug)["identity"]["build_id"] == bytes(range(20)).hex()
    debug.write_bytes(elf_fixture(b"wrong-build-id-12345"))
    try:
        verify_symbols(elf, debug)
        assert False, "ELF build ID mismatch accepted"
    except ValueError as error:
        assert "mismatch" in str(error)

    envelope = {"application_version": "1.9.0", "agent": "codex", "codex_mode": "default",
                "created_at": "2026-01-01", "target": {"input_name": "sample.exe", "sha256": "a" * 64},
                "quality_gate": {"status": "pass", "succeeded": 1, "total": 1,
                                 "coverage_percent": 100, "source_chars": 2000, "reasons": []},
                "result": {"limitations": ["partial"],
                "findings": [{"title": "Overflow", "description": "Unbounded copy", "severity": "high",
                              "confidence": "medium", "impact": "memory corruption",
                              "recommendation": "bound the copy", "validation": "inspect buffer length",
                              "evidence": [{"file": "rea-pseudocode.c",
                              "location": "FUN_12345678 @ 0x12345678 line 12", "observation": "copy"}]}]}}
    envelope["result"]["summary"] = "One candidate"
    (root / "rea-pseudocode.c").write_text("/* ===== FUN_12345678 @ 12345678 ===== */\n" +
                                            "line\n" * 15, encoding="utf-8")
    sarif = render_sarif(envelope, root)
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"][0]["level"] == "error"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 13
    reports = root / "reports"
    reports.mkdir()
    render_security_report(reports, envelope, evidence_root=root)
    assert (reports / "security-report.sarif").is_file()
    try:
        import jsonschema
    except ImportError:
        pass
    else:
        schema_path = Path(__file__).parent / "sarif-2.1.0.schema.json"
        if schema_path.is_file():
            jsonschema.validate(sarif, json.loads(schema_path.read_text(encoding="utf-8")))

    archive = root / "sample.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("bin/sample.exe", binary.read_bytes())
    unpacked = root / "unpacked"
    result = unpack_binary(archive, unpacked)
    assert result["files"][0]["format"] == "PE"
    assert sha256(unpacked / "files/bin/sample.exe") == sha256(binary)
    traversal = root / "bad.zip"
    with zipfile.ZipFile(traversal, "w") as z:
        z.writestr("../escape.exe", binary.read_bytes())
    try:
        unpack_binary(traversal, root / "bad-out")
        assert False, "Path traversal accepted"
    except ValueError as error:
        assert "unsafe" in str(error)
    firmware = root / "firmware.bin"
    firmware.write_bytes(b"FIRMWARE" * 20 + binary.read_bytes())
    carved = unpack_binary(firmware, root / "carved")
    assert carved["files"] and carved["files"][0]["format"] == "PE"
    with tarfile.open(root / "sample.tar", "w") as tar:
        info = tarfile.TarInfo("firmware.bin")
        data = firmware.read_bytes()
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    assert unpack_binary(root / "sample.tar", root / "tar-out")["files"]

    flow = {"leads": [{"function": "FUN_12345678", "address": "0x12345678", "source_api": "ReadFile",
                       "sink_api": "CreateProcess", "sink_line": 5}]}
    trace = {"events": [{"timestamp": "2026-01-01T00:00:01Z", "type": "process_start", "parent_pid": 1},
                        {"timestamp": "2026-01-01T00:00:00Z", "type": "process_start", "parent_pid": 0}]}
    timeline = build_trace_timeline(trace, flow)
    assert timeline[1]["candidate_citations"][0]["location"] == "FUN_12345678 @ 0x12345678"

    case_folder = root / "case"
    case_folder.mkdir()
    (case_folder / "manifest.json").write_text(json.dumps({"sha256": "a" * 64}), encoding="utf-8")
    (case_folder / "rea-decompilation.json").write_text(json.dumps({"items": [{"status": "ok",
        "address": "0x12345678", "procedure": {"name": "sample"},
        "pseudocode": "ReadFile(handle, buffer);\nCreateProcess(buffer);"}]}), encoding="utf-8")
    corpus = root / "corpus.json"
    (root / "corpus.json").write_text(json.dumps({"schema": 1, "cases": []}), encoding="utf-8")
    set_flow_answers(corpus, case_folder,
                     [{"function": "sample", "source_api": "ReadFile", "sink_api": "CreateProcess"}], True)
    active = root / "active.json"
    candidate = root / "candidate.json"
    active.write_text(json.dumps({"schema": 1, "sources": [{"name": "ReadFile", "output": 1}],
                                  "sinks": ["CreateProcess"], "sanitizers": []}), encoding="utf-8")
    candidate.write_text(active.read_text(encoding="utf-8"), encoding="utf-8")
    original = castorpollux_flow.rules_path
    castorpollux_flow.rules_path = lambda: active
    try:
        passing = evaluate_rule_change(candidate, corpus, [case_folder])
        assert passing["status"] == "passed" and passing["candidate"]["tp"] == 1
        assert activate_rule_change(candidate, corpus, [case_folder],
                                    passing["candidate_sha256"])["status"] == "passed"
        candidate.write_text(json.dumps({"schema": 1, "sources": [], "sinks": [], "sanitizers": []}), encoding="utf-8")
        blocked = evaluate_rule_change(candidate, corpus, [case_folder])
        assert blocked["status"] == "blocked" and blocked["candidate"]["fn"] == 1
        try:
            activate_rule_change(candidate, corpus, [case_folder], blocked["candidate_sha256"])
            assert False, "Regression was activated"
        except ValueError:
            pass
        assert "ReadFile" in active.read_text(encoding="utf-8")
    finally:
        castorpollux_flow.rules_path = original

print("CastorPollux 1.9 identity, SARIF, unpack, timeline, and corpus gate passed")
