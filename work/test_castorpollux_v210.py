"""Focused checks for 2.1 policy, evidence redaction, patch lineage, and history."""

import csv
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_settings import THEMES, approved_server, load_settings, save_settings
from castorpollux_secrets import scan_secrets
from castorpollux_patch import patch_impact_map
from castorpollux_workspace import InvestigationLibrary
from castorpollux_diagnostics import record_error
from castorpollux_symbols import lookup_symbols
from castorpollux_core import AnalysisRunner


with tempfile.TemporaryDirectory(prefix="castorpollux-v210-") as temporary:
    root = Path(temporary)
    with patch("castorpollux_settings.settings_path", return_value=root / "settings.json"):
        assert len(THEMES) >= 6 and "Daylight" in THEMES
        settings = save_settings({"theme": "Arctic", "symbol_servers": ["https://example.test/symbols"],
                                  "symbol_cache_days": 7, "symbol_cache_mb": 64})
        assert load_settings() == settings
        assert approved_server("https://example.test/symbols", settings)
        try:
            approved_server("https://unlisted.test/symbols", settings)
            raise AssertionError("Unlisted server accepted")
        except ValueError:
            pass
    folder = root / "investigation"
    folder.mkdir()
    key = "AKIA" + "A" * 16
    (folder / "rea-pseudocode.c").write_text(f"void FUN_140001000() {{ password = \"supersecret123\"; // {key}\n}}",
                                               encoding="utf-8")
    report = scan_secrets(folder)
    assert report["count"] == 2
    saved = (folder / "secret-evidence.json").read_text(encoding="utf-8")
    assert key not in saved and "supersecret123" not in saved
    with (folder / "functions.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["entry", "name"])
        writer.writeheader()
        writer.writerows([{"entry": "140001000", "name": "parse_input"},
                          {"entry": "140002000", "name": "copy_bytes"}])
    with (folder / "calls.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["caller_entry", "callee_entry"])
        writer.writeheader()
        writer.writerow({"caller_entry": "140001000", "callee_entry": "140002000"})
    (folder / "security-review-data.json").write_text(json.dumps({"result": {"findings": [{
        "title": "Unsafe copy", "severity": "high", "evidence": [{"location": "parse_input 140001000"}]}]}}),
        encoding="utf-8")
    impact = patch_impact_map(folder, {"functions": {"added": [], "changed": [
        {"function": "copy_bytes", "new_entry": "140002000"}]}})
    assert impact["findings"][0]["relation"] == "called function changed"
    assert len(impact["findings"][0]["call_path"]) == 2
    (folder / "manifest.json").write_text(json.dumps({"input_name": "sample.exe", "sha256": "abc",
        "started_at": "2026-01-01", "saved_binary": "source-binary.exe", "ghidra_status": "complete",
        "rea_status": "complete", "rea_decompile_status": "partial", "warnings": ["one failure"],
        "progress": {"percent": 94, "stage": "Decompiling"},
        "rea_decompile_counts": {"total": 2, "succeeded": 1}, "secret_leads": 2}), encoding="utf-8")
    (folder / "source-binary.exe").write_bytes(b"MZ")
    with patch("castorpollux_workspace.home", return_value=root):
        library = InvestigationLibrary()
        library.add(folder)
        detail = library.details()[0]
        assert detail["finding_count"] == 1 and detail["severities"]["high"] == 1
        assert detail["progress"]["percent"] == 94 and detail["resumable"]
    with patch("castorpollux_diagnostics.home", return_value=root):
        record_error("symbol timeout", folder, "optional symbol lookup")
        assert (folder / "errors.jsonl").is_file()
        assert (root / "Logs" / "castorpollux-errors.jsonl").is_file()
    with patch("castorpollux_workspace.home", return_value=root):
        assert "errors.jsonl" in InvestigationLibrary().details()[0]["logs"]
    binary = root / "symbol-target.exe"
    binary.write_bytes(b"MZtest")
    guid = "01234567-89AB-CDEF-0123-456789ABCDEF"
    class Download:
        def __init__(self):
            self._stream = __import__("io").BytesIO(b"verified pdb bytes")
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def geturl(self):
            return "https://example.test/symbols/sample.pdb"
        def read(self, size):
            return self._stream.read(size)
    class Opener:
        def open(self, *_args, **_kwargs):
            return Download()
    identity = {"kind": "pdb", "identity": {"guid": guid, "age": 1}}
    with patch("castorpollux_symbols._pe_codeview", return_value=(guid, 1, "sample.pdb")), \
         patch("castorpollux_symbols.verify_symbols", return_value=identity), \
         patch("castorpollux_symbols.urllib.request.build_opener", return_value=Opener()):
        _path, first = lookup_symbols(binary, root / "symbols-one", "https://example.test/symbols",
                                      root / "cache", 7, 64)
        _path, second = lookup_symbols(binary, root / "symbols-two", "https://example.test/symbols",
                                       root / "cache", 7, 64)
        assert not first["cache_hit"] and second["cache_hit"]
    class MissingEngine:
        root = root / "components"
        def current_version(self, _name):
            return "not installed"
        def analysis_paths(self, _notify, _cancelled):
            raise RuntimeError("engine unavailable")
    with patch("castorpollux_core.home", return_value=root), \
         patch("castorpollux_diagnostics.home", return_value=root):
        stopped = AnalysisRunner(MissingEngine(), lambda _message: None, lambda: False,
                                 lambda _process: None).run(binary, root / "stopped")
        manifest = json.loads((stopped / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["sha256"] and manifest["ghidra_status"] == "pending"
        assert (stopped / "errors.jsonl").is_file()
    with patch("castorpollux_workspace.home", return_value=root):
        assert any(item["path"] == str(stopped.resolve()) for item in InvestigationLibrary().details())

print("CastorPollux 2.1 themes, policy, secrets, patch impact, history, and errors passed")
