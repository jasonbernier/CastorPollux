"""Integration checks for coverage, scope, evidence, triage, archives, and local review."""

import csv
import io
import json
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_review import (coverage_rows, evidence_jump, export_coverage_csv,
                             finding_key, load_triage, ollama_models, ollama_review, _local_chat,
                             resolve_scope, save_triage)
from castorpollux_workspace import CodexReview, SECURITY_SCHEMA, review_readiness


source = next((Path(__file__).parent / "castorpollux-v110-test").glob("where-*"))
report_paths = [source / "security-report.json", *source.glob("ReviewHistory/*/security-report.json")]
old_report = next(report for path in report_paths
                  if (report := json.loads(path.read_text(encoding="utf-8")))["result"]["findings"])
finding = old_report["result"]["findings"][0]
needed = ("manifest.json", "rea-pseudocode.c", "rea-decompilation.json", "functions.csv",
          "symbols.csv", "sections.csv", "calls.csv", "xrefs.csv", "pseudocode.c",
          "security-report.json")


class Handler(BaseHTTPRequestHandler):
    posted = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        assert self.path == "/api/tags"
        value = {"models": [{"name": "local-test:1", "size": 123456},
                            {"name": "remote:cloud", "size": 0}]}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())

    def do_POST(self):
        assert self.path == "/api/chat"
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Handler.posted.append(body)
        assert body["model"] == "local-test:1" and body["stream"] is False
        assert body["format"] == SECURITY_SCHEMA
        result = {"summary": "No evidence-backed issue in this chunk.", "findings": [], "limitations": []}
        response = {"message": {"role": "assistant", "content": json.dumps(result)}, "done": True}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            self.wfile.write(json.dumps(response).encode())
        except ConnectionError:
            pass


class FakeProcess:
    returncode = 0
    stdout = io.StringIO("")

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        self.returncode = 1


with tempfile.TemporaryDirectory(prefix="castorpollux-v150-") as directory:
    folder = Path(directory)
    for name in needed:
        shutil.copy2(source / name, folder / name)
    rows = coverage_rows(folder)
    assert len(rows) == 103 and all(row["status"] == "ok" for row in rows)
    assert {row["section"] for row in rows} == {".text"}
    assert "Global" in {row["module"] for row in rows}
    partial = folder / "partial"
    partial.mkdir()
    (partial / "rea-decompilation-progress.json").write_text(json.dumps({
        "addresses": ["0x140001010", "0x1400010f0"],
        "items": {"0x140001010": {"address": "0x140001010", "status": "failed",
                                    "error": "provider error"}}}), encoding="utf-8")
    assert [row["status"] for row in coverage_rows(partial)] == ["failed", "pending"]
    exported = export_coverage_csv(folder, folder / "coverage.csv")
    with exported.open(encoding="utf-8-sig", newline="") as stream:
        assert len(list(csv.DictReader(stream))) == 103

    target = rows[0]
    scope = resolve_scope(folder, "functions", target["name"])
    assert scope["addresses"] == [target["address"]]
    assert len(resolve_scope(folder, "modules", "Global")["items"]) >= 1
    try:
        resolve_scope(folder, "functions", "does_not_exist")
        raise AssertionError("Unmatched scope was accepted")
    except ValueError:
        pass

    jump = evidence_jump(folder, finding["evidence"][0])
    assert jump["code"] and jump["function"] and jump["address"]
    try:
        evidence_jump(folder, {"file": "../secrets.txt", "location": "0x140001010"})
        raise AssertionError("Citation path escape was accepted")
    except ValueError:
        pass
    save_triage(folder, finding, "needs_more_evidence", "Check lifetime manually")
    assert load_triage(folder)[finding_key(finding)]["note"] == "Check lifetime manually"
    assert review_readiness(folder)[0]["sha256"]

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        assert ollama_models(url) == ["local-test:1"]
        try:
            _local_chat(url, {"model": "local-test:1", "stream": False, "format": SECURITY_SCHEMA}, lambda: True)
            raise AssertionError("Local review cancellation was ignored")
        except InterruptedError:
            pass
        result = ollama_review(scope, "local-test:1", "Review scoped code.", SECURITY_SCHEMA,
                               lambda _: None, lambda: False, url)
        assert result["findings"] == [] and Handler.posted
        assert target["name"] in Handler.posted[-1]["messages"][0]["content"]
        with patch("castorpollux_workspace.ollama_review",
                   side_effect=lambda s, m, p, schema, notify, cancelled:
                       ollama_review(s, m, p, schema, notify, cancelled, url)):
            envelope = CodexReview(lambda _: None, lambda: False, lambda _: None).run(
                folder, False, None, {"md"}, "ollama", "functions", target["name"], "local-test:1")
        assert envelope["agent"] == "ollama" and envelope["review_scope"]["mode"] == "functions"
        assert (folder / "security-review-data.json").is_file()
        assert (folder / "security-report.md").is_file() and not (folder / "security-report.json").exists()
        assert len(list((folder / "ReviewHistory").iterdir())) == 1

        def fake_launch(args, **kwargs):
            stage = Path(kwargs["cwd"])
            code = (stage / "rea-pseudocode.c").read_text(encoding="utf-8")
            assert target["name"] in code and len(code) < 20_000
            assert not (stage / "disassembly.txt").exists()
            with (stage / "functions.csv").open(encoding="utf-8", newline="") as stream:
                assert len(list(csv.DictReader(stream))) == 1
            assert not (stage / "source-binary.exe").exists()
            Path(args[args.index("--output-last-message") + 1]).write_text(json.dumps({
                "summary": "Scoped test", "findings": [], "limitations": []}), encoding="utf-8")
            return FakeProcess()

        with patch("castorpollux_preflight.agent_capabilities", return_value={"status": "ready", "missing": []}), \
             patch("castorpollux_workspace.probe_agent_stage"), \
             patch("castorpollux_workspace.subprocess.Popen", side_effect=fake_launch):
            cli = CodexReview(lambda _: None, lambda: False, lambda _: None).run(
                folder, False, Path(sys.executable), {"json"}, "codex", "functions", target["name"])
        assert cli["agent"] == "codex" and (folder / "security-report.json").is_file()
        assert len(list((folder / "ReviewHistory").iterdir())) == 2
    finally:
        server.shutdown()
        server.server_close()

print("Coverage, export, scope, citations, triage, local protocol, CLI staging, and archives passed")
