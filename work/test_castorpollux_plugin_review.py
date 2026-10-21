"""Verify an enabled plugin reaches the agent request and extra report."""

import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_plugins import SAMPLE, validate_plugin
from castorpollux_workspace import CodexReview

source = next((Path(__file__).parent / "castorpollux-v110-test").glob("where-*"))
plugin = validate_plugin({**SAMPLE, "enabled": True, "path": "test-plugin.json"})

class FakeProcess:
    returncode = 0
    def poll(self): return 0
    def wait(self, timeout=None): return 0
    def terminate(self): self.returncode = 1

def launch(args, **kwargs):
    stage = Path(kwargs["cwd"])
    request = (stage / "security-review-request.txt").read_text(encoding="utf-8")
    assert "MyRiskyApi" in request
    Path(args[args.index("--output-last-message") + 1]).write_text(json.dumps({
        "summary": "Plugin integration fixture", "findings": [], "limitations": []}), encoding="utf-8")
    return FakeProcess()

with tempfile.TemporaryDirectory(prefix="castorpollux-plugin-review-") as temp:
    folder = Path(temp)
    for name in ("manifest.json", "rea-pseudocode.c", "rea-decompilation.json",
                 "functions.csv", "symbols.csv", "sections.csv", "strings.csv", "calls.csv", "xrefs.csv"):
        shutil.copy2(source / name, folder / name)
    with patch("castorpollux_workspace.load_plugins", return_value=[plugin]), \
         patch("castorpollux_workspace.subprocess.Popen", side_effect=launch):
        report = CodexReview(lambda _: None, lambda: False, lambda _: None).run(
            folder, False, Path(sys.executable), {"json"}, secondary_decompiler=False)
    assert report["plugins"][0]["id"] == "example-policy"
    custom = folder / "security-report-plugin-example-policy.md"
    assert custom.is_file() and "Plugin integration fixture" in custom.read_text(encoding="utf-8")

print("Plugin guidance and report template integration passed")
