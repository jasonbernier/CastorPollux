"""Focused regression checks for review readiness, agent adapters, and formats."""

import json
import io
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_workspace import CodexReview, review_readiness

source = next((Path(__file__).parent / "castorpollux-v110-test").glob("where-*"))
result = {"summary": "Fixture review only.", "findings": [], "limitations": ["Mocked agent."]}


class FakeProcess:
    returncode = 0

    def __init__(self, output=""):
        self.stdout = io.StringIO(output)

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        self.returncode = 1


with tempfile.TemporaryDirectory(prefix="castorpollux-v120-") as directory:
    folder = Path(directory)
    for name in ("manifest.json", "pseudocode.c", "functions.csv", "disassembly.txt", "rea-evidence.json"):
        shutil.copy2(source / name, folder / name)
    for name in ("rea-pseudocode.c", "rea-decompilation.json"):
        shutil.copy2(Path(__file__).parent / "rea-decomp-test" / name, folder / name)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    manifest["ghidra_status"] = "failed"
    manifest["rea_status"] = "failed"
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    _, warnings = review_readiness(folder)
    assert len(warnings) == 2

    def fake_launch(args, **kwargs):
        stage = Path(kwargs["cwd"])
        assert (stage / "rea-pseudocode.c").is_file()
        assert (stage / "pseudocode.c").is_file()
        assert not (stage / "source-binary.exe").exists()
        output = "Inspecting staged pseudocode\n" if "--output-last-message" in args else ""
        if "--output-last-message" in args:
            Path(args[args.index("--output-last-message") + 1]).write_text(json.dumps(result), encoding="utf-8")
        elif "--json-schema" in args:
            output = json.dumps({"structured_output": result})
        else:
            assert kwargs["env"]["OPENCODE_CONFIG_CONTENT"]
            output = "```json\n" + json.dumps(result) + "\n```"
        return FakeProcess(output)

    for agent, formats in (("codex", {"json", "pdf"}), ("claude", {"md"}),
                           ("opencode", {"html", "csv"})):
        notifications = []
        with patch("castorpollux_preflight.agent_capabilities", return_value={"status": "ready", "missing": []}), \
             patch("castorpollux_workspace.probe_agent_stage"), \
             patch("castorpollux_workspace.subprocess.Popen", side_effect=fake_launch):
            envelope = CodexReview(notifications.append, lambda: False, lambda _: None).run(
                folder, False, Path(sys.executable), formats, agent)
        assert any(message.startswith("Agent live:") for message in notifications)
        assert envelope["agent"] == agent and envelope["readiness_warnings"] == warnings
        for extension in ("json", "md", "html", "csv", "pdf"):
            assert (folder / ("security-report." + extension)).is_file() == (extension in formats)

print("Review readiness, three agent adapters, and selective formats passed")
