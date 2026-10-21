import json
import io
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_workspace import CodexReview

folder = next((Path(__file__).parent / "castorpollux-v110-test").glob("where-*"))
calls = []

class FakeProcess:
    returncode = 0
    stdout = io.StringIO("Mock agent finished.\n")
    def poll(self):
        return 0
    def wait(self, timeout=None):
        return 0
    def terminate(self):
        self.returncode = 1

def launch(args, **kwargs):
    calls.append(args)
    stage = Path(kwargs["cwd"])
    assert (stage / "pseudocode.c").is_file() and (stage / "disassembly.txt").is_file()
    assert not (stage / "source-binary.exe").exists() and not (stage / "GhidraProject").exists()
    output = Path(args[args.index("--output-last-message") + 1])
    output.write_text(json.dumps({
        "summary": "No evidence-backed potential vulnerabilities were identified in this fixture.",
        "findings": [],
        "limitations": ["This is a mocked integration test and does not assess the binary."],
    }), encoding="utf-8")
    return FakeProcess()

with patch("castorpollux_workspace.probe_agent_stage"), \
     patch("castorpollux_workspace.subprocess.Popen", side_effect=launch):
    result = CodexReview(print, lambda: False, lambda p: None).run(folder, True, Path(sys.executable))

assert "--sandbox" in calls[0] and "read-only" in calls[0]
assert "--cyber-access-program" in calls[0] and "daybreak_blue" in calls[0]
assert all((folder / ("security-report." + ext)).is_file() for ext in ("json", "md", "html", "csv", "pdf"))
print("Mocked Codex integration passed:", result["codex_mode"])
