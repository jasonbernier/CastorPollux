"""Quality, privacy, secondary engine, and batch behavior checks."""

import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_quality import coverage_assessment, redact_stage, second_decompiler_check
from castorpollux_workspace import _stage_cloud_evidence, read_manifest, resolve_scope
from castorpollux_batch import run_batch


source = next((Path(__file__).parent / "castorpollux-v110-test").glob("where-*"))
with tempfile.TemporaryDirectory(prefix="castorpollux-v160-") as temporary:
    folder = Path(temporary)
    for name in ("manifest.json", "rea-pseudocode.c", "rea-decompilation.json", "functions.csv",
                 "symbols.csv", "sections.csv", "strings.csv", "calls.csv", "xrefs.csv"):
        shutil.copy2(source / name, folder / name)
    quality = coverage_assessment(folder, 80)
    assert quality["status"] == "passed" and quality["succeeded"] == 103
    decomp = json.loads((folder / "rea-decompilation.json").read_text(encoding="utf-8"))
    for item in decomp["items"][2:]:
        item["status"] = "failed"
    (folder / "rea-decompilation.json").write_text(json.dumps(decomp), encoding="utf-8")
    quality = coverage_assessment(folder, 80)
    assert quality["status"] == "warning" and quality["coverage_percent"] < 5
    scope = resolve_scope(folder, "all", "")
    stage = folder / "stage"
    stage.mkdir()
    with (folder / "strings.csv").open("a", encoding="utf-8") as output:
        output.write("\n0x140000001,password=secretvalue123,23\n")
    _stage_cloud_evidence(folder, stage, read_manifest(folder), scope, "all")
    result = redact_stage(stage, ["secretvalue123"])
    assert result["total_replacements"] > 0
    assert "secretvalue123" not in (stage / "strings.csv").read_text(encoding="utf-8")
    assert "secretvalue123" in (folder / "strings.csv").read_text(encoding="utf-8")
    high = [{"title": "High test", "severity": "high",
             "evidence": [{"file": "rea-pseudocode.c", "location": "FUN_140001010"}]}]
    missing = second_decompiler_check(folder, high, None, lambda _: None, lambda: False, lambda _: None)
    assert missing["status"] == "unavailable"
    (folder / "source-binary.exe").write_bytes(b"MZ" + b"\0" * 128)
    retdec = folder / "retdec-decompiler.exe"
    retdec.write_bytes(b"test")

    class FakeProcess:
        returncode = 0
        def poll(self):
            return 0

    def launch(args, **_):
        Path(args[args.index("-o") + 1]).write_text("void FUN_140001010() { return; }", encoding="utf-8")
        return FakeProcess()

    with patch("castorpollux_quality.subprocess.Popen", side_effect=launch):
        secondary = second_decompiler_check(folder, high, retdec, lambda _: None,
                                            lambda: False, lambda _: None)
    assert secondary["status"] == "completed"
    assert secondary["findings"][0]["status"] == "matching_location_found"
    assert "does not confirm" in secondary["message"]

    config = folder / "batch.json"
    config.write_text(json.dumps({"inputs": [str(folder / "source-binary.exe")],
                                  "output": str(folder), "agent": "none",
                                  "summary": str(folder / "summary.json")}), encoding="utf-8")
    with patch("castorpollux_batch.AnalysisRunner.run", return_value=folder):
        assert run_batch(config) == 0
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    assert summary["results"][0]["status"] == "complete"

print("Coverage thresholds, redaction, secondary decompiler, and batch passed")
