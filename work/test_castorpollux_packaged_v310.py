"""Packaged v3.1 smoke: bundled scan and persisted dashboard metrics."""

import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
target = root / "work" / "castorpollux-v310-packaged-smoke"
target.mkdir(exist_ok=True)
config = target / "batch.json"
config.write_text(json.dumps({"inputs": [r"C:\Windows\System32\where.exe"],
                              "output": str(target), "agent": "none",
                              "summary": str(target / "summary.json")}), encoding="utf-8")
result = subprocess.run([str(root / "outputs" / "CastorPollux.exe"), "--batch", str(config)],
                        timeout=420, check=False)
summary = json.loads((target / "summary.json").read_text(encoding="utf-8"))
assert result.returncode == 0 and summary["status"] == "complete", summary
assert summary["application_version"] == "3.1.0"
folder = Path(summary["results"][0]["investigation"])
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
index = json.loads((folder / "scan-metrics.json").read_text(encoding="utf-8"))
detail = json.loads((folder / index["latest"]["file"]).read_text(encoding="utf-8"))
assert manifest["ghidra_status"] == manifest["rea_status"] == manifest["rea_decompile_status"] == "complete"
assert detail["status"] == "complete" and len(detail["stages"]) >= 5
assert detail["wall_seconds"] > 0
assert any(row.get("peak_working_set_bytes") for row in detail["processes"]), detail["processes"]
print(f"Packaged v3.1 verified: {len(detail['stages'])} stages, "
      f"{len(detail['processes'])} process samples, {detail['wall_seconds']}s")
