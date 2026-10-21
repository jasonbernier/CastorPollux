"""Packaged v2.9 smoke: analysis completion and post-scan usage snapshot."""

import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
target = root / "work" / "castorpollux-v290-packaged-smoke"
target.mkdir(exist_ok=True)
config = target / "batch.json"
config.write_text(json.dumps({"inputs": [r"C:\Windows\System32\where.exe"],
                              "output": str(target), "agent": "none",
                              "summary": str(target / "summary.json")}), encoding="utf-8")
result = subprocess.run([str(root / "outputs" / "CastorPollux.exe"), "--batch", str(config)],
                        timeout=360, check=False)
summary = json.loads((target / "summary.json").read_text(encoding="utf-8"))
assert result.returncode == 0 and summary["status"] == "complete", summary
assert summary["application_version"] == "2.9.0"
row = summary["results"][0]
folder = Path(row["investigation"])
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
usage = json.loads((folder / "agent-usage.json").read_text(encoding="utf-8"))
assert manifest["ghidra_status"] == manifest["rea_status"] == manifest["rea_decompile_status"] == "complete"
assert row["agent_usage"] == usage and usage["status"] in {"available", "unavailable"}
assert (folder / "rea-pseudocode.c").is_file()
print(f"Packaged v2.9 verified: REA {manifest['rea_decompile_counts']['succeeded']} procedures; "
      f"Codex usage {usage['status']}")
