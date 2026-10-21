"""Run the self-extracting release on a signed Windows binary."""

import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
output = root / "work" / "castorpollux-v170-packaged-smoke"
output.mkdir(exist_ok=True)
config = output / "batch.json"
config.write_text(json.dumps({"inputs": [r"C:\Windows\System32\where.exe"],
                              "output": str(output), "agent": "none",
                              "summary": str(output / "summary.json")}), encoding="utf-8")
result = subprocess.run([str(root / "outputs" / "CastorPollux.exe"), "--batch", str(config)],
                        timeout=300, check=False)
summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
assert result.returncode == 0, summary
assert summary["status"] == "complete", summary
folder = Path(summary["results"][0]["investigation"])
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
assert manifest["rea_decompile_status"] == "complete", manifest
assert manifest["target_signature"]["status"] == "Valid", manifest["target_signature"]
assert (folder / "data-flow.json").is_file()
assert (folder / "rea-pseudocode.c").is_file()
print("Packaged EXE decompiled signed where.exe and saved flow/signature evidence")
