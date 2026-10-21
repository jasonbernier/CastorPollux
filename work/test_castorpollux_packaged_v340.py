"""Smoke-test the bundled 3.4 executable against a small Windows binary."""

import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
target = root / "work" / "castorpollux-v340-packaged-smoke"
target.mkdir(exist_ok=True)
config = target / "batch.json"
config.write_text(json.dumps({"inputs": [r"C:\Windows\System32\where.exe"],
                              "output": str(target), "agent": "none",
                              "summary": str(target / "summary.json")}), encoding="utf-8")
result = subprocess.run([str(root / "outputs" / "CastorPollux.exe"), "--batch", str(config)],
                        timeout=420, check=False)
summary = json.loads((target / "summary.json").read_text(encoding="utf-8"))
assert result.returncode == 0 and summary["status"] == "complete", summary
assert summary["application_version"] == "3.4.0"
folder = Path(summary["results"][0]["investigation"])
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
assert manifest["ghidra_status"] == manifest["rea_status"] == manifest["rea_decompile_status"] == "complete"
assert manifest["progress"]["percent"] == 100
assert manifest["rea_decompile_counts"]["succeeded"] > 0
assert (folder / "scan-metrics.json").is_file()
print(f"Packaged v3.4 verified: {manifest['rea_decompile_counts']['succeeded']} procedures and 100% scan progress")
