"""Packaged v3.2 smoke: scan metrics and standalone HTML dashboard export."""

import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
target = root / "work" / "castorpollux-v320-packaged-smoke"
target.mkdir(exist_ok=True)
config = target / "batch.json"
config.write_text(json.dumps({"inputs": [r"C:\Windows\System32\where.exe"],
                              "output": str(target), "agent": "none",
                              "summary": str(target / "summary.json")}), encoding="utf-8")
result = subprocess.run([str(root / "outputs" / "CastorPollux.exe"), "--batch", str(config)],
                        timeout=420, check=False)
summary = json.loads((target / "summary.json").read_text(encoding="utf-8"))
assert result.returncode == 0 and summary["status"] == "complete", summary
assert summary["application_version"] == "3.2.0"
folder = Path(summary["results"][0]["investigation"])
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
assert manifest["ghidra_status"] == manifest["rea_status"] == manifest["rea_decompile_status"] == "complete"
sys.path.insert(0, str(root / "work"))
from castorpollux_dashboard_export import export_dashboard_html
from castorpollux_workspace import InvestigationLibrary

items = InvestigationLibrary().details()
item = next(row for row in items if Path(row["path"]) == folder)
snapshot = export_dashboard_html(folder, item, items, target / "dashboard.html", "3.2.0")
html = snapshot.read_text(encoding="utf-8")
assert all(f'id="{section}"' in html for section in ("overview", "performance", "resources", "quality"))
assert "Peak working set" in html and "where.exe" in html
assert str(folder) not in html and manifest.get("input_path", "<none>") not in html
print(f"Packaged v3.2 verified: {manifest['rea_decompile_counts']['succeeded']} procedures; "
      f"HTML dashboard {snapshot.stat().st_size} bytes")
