"""End-to-end smoke test for the self-extracting v2.8 release."""

import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
target = root / "work" / "castorpollux-v280-packaged-smoke"
target.mkdir(exist_ok=True)
config = target / "batch.json"
config.write_text(json.dumps({"inputs": [r"C:\Windows\System32\where.exe"],
                              "output": str(target), "agent": "none",
                              "summary": str(target / "summary.json")}), encoding="utf-8")
result = subprocess.run([str(root / "outputs" / "CastorPollux.exe"), "--batch", str(config)],
                        timeout=360, check=False)
summary = json.loads((target / "summary.json").read_text(encoding="utf-8"))
assert result.returncode == 0 and summary["status"] == "complete", summary
folder = Path(summary["results"][0]["investigation"])
manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
graph = json.loads((folder / "advanced-graph.json").read_text(encoding="utf-8"))
edges = json.loads((folder / "call-edge-checks.json").read_text(encoding="utf-8"))
assert manifest["ghidra_status"] == "complete" and manifest["rea_decompile_status"] == "complete"
assert manifest["rea_decompile_counts"]["failed"] == 0
assert graph["ssa_ops"] > 1000 and graph["def_use_edges"] > 1000
assert isinstance(graph["ssa_source_sink_count"], int)
assert manifest["ssa_source_sink_leads"] == graph["ssa_source_sink_count"]
assert edges["independently_verified"] > 0
assert (folder / "overflow-leads.json").is_file()
print(f"Packaged v2.8 verified: {graph['ssa_ops']} SSA ops; {edges['independently_verified']} independently checked PE edges")
