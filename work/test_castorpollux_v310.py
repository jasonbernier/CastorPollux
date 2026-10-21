"""Scan performance and resource dashboard data regression tests."""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from castorpollux_metrics import ScanMetrics, export_metrics_csv, load_metrics, trend


class DashboardMetricsTests(unittest.TestCase):
    def test_run_metrics_and_resume_history(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            manifest = {"input_bytes": 2048, "ghidra_status": "complete", "rea_status": "complete",
                        "rea_decompile_status": "complete", "rea_decompile_counts": {"succeeded": 3, "total": 4}}
            for run_id in ("first", "second"):
                metrics = ScanMetrics(folder, run_id)
                metrics.stage("Preparing engines", 2)
                metrics.stage("Ghidra export", 30)
                metrics.process(SimpleNamespace(pid=os.getpid()))
                time.sleep(0.08)
                metrics.process(None)
                data = metrics.finish("complete", manifest)
                self.assertGreaterEqual(data["wall_seconds"], 0)
                self.assertEqual(len(data["stages"]), 2)
                self.assertEqual(data["processes"][0]["stage"], "Ghidra export")
                if os.name == "nt":
                    self.assertGreater(data["processes"][0]["peak_working_set_bytes"], 0)
            index, latest = load_metrics(folder)
            self.assertEqual(len(index["runs"]), 2)
            self.assertEqual(latest["run_id"], "second")
            self.assertEqual(trend([folder])["count"], 1)
            csv_path = export_metrics_csv(folder, folder / "metrics.csv")
            self.assertIn("Ghidra export", csv_path.read_text(encoding="utf-8-sig"))

    def test_legacy_investigation_has_explicit_missing_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "manifest.json").write_text(json.dumps({
                "started_at": "2026-10-18T10:00:00+00:00",
                "finished_at": "2026-10-18T10:00:25+00:00",
                "rea_decompile_counts": {"succeeded": 2, "total": 2}}), encoding="utf-8")
            index, detail = load_metrics(folder)
            self.assertEqual(index["schema"], 0)
            self.assertEqual(detail["wall_seconds"], 25)
            self.assertEqual(detail["processes"], [])
            self.assertIn("predates", detail["sampling_note"])


if __name__ == "__main__":
    unittest.main()
