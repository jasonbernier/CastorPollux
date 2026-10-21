"""Standalone HTML dashboard export regression tests."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from castorpollux_dashboard_export import export_dashboard_html
from castorpollux_metrics import ScanMetrics


class DashboardHtmlTests(unittest.TestCase):
    def _item(self, folder):
        return {"path": str(folder), "name": folder.name, "coverage": {"succeeded": 3, "total": 4},
                "ghidra": "complete", "rea": "complete", "decompile": "complete",
                "finding_count": 2}

    def test_self_contained_snapshot_escapes_names_and_omits_private_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "investigation"
            folder.mkdir()
            (folder / "manifest.json").write_text(json.dumps({
                "input_name": r"C:\private\<img onerror=alert(1)>.exe", "input_path": r"C:\private\secret.exe",
                "sha256": "PRIVATE_HASH", "versions": {"ghidra": "12.0.3"},
                "warnings": ["C:\\private\\do-not-share"]}), encoding="utf-8")
            metrics = ScanMetrics(folder, "test")
            metrics.stage("Ghidra <script>alert(1)</script>", 30)
            metrics.stage("REA", 70)
            metrics.finish("complete", {"rea_decompile_counts": {"succeeded": 3, "total": 4}})
            item = self._item(folder)
            target = Path(directory) / "snapshot.html"
            self.assertEqual(export_dashboard_html(folder, item, [item], target, "3.2.0"), target)
            source = target.read_text(encoding="utf-8")
            self.assertIn("<!doctype html>", source)
            self.assertIn("<svg", source)
            self.assertIn("Ghidra &lt;script&gt;alert(1)&lt;/script&gt;", source)
            self.assertIn("&lt;img onerror=alert(1)&gt;.exe", source)
            self.assertNotIn("<script>", source)
            self.assertNotIn("<img onerror", source)
            self.assertNotIn("C:\\private", source)
            self.assertNotIn("PRIVATE_HASH", source)
            self.assertNotIn("<link ", source)
            self.assertNotIn("<iframe", source)

    def test_legacy_snapshot_states_unavailable_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "older"
            folder.mkdir()
            (folder / "manifest.json").write_text(json.dumps({
                "input_name": "older.exe", "started_at": "2026-10-18T10:00:00+00:00",
                "finished_at": "2026-10-18T10:00:20+00:00"}), encoding="utf-8")
            target = Path(directory) / "legacy.html"
            item = self._item(folder)
            export_dashboard_html(folder, item, [item], target, "3.2.0")
            source = target.read_text(encoding="utf-8")
            self.assertIn("20.0 s", source)
            self.assertIn("No process samples were captured", source)


if __name__ == "__main__":
    unittest.main()
