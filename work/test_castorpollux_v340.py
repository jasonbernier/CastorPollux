"""GUI usability and scan-status regressions for CastorPollux 3.4."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from castorpollux_settings import DEFAULT, THEMES, validate_settings
from castorpollux_ui_support import activity_kind, filter_activity, stage_estimate


class UsabilityTests(unittest.TestCase):
    def test_filter_eta_and_settings(self):
        self.assertIn("Daylight", THEMES)
        valid = validate_settings({**DEFAULT, "theme": "Daylight", "desktop_notifications": True,
                                   "notification_min_seconds": 90})
        self.assertTrue(valid["desktop_notifications"])
        self.assertEqual(valid["notification_min_seconds"], 90)
        records = [{"text": "ERROR: Ghidra failed", "kind": activity_kind("ERROR: Ghidra failed"), "bookmarked": True},
                   {"text": "REA complete", "kind": activity_kind("REA complete"), "bookmarked": False}]
        self.assertEqual(len(filter_activity(records, "ghidra", "Bookmarked")), 1)
        self.assertEqual(len(filter_activity(records, "", "Stages")), 1)
        progress, eta = stage_estimate("Decompiling with REA", 79, 30, None)
        self.assertIn("48%", progress)
        self.assertTrue(eta.startswith("~"))
        self.assertIn("past scans", stage_estimate("Running Ghidra", 20, 10, 60)[1])

    def test_gui_tabs_queue_bookmarks_and_day_mode(self):
        from castorpollux import CastorPollux
        workspace_patch = patch("castorpollux.save_workspace")
        workspace_patch.start()
        with patch("castorpollux.load_workspace", return_value={}):
            app = CastorPollux()
        with tempfile.TemporaryDirectory() as directory:
            try:
                app.bookmark_path = Path(directory) / "bookmarks.json"
                self.assertEqual(app.nav_group["analyze"], "Start")
                self.assertEqual(app.analyze_tabs.get(), "Target")
                app._focus_activity_search()
                self.assertEqual(app.analyze_tabs.get(), "Activity")
                app._log("ERROR: bookmark this line")
                app.log_box._textbox.mark_set("insert", "end-2l")
                app._bookmark_selected_log()
                saved = json.loads(app.bookmark_path.read_text(encoding="utf-8"))
                self.assertTrue(any("bookmark this line" in item["text"] for item in saved))
                app.activity_search.set("bookmark this line")
                app.activity_filter.set("Bookmarked")
                app._render_activity()
                self.assertEqual(len(app.log_visible_records), 1)
                first = Path(directory) / "one.exe"
                second = Path(directory) / "two.exe"
                first.write_bytes(b"MZ")
                second.write_bytes(b"MZ")
                app._receive_dropped_files([str(first), str(second), str(first)])
                self.assertEqual(app.page_name, "batch")
                self.assertEqual(len(app.batch_sources), 2)
                app.show_page("settings")
                self.assertEqual(app.nav_tabs.get(), "System")
                with patch("castorpollux.save_settings", side_effect=lambda data: data):
                    app._toggle_day_mode()
                self.assertEqual(app.settings["theme"], "Daylight")
                app.show_page("history")
                self.assertEqual(app.nav_tabs.get(), "Start")
            finally:
                app.destroy()
                workspace_patch.stop()


if __name__ == "__main__":
    unittest.main()
