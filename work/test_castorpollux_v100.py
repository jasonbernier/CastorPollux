"""First-release identity and information-page regression checks."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from castorpollux_core import APP_VERSION


class FirstReleaseTests(unittest.TestCase):
    def test_release_identity_and_docs(self):
        self.assertEqual(APP_VERSION, "1.0.0")
        about = (ROOT / "content/about.html").read_text(encoding="utf-8")
        help_text = (ROOT / "content/help.html").read_text(encoding="utf-8")
        self.assertIn("<h2>How an investigation works</h2>", about)
        self.assertIn("https://github.com/jasonbernier/CastorPollux", about)
        self.assertNotIn("EDIT HTML", about)
        self.assertIn('data-title="Components and settings"', help_text)
        for text in (about, help_text):
            self.assertNotIn("Version 3.", text)
            self.assertNotIn("Version 2.", text)
            self.assertNotIn("New in 2.", text)
            self.assertNotIn("HexVigil", text)

    def test_information_pages_render(self):
        from castorpollux import CastorPollux

        workspace_patch = patch("castorpollux.save_workspace")
        workspace_patch.start()
        with patch("castorpollux.load_workspace", return_value={}):
            app = CastorPollux()
        try:
            self.assertNotIn("v1.0.0", app.title())
            app.show_page("about")
            app.update_idletasks()
            self.assertIn("CastorPollux", app.about_view.get("1.0", "end-1c"))
            self.assertIn("https://github.com/jasonbernier/CastorPollux",
                          app.about_view.get("1.0", "end-1c"))
            self.assertNotIn("<h1>", app.about_view.get("1.0", "end-1c"))
            self.assertEqual(app.about_view.cget("state"), "disabled")
            self.assertFalse(hasattr(app, "about_edit_button"))
            link_index = app.about_view._textbox.search("https://github.com/jasonbernier/CastorPollux", "1.0")
            self.assertTrue(link_index)
            self.assertTrue(any(tag.startswith("link_") for tag in app.about_view._textbox.tag_names(link_index)))
            app.show_page("help")
            self.assertIn("Components and settings", app.help_sections)
            self.assertNotIn("<h2>", app.help_box.get("1.0", "end-1c"))
            app.show_page("credits")
            app.update_idletasks()
            self.assertEqual(app.page_name, "credits")
        finally:
            app.destroy()
            workspace_patch.stop()

    def test_action_console_components_and_progress_reset(self):
        from castorpollux import CastorPollux
        with patch("castorpollux.save_workspace"), patch("castorpollux.load_workspace", return_value={}), \
             patch.object(CastorPollux, "_install_file_drop"):
            app = CastorPollux()
        try:
            app.show_page("queries")
            self.assertEqual(len(app.query_buttons), 8)
            app.busy = True
            app._refresh_controls()
            self.assertTrue(all(button.cget("state") == "disabled" for button in app.query_buttons))
            app.busy = False
            app._refresh_controls()
            self.assertTrue(all(button.cget("state") == "normal" for button in app.query_buttons))
            app.show_page("console")
            self.assertTrue(app.console_box.winfo_exists())
            app.show_page("updates")
            self.assertEqual(len(app.update_rows), 4)
            app.show_page("plugins")
            app._view_plugin_sample()
            self.assertIn('"enabled": false', app.plugin_box.get("1.0", "end-1c"))
            app.progress_bar.set(1)
            app.progress_text.set("100%")
            app.active_task_kind = "task"
            app.task_error = False
            app.task_started = 0
            app.events.put(("done", None))
            app._drain()
            self.assertEqual(app.progress_bar.get(), 0)
            self.assertEqual(app.progress_text.get(), "READY")
        finally:
            app.destroy()


if __name__ == "__main__":
    unittest.main()
