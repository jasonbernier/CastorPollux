"""First-release usability and passive-state security checks."""

import ast
import json
import os
import subprocess
import sys
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from castorpollux_settings import (DEFAULT, THEMES, SHORTCUT_ACTIONS, load_workspace, save_workspace,
                               validate_settings, validate_shortcuts, shortcut_conflicts)
from castorpollux_ui_state import begin_session, end_session, load_palette, save_palette


class DesktopEnhancementTests(unittest.TestCase):
    def test_form_drafts_are_bounded_passive_and_private(self):
        from castorpollux_drafts import load_drafts, save_drafts, drafts_path
        with tempfile.TemporaryDirectory() as directory, patch("castorpollux_drafts.home", return_value=Path(directory)):
            saved = save_drafts({
                "analyze": {"input_path": r"C:\samples\target.exe", "review_agent": "codex",
                            "unknown_command": "run-now"},
                "review": {"scope_selection": "entrypoint", "redaction_terms": "private-token",
                           "report_formats": {"sarif": True, "unknown": True}},
                "batch": {"sources": [r"C:\samples\target.exe"]},
                "about": {"text": "Legacy unpublished About edit"},
            })
            self.assertEqual(load_drafts(), saved)
            raw = drafts_path().read_text(encoding="utf-8")
            self.assertNotIn("private-token", raw)
            self.assertNotIn("unknown_command", raw)
            self.assertNotIn("about", saved)
            self.assertNotIn("run-now", raw)
            self.assertEqual(saved["review"]["report_formats"], {"sarif": True})
            drafts_path().write_text("x" * 262145, encoding="utf-8")
            self.assertEqual(load_drafts(), {})

    def test_gui_restores_and_autosaves_form_drafts(self):
        if os.environ.get("CASTORPOLLUX_GUI_TEST_CHILD") != "1":
            environment = {**os.environ, "CASTORPOLLUX_GUI_TEST_CHILD": "1"}
            result = subprocess.run([sys.executable, "-X", "faulthandler", "-m", "unittest",
                                     "work.test_castorpollux_v100_ui.DesktopEnhancementTests."
                                     "test_gui_restores_and_autosaves_form_drafts", "-v"],
                                    cwd=ROOT.parent, env=environment, text=True,
                                    capture_output=True, timeout=120, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return
        from castorpollux import CastorPollux
        restored = {"analyze": {"input_path": r"C:\samples\target.exe", "output_path": r"C:\results"},
                    "review": {"scope_mode": "functions", "scope_selection": "entrypoint",
                               "report_formats": {"sarif": False}},
                    "batch": {"sources": [r"C:\samples\one.exe"], "batch_agent": "none"},
                    "settings": {"cache_days": "45"},
                    "about": {"text": "Legacy unpublished draft"}}
        saved = []
        with patch("castorpollux.begin_session", return_value=(None, False)), \
             patch("castorpollux.end_session"), patch("castorpollux.save_workspace"), \
             patch("castorpollux.load_workspace", return_value={"page": "analyze"}), \
             patch("castorpollux.load_settings", return_value=DEFAULT), \
             patch("castorpollux.load_drafts", return_value=restored), \
             patch("castorpollux.save_drafts", side_effect=lambda forms: saved.append(forms) or forms), \
             patch.object(CastorPollux, "_install_file_drop"):
            app = CastorPollux()
            try:
                self.assertEqual(app.input_path.get(), r"C:\samples\target.exe")
                self.assertEqual(app.scope_selection.get(), "entrypoint")
                self.assertFalse(app.report_formats["sarif"].get())
                self.assertEqual(app.batch_sources, [r"C:\samples\one.exe"])
                self.assertIn("Settings", app.dirty_pages)
                app.show_page("about")
                self.assertEqual(app.about_view.cget("state"), "disabled")
                self.assertNotIn("Legacy unpublished draft", app.about_view.get("1.0", "end-1c"))
                app.redaction_terms.set("do-not-persist")
                app._save_drafts_now()
                self.assertNotIn("about", saved[-1])
                self.assertNotIn("redaction_terms", saved[-1]["review"])
                app.show_page("history")
                self.assertNotIn("About", app.dirty_pages)
            finally:
                app.destroy()

    def test_first_party_code_avoids_dynamic_eval_and_shell_invocation(self):
        for path in ROOT.glob("*.py"):
            if path.name.startswith("test_"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, {"eval", "exec"}, path.name)
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                        self.assertIsNot(keyword.value.value, True, path.name)

    def test_bundled_credit_files_are_fixed_and_present(self):
        from castorpollux import CREDIT_LICENSE_FILES
        root = ROOT.parent / "outputs/CastorPollux-Licenses"
        for names in CREDIT_LICENSE_FILES.values():
            for name in names:
                self.assertEqual(Path(name).name, name)
                self.assertTrue((root / name).is_file(), name)

    def test_settings_reject_unsafe_or_unbounded_prefs(self):
        self.assertIn("High Contrast", THEMES)
        selected = validate_settings({**DEFAULT, "theme": "High Contrast", "font_scale": 130,
                                      "layout_presets": {"Analyst view": .42},
                                      "active_layout": "Analyst view"})
        self.assertEqual(selected["font_scale"], 130)
        self.assertEqual(selected["layout_presets"]["Analyst view"], .42)
        for override in ({"font_scale": 1000}, {"layout_presets": {"../escape": .5}},
                         {"layout_presets": {"Too narrow": .01}}):
            with self.assertRaises(ValueError):
                validate_settings({**DEFAULT, **override})

    def test_shortcut_conflicts_and_recovery_stages(self):
        from castorpollux_recovery import recovery_stages, recovery_log_preview
        valid = validate_shortcuts(SHORTCUT_ACTIONS)
        self.assertEqual(valid["Analyze"], "<Control-Return>")
        duplicate = {**valid, "History": "<Control-k>"}
        self.assertTrue(shortcut_conflicts(duplicate))
        with self.assertRaisesRegex(ValueError, "conflict"):
            validate_shortcuts(duplicate)
        with self.assertRaises(ValueError):
            validate_shortcuts({**valid, "History": "<KeyPress-any>"})
        rows = recovery_stages({"ghidra_status": "complete", "rea_status": "failed",
                                "rea_decompile_status": "blocked"})
        self.assertFalse(rows[0]["can_resume"])
        self.assertTrue(rows[1]["can_resume"])
        self.assertFalse(rows[2]["can_resume"])
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "rea.log").write_text("token=abcdef01234567890123456789012345\n" + "x" * 10000,
                                            encoding="utf-8")
            self.assertLessEqual(len(recovery_log_preview(folder, "rea")), 6000)
            with patch.object(Path, "is_symlink", return_value=True), self.assertRaises(ValueError):
                recovery_log_preview(folder, "rea")
            with self.assertRaises(ValueError):
                recovery_log_preview(folder, "../rea")

    def test_keyboard_button_callbacks_accept_missing_event(self):
        from castorpollux import CastorPollux
        handlers = {}
        button = SimpleNamespace(bind=lambda sequence, callback: handlers.setdefault(sequence, callback),
                                 invoke=lambda: handlers.setdefault("calls", []).append("invoked"))
        with patch("castorpollux.tk.Frame.configure"):
            CastorPollux._keyboard_button(button)
        handlers["<Return>"]()
        handlers["<space>"](object())
        self.assertEqual(handlers["calls"], ["invoked", "invoked"])

    def test_workspace_restores_only_known_passive_selections(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            investigation = base / "known"
            investigation.mkdir()
            binary = base / "sample.exe"
            binary.write_bytes(b"MZ")
            with patch("castorpollux_settings.home", return_value=base):
                save_workspace({"page": "reports", "current_folder": investigation,
                                "input_path": binary, "output_path": base,
                                "tabs": {"analyze": "Activity", "settings": "Invalid"}})
                restored = load_workspace({"analyze", "reports"}, {investigation.resolve()})
                self.assertEqual(restored["page"], "reports")
                self.assertEqual(restored["current_folder"], str(investigation.resolve()))
                self.assertEqual(restored["tabs"], {"analyze": "Activity"})
                (base / "workspace.json").write_text(json.dumps({"page": "__import__('os')",
                    "current_folder": str(base / "unknown"), "input_path": str(base / "missing.exe")}),
                    encoding="utf-8")
                self.assertEqual(load_workspace({"analyze", "reports"}, {investigation.resolve()}), {})

    def test_command_history_and_abandoned_session_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            allowed = {"page:analyze", "page:history"}
            with patch("castorpollux_ui_state.home", return_value=base):
                state = save_palette({"saved": ["page:history", "unknown"],
                                      "history": ["page:analyze", "page:analyze", "unknown"]}, allowed)
                self.assertEqual(state, {"saved": ["page:history"], "history": ["page:analyze"]})
                self.assertEqual(load_palette(allowed), state)
                self.assertEqual(save_palette({**state, "history": []}, allowed)["history"], [])
                sessions = base / "Sessions"
                sessions.mkdir()
                (sessions / "session-old.json").write_text('{"pid": 999999999}', encoding="utf-8")
                marker, interrupted = begin_session()
                self.assertTrue(interrupted)
                self.assertFalse((sessions / "session-old.json").exists())
                second, interrupted_again = begin_session()
                self.assertFalse(interrupted_again)
                end_session(marker)
                end_session(second)

    def test_gui_credits_panes_help_palette_and_scaling(self):
        if os.environ.get("CASTORPOLLUX_GUI_TEST_CHILD") != "1":
            environment = {**os.environ, "CASTORPOLLUX_GUI_TEST_CHILD": "1"}
            result = subprocess.run([sys.executable, "-X", "faulthandler", "-m", "unittest",
                                     "work.test_castorpollux_v100_ui.DesktopEnhancementTests."
                                     "test_gui_credits_panes_help_palette_and_scaling", "-v"],
                                    cwd=ROOT.parent, env=environment, text=True,
                                    capture_output=True, timeout=120, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return
        from castorpollux import CastorPollux
        workspace_patch = patch("castorpollux.save_workspace")
        workspace_patch.start()
        drop_patch = patch("castorpollux.CastorPollux._install_file_drop")
        drop_patch.start()
        with patch("castorpollux.begin_session", return_value=(None, True)), \
             patch("castorpollux.end_session"), \
             patch("castorpollux.load_workspace", return_value={"page": "reports", "tabs": {"analyze": "Activity"}}), \
             patch("castorpollux.load_settings", return_value={**DEFAULT, "restore_tabs": True}):
            app = CastorPollux()
        try:
            self.assertEqual(app.page_name, "analyze")
            self.assertEqual(app.analyze_tabs.get(), "Activity")
            app._restore_page_tab("dashboards", None)
            button = app.nav["history"]
            self.assertEqual(tk.Frame.cget(button, "takefocus"), "1")
            app._highlight_focus(SimpleNamespace(widget=button))
            self.assertEqual(int(tk.Frame.cget(button, "highlightthickness")), 3)
            with patch("castorpollux.load_palette", return_value={"history": [], "saved": []}), \
                 patch("castorpollux.save_palette", side_effect=lambda data, _allowed: data):
                app._command_palette()
                app.palette_query.set("interrupted")
                self.assertGreater(len(app.palette_results.winfo_children()), 0)
                app.palette_query.set("history")
                row = app.palette_results.winfo_children()[0]
                row.winfo_children()[1].invoke()
                self.assertIn("page:history", app.palette_state["saved"])
                app.palette_view_mode.set("Saved actions")
                app.palette_query.set("previous")
                self.assertEqual(len(app.palette_results.winfo_children()), 1)
                app.palette_results.winfo_children()[0].winfo_children()[0].invoke()
                self.assertEqual(app.page_name, "history")
                app._command_palette()
                app.palette_view_mode.set("Recent commands")
                app.palette_query.set("history")
                self.assertEqual(len(app.palette_results.winfo_children()), 1)
                with patch("castorpollux.messagebox.askyesno", return_value=True):
                    app.palette_clear_history.invoke()
                self.assertEqual(app.palette_state["history"], [])
                self.assertEqual(app.palette_state["saved"], ["page:history"])
                app.palette_window.grab_release()
                app.palette_window.destroy()
            app.show_page("settings")
            self.assertTrue(app.settings_tabs.tab("Shortcuts").winfo_exists())
            app.shortcut_vars["History"].set("<Control-k>")
            self.assertIn("Settings", app.dirty_pages)
            self.assertFalse(app._check_shortcuts())
            app.shortcut_vars["History"].set("<Control-h>")
            self.assertTrue(app._check_shortcuts())
            self.assertNotIn("Settings", app.dirty_pages)
            app.settings_tabs.set("Symbols")
            app.show_page("analyze")
            app.show_page("settings")
            self.assertEqual(app.settings_tabs.get(), "Symbols")
            app.show_page("credits")
            app.credits_search.set("MIT")
            app._render_credits()
            self.assertIn("OF 19 SOURCES", app.credits_count.cget("text"))
            app.credits_search.set("no matching license or project")
            app._render_credits()
            app.update_idletasks()
            self.assertIn("0 OF 19", app.credits_count.cget("text"))
            app.credits_search.set("MIT")
            app._render_credits()
            with patch("castorpollux.resource", return_value=ROOT.parent / "outputs/CastorPollux-Licenses"):
                app._open_license_details("REA", "MIT", "https://github.com/morluto/rea")
            for child in app.winfo_children():
                if child.winfo_class() == "Toplevel":
                    child.destroy()
            app._context_help()
            self.assertEqual(app.page_name, "help")
            self.assertEqual(app.help_topic.get(), "Components and settings")
            app.show_page("investigations")
            self.assertTrue(app.rows_panel.winfo_exists())
            self.assertTrue(app.detail_box.winfo_exists())
            app.show_page("reports")
            self.assertTrue(app.report_evidence.winfo_exists())
            app._command_palette()
            self.assertTrue(app.palette_window.winfo_exists())
            app.palette_window.destroy()
            app.last_split_ratio = .44
            with patch("castorpollux.simpledialog.askstring", return_value="Analyst view"), \
                 patch("castorpollux.save_settings", side_effect=validate_settings):
                app._save_current_layout()
            self.assertEqual(app.settings["layout_presets"]["Analyst view"], .44)
            app.show_page("settings")
            app.theme_choice.set("High Contrast")
            app.font_scale_choice.set("130")
            with patch("castorpollux.save_settings", side_effect=validate_settings):
                app._save_settings()
            self.assertEqual(app.settings["theme"], "High Contrast")
            self.assertNotIn("Settings", app.dirty_pages)
            self.assertEqual(app._font(10).cget("size"), 13)
            app._recovery_prompt()
            self.assertTrue(app.recovery_window.winfo_exists())
            app.recovery_window.grab_release()
            app.recovery_window.destroy()
        finally:
            app.destroy()
            drop_patch.stop()
            workspace_patch.stop()


if __name__ == "__main__":
    unittest.main()
