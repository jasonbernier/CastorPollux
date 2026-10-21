"""GUI file selection, copyable logs, progress, and defensive-agent regressions."""

import ctypes
import os
import struct
import sys
import tempfile
import tkinter as tk
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from castorpollux_core import symbol_lookup_failure_class
from castorpollux_drop import WM_DROPFILES, WindowsFileDrop, first_regular_file
from castorpollux_recovery import RECOVERY_PROMPT, engine_failures
from castorpollux_workspace import agent_failure_summary, build_review_prompt


class DesktopWorkflowTests(unittest.TestCase):
    def test_file_selection_and_defensive_prompts(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.exe"
            source.write_bytes(b"MZ" + bytes(100))
            self.assertEqual(first_regular_file([directory, source]), source.resolve())
            self.assertIsNone(first_regular_file([directory]))
        prompt = build_review_prompt({"description": "selected procedures"}, plugins=[])
        self.assertTrue(prompt.startswith("This review is for a defensive outcome:"))
        self.assertIn("strictly for a defensive outcome", prompt)
        self.assertIn("for a defensive outcome", RECOVERY_PROMPT)
        self.assertEqual(symbol_lookup_failure_class(ValueError("GUID matches, but age differs")),
                         "identity_mismatch")
        self.assertEqual(engine_failures({"ghidra_status": "complete", "rea_status": "complete",
                                          "rea_decompile_status": "complete",
                                          "warnings": ["Optional online symbol lookup failed: timeout"]}), [])

    def test_provider_refusal_is_short_and_preserves_log_reference(self):
        raw = "FUNCTION BODY\nERROR: This content was flagged for possible cybersecurity risk."
        summary = agent_failure_summary("codex", 1, raw)
        self.assertIn("declined the defensive review", summary)
        self.assertIn("codex-review.log", summary)
        self.assertNotIn("FUNCTION BODY", summary)

    @unittest.skipUnless(os.name == "nt", "Windows shell drop test")
    def test_a_windows_drop_message_reaches_tk(self):
        root = tk.Tk()
        root.geometry("320x100")
        root.update()
        received = []
        handler = WindowsFileDrop(root, [], lambda paths: received.extend(paths))
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        user = ctypes.WinDLL("user32", use_last_error=True)
        kernel.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
        kernel.GlobalAlloc.restype = ctypes.c_void_p
        kernel.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel.GlobalLock.restype = ctypes.c_void_p
        kernel.GlobalUnlock.argtypes = [ctypes.c_void_p]
        user.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
        user.SendMessageW.restype = ctypes.c_ssize_t
        value = r"C:\Windows\System32\where.exe"
        blob = struct.pack("<IiiII", 20, 0, 0, 0, 1) + (value + "\0\0").encode("utf-16-le")
        handle = kernel.GlobalAlloc(0x42, len(blob))
        self.assertTrue(handle)
        pointer = kernel.GlobalLock(handle)
        ctypes.memmove(pointer, blob, len(blob))
        kernel.GlobalUnlock(handle)
        try:
            user.SendMessageW(root.winfo_id(), WM_DROPFILES, handle, 0)
            root.update()
            self.assertEqual(received, [value])
        finally:
            handler.close()
            root.destroy()

    def test_gui_scan_banner_and_log_copy(self):
        from castorpollux import CastorPollux
        workspace_patch = patch("castorpollux.save_workspace")
        workspace_patch.start()
        with patch("castorpollux.load_workspace", return_value={}):
            app = CastorPollux()
        try:
            app._install_file_drop()
            self.assertIsNotNone(app.file_drop)
            self.assertTrue(hasattr(app.log_box, "_castorpollux_context_menu"))
            app._log("COPY ME")
            app.log_box._castorpollux_context_menu.invoke(1)
            self.assertIn("COPY ME", app.clipboard_get())
            app._set_scan_progress(64, "Decompiling with REA")
            self.assertEqual(app.scan_percent_text.get(), "64%")
            self.assertEqual(app.scan_state_text.get(), "SCAN RUNNING")
            app._set_scan_progress(100, "Analysis complete")
            self.assertEqual(app.scan_state_text.get(), "SCAN COMPLETE")
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "dropped.exe"
                source.write_bytes(b"MZ")
                app._receive_dropped_files([str(source)])
                self.assertEqual(Path(app.input_path.get()), source.resolve())
        finally:
            app.destroy()
            workspace_patch.stop()


if __name__ == "__main__":
    unittest.main()
