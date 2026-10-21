"""Windows Explorer file-drop support using the shell's WM_DROPFILES message."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path


WM_DROPFILES = 0x0233
GWLP_WNDPROC = -4


def first_regular_file(paths) -> Path | None:
    for value in paths:
        candidate = Path(value).expanduser()
        if candidate.is_file():
            return candidate.resolve()
    return None


class WindowsFileDrop:
    """Accept file paths on Tk windows without a bundled drag/drop extension."""

    def __init__(self, root, widgets, on_files):
        if os.name != "nt":
            raise OSError("Windows file drop is available only on Windows")
        self.root = root
        self.on_files = on_files
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self.user32.GetParent.argtypes = [wintypes.HWND]
        self.user32.GetParent.restype = wintypes.HWND
        self.user32.IsWindow.argtypes = [wintypes.HWND]
        self.user32.IsWindow.restype = wintypes.BOOL
        self.user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        self.user32.SetWindowLongPtrW.restype = ctypes.c_void_p
        self.user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT,
                                                wintypes.WPARAM, wintypes.LPARAM]
        self.user32.CallWindowProcW.restype = ctypes.c_ssize_t
        self.shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
        self.shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
        self.shell32.DragQueryFileW.restype = wintypes.UINT
        self.shell32.DragFinish.argtypes = [wintypes.HANDLE]
        self.original: dict[int, int] = {}
        self.callbacks = {}
        root.update_idletasks()
        ids = {int(widget.winfo_id()) for widget in [root, *widgets] if widget.winfo_exists()}
        outer = self.user32.GetParent(root.winfo_id())
        if outer:
            ids.add(int(outer))
        for hwnd in ids:
            self._attach(hwnd)
        root.bind("<Destroy>", self._on_destroy, add="+")

    def _attach(self, hwnd: int):
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT,
                                           wintypes.WPARAM, wintypes.LPARAM)
        def dispatch(window, message, wparam, lparam):
            if message == WM_DROPFILES:
                try:
                    paths = self._paths(wparam)
                    if paths:
                        self.on_files(paths)
                except Exception as error:
                    try:
                        self.root.report_callback_exception(type(error), error, error.__traceback__)
                    except Exception:
                        pass
                return 0
            return self.user32.CallWindowProcW(self.original[hwnd], window, message, wparam, lparam)
        callback = callback_type(dispatch)
        ctypes.set_last_error(0)
        previous = self.user32.SetWindowLongPtrW(hwnd, GWLP_WNDPROC, ctypes.cast(callback, ctypes.c_void_p))
        if not previous and ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
        self.original[hwnd] = int(previous)
        self.callbacks[hwnd] = callback
        self.shell32.DragAcceptFiles(hwnd, True)

    def _paths(self, hdrop) -> list[str]:
        try:
            count = min(int(self.shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)), 256)
            paths = []
            for index in range(count):
                length = int(self.shell32.DragQueryFileW(hdrop, index, None, 0))
                if length <= 0 or length > 32767:
                    continue
                buffer = ctypes.create_unicode_buffer(length + 1)
                self.shell32.DragQueryFileW(hdrop, index, buffer, length + 1)
                paths.append(buffer.value)
            return paths
        finally:
            self.shell32.DragFinish(hdrop)

    def _on_destroy(self, event):
        if event.widget is self.root:
            self.close()

    def close(self):
        for hwnd, previous in list(self.original.items()):
            if self.user32.IsWindow(hwnd):
                self.shell32.DragAcceptFiles(hwnd, False)
                self.user32.SetWindowLongPtrW(hwnd, GWLP_WNDPROC, ctypes.c_void_p(previous))
            self.original.pop(hwnd, None)
            self.callbacks.pop(hwnd, None)
