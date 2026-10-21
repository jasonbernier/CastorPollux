"""Small, testable helpers for activity, scan timing, and desktop notices."""

from __future__ import annotations

import ctypes
import json
import os
import statistics
from ctypes import wintypes
from pathlib import Path


STAGE_RANGES = {
    "Preparing engines": (2, 8),
    "Verifying binary": (8, 14),
    "Checking symbols": (14, 20),
    "Running Ghidra": (20, 48),
    "Collecting REA evidence": (48, 64),
    "Decompiling with REA": (64, 95),
    "Scanning security evidence": (95, 100),
}


def activity_kind(text: str) -> str:
    value = text.casefold()
    if "error" in value or "failed" in value or "stopped" in value:
        return "Errors"
    if "warning" in value or "mismatch" in value or "skipped" in value:
        return "Warnings"
    if value.startswith("castorpollux_stage ") or "complete" in value:
        return "Stages"
    return "Other"


def filter_activity(records: list[dict], query: str, category: str) -> list[dict]:
    needle = query.casefold().strip()
    return [row for row in records if
            (category == "All" or (category == "Bookmarked" and row.get("bookmarked")) or
             (category not in {"All", "Bookmarked"} and row.get("kind") == category)) and
            (not needle or needle in row.get("text", "").casefold())]


def stage_estimate(label: str, overall_percent: int, stage_elapsed: float,
                   historical_seconds: float | None) -> tuple[str, str]:
    """Return an honest stage progress description and approximate time remaining."""
    start, end = STAGE_RANGES.get(label, (overall_percent, overall_percent))
    if end > start and overall_percent > start:
        fraction = min(1.0, (overall_percent - start) / (end - start))
        if fraction >= 0.08 and stage_elapsed >= 3:
            remaining = max(0, stage_elapsed * (1 - fraction) / fraction)
            return f"Stage {round(fraction * 100)}%", f"~{format_duration(remaining)}"
    if historical_seconds and historical_seconds > 0:
        return "Stage running", f"~{format_duration(max(0, historical_seconds - stage_elapsed))} (past scans)"
    return "Stage running", "unavailable until a completed scan"


def format_duration(seconds: float) -> str:
    value = max(0, round(seconds))
    minutes, remainder = divmod(value, 60)
    return f"{minutes}m {remainder:02d}s" if minutes else f"{remainder}s"


def historical_stage_seconds(folders: list[Path], limit: int = 20) -> dict[str, float]:
    values: dict[str, list[float]] = {}
    for folder in folders[:limit]:
        index = Path(folder) / "scan-metrics.json"
        try:
            latest = json.loads(index.read_text(encoding="utf-8")).get("latest", {})
            path = Path(folder) / latest.get("file", "")
            if not path.is_file() or not path.resolve().is_relative_to(Path(folder).resolve()):
                continue
            detail = json.loads(path.read_text(encoding="utf-8"))
            for stage in detail.get("stages", []):
                name, seconds = stage.get("name"), stage.get("wall_seconds")
                if isinstance(name, str) and isinstance(seconds, (int, float)) and seconds > 0:
                    values.setdefault(name, []).append(float(seconds))
        except (OSError, ValueError, TypeError):
            continue
    return {name: statistics.median(samples) for name, samples in values.items()}


def notify_windows(root, title: str, message: str) -> bool:
    """Show a Windows shell notification; return False if the shell declines it."""
    if os.name != "nt":
        return False
    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_byte * 8)]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                    ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT),
                    ("hIcon", wintypes.HICON), ("szTip", wintypes.WCHAR * 128),
                    ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                    ("szInfo", wintypes.WCHAR * 256), ("uTimeoutOrVersion", wintypes.UINT),
                    ("szInfoTitle", wintypes.WCHAR * 64), ("dwInfoFlags", wintypes.DWORD),
                    ("guidItem", GUID), ("hBalloonIcon", wintypes.HICON)]

    shell = ctypes.WinDLL("shell32", use_last_error=True)
    user = ctypes.WinDLL("user32", use_last_error=True)
    shell.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
    shell.Shell_NotifyIconW.restype = wintypes.BOOL
    user.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
    user.LoadIconW.restype = wintypes.HICON
    item = NOTIFYICONDATAW()
    item.cbSize = ctypes.sizeof(item)
    item.hWnd = root.winfo_id()
    item.uID = 0x4856
    item.uFlags = 0x2 | 0x4  # NIF_ICON | NIF_TIP
    item.hIcon = user.LoadIconW(None, ctypes.c_void_p(32516))  # IDI_INFORMATION
    item.szTip = "CastorPollux"
    added = bool(shell.Shell_NotifyIconW(0, ctypes.byref(item)))
    if not added:
        return False
    item.uFlags = 0x10  # NIF_INFO
    item.szInfo = message[:255]
    item.szInfoTitle = title[:63]
    item.dwInfoFlags = 0x1  # NIIF_INFO
    shown = bool(shell.Shell_NotifyIconW(1, ctypes.byref(item)))
    root.after(30000, lambda: shell.Shell_NotifyIconW(2, ctypes.byref(item)))
    return shown
