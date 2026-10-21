"""Bounded, passive desktop session and command-palette state."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

from castorpollux_core import home


def _atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return ctypes.get_last_error() == 5  # Access denied implies a live protected process.
        try:
            exit_code = wintypes.DWORD()
            return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code))) and exit_code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def begin_session() -> tuple[Path, bool]:
    """Mark this UI session active and report abandoned prior UI sessions."""
    directory = home() / "Sessions"
    directory.mkdir(parents=True, exist_ok=True)
    interrupted = False
    for marker in list(directory.glob("session-*.json"))[:128]:
        try:
            if marker.stat().st_size > 4096:
                raise ValueError("Oversized session marker")
            data = json.loads(marker.read_text(encoding="utf-8"))
            pid = data.get("pid") if isinstance(data, dict) else None
            alive = isinstance(pid, int) and _pid_alive(pid)
        except (OSError, ValueError):
            alive = False
        if not alive:
            interrupted = True
            try:
                marker.unlink(missing_ok=True)
            except OSError:
                pass
    marker = directory / f"session-{uuid.uuid4().hex}.json"
    _atomic_json(marker, {"pid": os.getpid()})
    return marker, interrupted


def end_session(marker: Path | None) -> None:
    if marker is not None:
        marker.unlink(missing_ok=True)


def palette_path() -> Path:
    return home() / "command-palette.json"


def load_palette(allowed: set[str]) -> dict[str, list[str]]:
    try:
        path = palette_path()
        if path.stat().st_size > 8192:
            raise ValueError("Palette file too large")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    result = {}
    for key in ("history", "saved"):
        raw = data.get(key, [])
        result[key] = list(dict.fromkeys(value for value in raw[:50]
                                        if isinstance(value, str) and value in allowed)) if isinstance(raw, list) else []
    return result


def save_palette(data: dict, allowed: set[str]) -> dict[str, list[str]]:
    clean = {}
    for key in ("history", "saved"):
        raw = data.get(key, [])
        clean[key] = list(dict.fromkeys(value for value in raw[:50]
                                        if isinstance(value, str) and value in allowed)) if isinstance(raw, list) else []
    _atomic_json(palette_path(), clean)
    return clean
