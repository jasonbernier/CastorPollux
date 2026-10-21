"""Bounded scan timing and sampled Windows process-tree resource metrics."""

from __future__ import annotations

import csv
import json
import os
import statistics
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _windows_process_tree(root_pid: int) -> tuple[int, int, dict[int, float]] | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX), wintypes.DWORD]
    filetime = wintypes.FILETIME
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(filetime)] * 4

    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if not snapshot or snapshot == wintypes.HANDLE(-1).value:
        return None
    parent = {}
    try:
        row = PROCESSENTRY32W()
        row.dwSize = ctypes.sizeof(row)
        if kernel.Process32FirstW(snapshot, ctypes.byref(row)):
            while True:
                parent[int(row.th32ProcessID)] = int(row.th32ParentProcessID)
                if not kernel.Process32NextW(snapshot, ctypes.byref(row)):
                    break
    finally:
        kernel.CloseHandle(snapshot)
    pids = {int(root_pid)}
    for _ in range(32):
        more = {pid for pid, ppid in parent.items() if ppid in pids}
        if more <= pids:
            break
        pids.update(more)
    rss = private = 0
    cpu_by_pid = {}
    for pid in pids:
        handle = kernel.OpenProcess(0x1000 | 0x10, False, pid)
        if not handle:
            continue
        try:
            memory = PROCESS_MEMORY_COUNTERS_EX()
            memory.cb = ctypes.sizeof(memory)
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
                rss += int(memory.WorkingSetSize)
                private += int(memory.PrivateUsage)
            created, exited, kernel_time, user_time = (filetime() for _ in range(4))
            if kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                      ctypes.byref(kernel_time), ctypes.byref(user_time)):
                ticks = ((int(kernel_time.dwHighDateTime) << 32) + int(kernel_time.dwLowDateTime) +
                         (int(user_time.dwHighDateTime) << 32) + int(user_time.dwLowDateTime))
                cpu_by_pid[pid] = ticks / 10_000_000
        finally:
            kernel.CloseHandle(handle)
    return rss, private, cpu_by_pid


class ProcessSampler:
    def __init__(self, pid: int, stage: str, interval: float = 2.0):
        self.pid, self.stage, self.interval = int(pid), stage, interval
        self.started = time.monotonic()
        self.started_at = _utc()
        self.stop_event = threading.Event()
        self.samples: list[dict] = []
        self.cpu_by_pid: dict[int, float] = {}
        self.cpu_baseline: dict[int, float] = {}
        self.peak_rss = self.peak_private = 0
        self.status = "sampling" if os.name == "nt" else "unavailable"
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                sampled = _windows_process_tree(self.pid)
                if sampled is not None:
                    rss, private, cpu = sampled
                    self.peak_rss = max(self.peak_rss, rss)
                    self.peak_private = max(self.peak_private, private)
                    for pid, seconds in cpu.items():
                        self.cpu_baseline.setdefault(pid, seconds)
                        self.cpu_by_pid[pid] = max(self.cpu_by_pid.get(pid, 0.0),
                                                   seconds - self.cpu_baseline[pid])
                    if len(self.samples) < 2000:
                        self.samples.append({"elapsed_seconds": round(time.monotonic() - self.started, 2),
                                             "working_set_bytes": rss, "private_bytes": private})
            except Exception:
                self.status = "unavailable"
            self.stop_event.wait(self.interval)

    def finish(self) -> dict:
        self.stop_event.set()
        self.thread.join(timeout=3)
        return {"stage": self.stage, "pid": self.pid, "started_at": self.started_at,
                "wall_seconds": round(time.monotonic() - self.started, 3),
                "peak_working_set_bytes": self.peak_rss if self.peak_rss else None,
                "peak_private_bytes": self.peak_private if self.peak_private else None,
                "sampled_cpu_seconds": round(sum(self.cpu_by_pid.values()), 3) if self.peak_rss else None,
                "sample_count": len(self.samples), "samples": self.samples,
                "status": "sampled" if self.peak_rss else "unavailable",
                "note": "Sampled process-tree values; short-lived peaks and exited children may be missed."}


class ScanMetrics:
    def __init__(self, folder: Path, run_id: str):
        self.folder = Path(folder)
        self.run_id = run_id
        self.started = time.monotonic()
        self.started_at = _utc()
        self.active_stage: dict | None = None
        self.stages: list[dict] = []
        self.processes: list[dict] = []
        self.sampler: ProcessSampler | None = None

    def stage(self, name: str, percent: int):
        if self.active_stage and self.active_stage["name"] == name:
            self.active_stage["last_percent"] = percent
            return
        self._close_stage()
        self.active_stage = {"name": name, "started_at": _utc(), "started_monotonic": time.monotonic(),
                             "first_percent": percent, "last_percent": percent}

    def _close_stage(self):
        if self.active_stage:
            item = self.active_stage
            self.stages.append({"name": item["name"], "started_at": item["started_at"],
                                "first_percent": item["first_percent"], "last_percent": item["last_percent"],
                                "wall_seconds": round(time.monotonic() - item["started_monotonic"], 3)})
            self.active_stage = None

    def process(self, process):
        if self.sampler:
            self.processes.append(self.sampler.finish())
            self.sampler = None
        if process is not None and isinstance(getattr(process, "pid", None), int):
            self.sampler = ProcessSampler(process.pid, self.active_stage["name"] if self.active_stage else "Other")

    def finish(self, status: str, manifest: dict) -> dict:
        self.process(None)
        self._close_stage()
        data = {"schema": 1, "run_id": self.run_id, "started_at": self.started_at,
                "finished_at": _utc(), "wall_seconds": round(time.monotonic() - self.started, 3),
                "status": status, "binary_bytes": manifest.get("input_bytes"),
                "ghidra_status": manifest.get("ghidra_status"),
                "rea_status": manifest.get("rea_status"),
                "rea_decompile_status": manifest.get("rea_decompile_status"),
                "rea_decompile_counts": manifest.get("rea_decompile_counts", {}),
                "stages": self.stages, "processes": self.processes,
                "sampling_note": "Observed working set, private bytes, and CPU for the launched process tree on Windows. "
                                 "These are sampled estimates, not hard resource ceilings."}
        directory = self.folder / "ScanMetrics"
        directory.mkdir(exist_ok=True)
        path = directory / ("scan-" + self.run_id + ".json")
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        index = self.folder / "scan-metrics.json"
        try:
            previous = json.loads(index.read_text(encoding="utf-8"))
            runs = previous.get("runs", []) if isinstance(previous, dict) else []
        except (OSError, ValueError):
            runs = []
        summary = {key: data[key] for key in ("run_id", "started_at", "finished_at", "wall_seconds", "status",
                                              "binary_bytes", "ghidra_status", "rea_status", "rea_decompile_status",
                                              "rea_decompile_counts")}
        summary["file"] = str(path.relative_to(self.folder)).replace("\\", "/")
        runs = [item for item in runs if item.get("run_id") != self.run_id] + [summary]
        index.write_text(json.dumps({"schema": 1, "latest": summary, "runs": runs[-100:]}, indent=2), encoding="utf-8")
        return data


def load_metrics(folder: Path) -> tuple[dict, dict]:
    folder = Path(folder)
    index_path = folder / "scan-metrics.json"
    if index_path.is_file():
        index = json.loads(index_path.read_text(encoding="utf-8"))
        latest = index.get("latest", {})
        detail = folder / latest.get("file", "")
        if detail.is_file() and detail.resolve().is_relative_to(folder.resolve()):
            return index, json.loads(detail.read_text(encoding="utf-8"))
        return index, latest
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    start, end = manifest.get("started_at"), manifest.get("finished_at")
    try:
        seconds = max(0.0, (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except (ValueError, TypeError):
        seconds = None
    legacy = {"schema": 0, "status": "legacy", "started_at": start, "finished_at": end,
              "wall_seconds": seconds, "stages": [], "processes": [],
              "rea_decompile_counts": manifest.get("rea_decompile_counts", {}),
              "sampling_note": "This investigation predates performance and resource sampling."}
    return {"schema": 0, "latest": legacy, "runs": [legacy]}, legacy


def trend(folders: list[Path]) -> dict:
    rows = []
    for folder in folders[:100]:
        try:
            index, latest = load_metrics(folder)
            if isinstance(latest.get("wall_seconds"), (int, float)):
                rows.append({"folder": str(folder), "name": Path(folder).name,
                             "seconds": latest["wall_seconds"], "status": latest.get("status", "unknown"),
                             "date": latest.get("finished_at", "")})
        except (OSError, ValueError):
            continue
    values = [row["seconds"] for row in rows]
    ordered = sorted(values)
    return {"rows": rows, "count": len(rows),
            "median_seconds": round(statistics.median(values), 2) if values else None,
            "p95_seconds": ordered[max(0, int(0.95 * len(ordered) + 0.9999) - 1)] if values else None,
            "note": "Recent investigations only; target size and engine versions can differ."}


def export_metrics_csv(folder: Path, destination: Path) -> Path:
    _, detail = load_metrics(folder)
    with Path(destination).open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["kind", "name", "wall_seconds", "peak_working_set_mib",
                                                       "peak_private_mib", "sampled_cpu_seconds", "status"])
        writer.writeheader()
        for stage in detail.get("stages", []):
            writer.writerow({"kind": "stage", "name": stage["name"], "wall_seconds": stage["wall_seconds"]})
        for process in detail.get("processes", []):
            writer.writerow({"kind": "process", "name": process["stage"], "wall_seconds": process["wall_seconds"],
                             "peak_working_set_mib": round(process["peak_working_set_bytes"] / 1048576, 2)
                             if process.get("peak_working_set_bytes") is not None else "",
                             "peak_private_mib": round(process["peak_private_bytes"] / 1048576, 2)
                             if process.get("peak_private_bytes") is not None else "",
                             "sampled_cpu_seconds": process.get("sampled_cpu_seconds"),
                             "status": process.get("status", "unknown")})
    return Path(destination)
