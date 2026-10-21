"""Read Codex account rate limits through the installed CLI app-server protocol."""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_core import APP_VERSION


def summarize_usage(response: dict) -> dict:
    """Keep only display-safe values; absent windows are unavailable, not full."""
    snapshots = response.get("rateLimitsByLimitId") or {}
    if not isinstance(snapshots, dict) or not snapshots:
        snapshots = {"codex": response.get("rateLimits") or {}}
    limits = []
    for key, value in snapshots.items():
        if not isinstance(value, dict):
            continue
        windows = []
        for label in ("primary", "secondary"):
            item = value.get(label)
            if not isinstance(item, dict) or not isinstance(item.get("usedPercent"), (int, float)):
                continue
            used = max(0, min(100, float(item["usedPercent"])))
            windows.append({"window": label, "used_percent": used, "remaining_percent": round(100 - used, 1),
                            "duration_minutes": item.get("windowDurationMins"), "resets_at": item.get("resetsAt")})
        limits.append({"id": str(key), "name": value.get("limitName") or str(key), "windows": windows})
    return {"agent": "codex", "status": "available" if any(item["windows"] for item in limits) else "unavailable",
            "checked_at": datetime.now(timezone.utc).isoformat(), "limits": limits}


def usage_label(usage: dict) -> str:
    if usage.get("agent") == "all":
        return "  |  ".join(usage_label(item) for item in usage.get("items", []))
    if usage.get("agent") == "claude":
        return ("Claude Code: " + usage.get("summary", "usage unavailable"))
    if usage.get("agent") == "opencode":
        return ("OpenCode: " + usage.get("summary", "usage unavailable"))
    if usage.get("status") != "available":
        return "Codex usage: unavailable from installed CLI; open Codex and use /status."
    parts = []
    for limit in usage["limits"]:
        windows = limit["windows"]
        if windows:
            parts.append(str(limit["name"]) + ": " + ", ".join(
                f"{window['remaining_percent']:g}% left ({window['duration_minutes']} min)"
                if window["duration_minutes"] else f"{window['remaining_percent']:g}% left"
                for window in windows))
    return "Codex usage: " + "; ".join(parts) if parts else "Codex usage: unavailable."


def read_other_usage(agent: str, executable: Path | None, review_log: Path | None = None) -> dict:
    """Report measured session usage, never invent remaining subscription quota."""
    result = {"agent": agent, "checked_at": datetime.now(timezone.utc).isoformat(),
              "status": "unavailable", "summary": "remaining quota is not exposed by this CLI"}
    if not executable or not Path(executable).is_file():
        result["summary"] = "CLI not installed"
        return result
    if agent == "claude":
        # The --output-format json response contains per-run usage, but no
        # supported machine-readable subscription balance endpoint.
        if review_log and Path(review_log).is_file():
            try:
                value = json.loads(Path(review_log).read_text(encoding="utf-8"))
                usage = value.get("usage") or {}
                result.update({"status": "session_only", "session_usage": usage,
                               "summary": "last review: " + str(usage.get("input_tokens", "?")) +
                               " input / " + str(usage.get("output_tokens", "?")) +
                               " output tokens; remaining quota unavailable"})
            except (OSError, ValueError, TypeError):
                pass
        return result
    if agent == "opencode":
        try:
            process = subprocess.run([str(executable), "stats"], capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=15,
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if process.returncode == 0:
                result.update({"status": "session_only", "summary":
                               "local usage stats available (see agent-usage.json); remaining provider quota unavailable",
                               "stats": process.stdout[:12000]})
            else:
                result["summary"] = "stats command unavailable; remaining quota unavailable"
        except (OSError, subprocess.TimeoutExpired):
            pass
    return result


def read_codex_usage(executable: Path | None, timeout: float = 15) -> dict:
    if not executable or not Path(executable).is_file():
        return {"agent": "codex", "status": "unavailable", "reason": "Codex CLI not found"}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = None
    try:
        process = subprocess.Popen([str(executable), "app-server", "--listen", "stdio://"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, encoding="utf-8", errors="replace", bufsize=1,
                                   creationflags=flags)
        messages: queue.Queue[dict] = queue.Queue()
        def reader() -> None:
            for line in process.stdout:
                try:
                    messages.put(json.loads(line))
                except ValueError:
                    continue
        threading.Thread(target=reader, daemon=True).start()
        deadline = time.monotonic() + timeout
        def send(message: dict) -> None:
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
        def receive(request_id: int) -> dict:
            while time.monotonic() < deadline:
                try:
                    message = messages.get(timeout=min(0.5, max(0.01, deadline - time.monotonic())))
                except queue.Empty:
                    if process.poll() is not None:
                        break
                    continue
                if message.get("id") == request_id:
                    if "error" in message:
                        raise RuntimeError(str(message["error"].get("message", "Codex usage request failed")))
                    return message.get("result") or {}
            raise TimeoutError("Codex usage read timed out")
        send({"id": 1, "method": "initialize", "params": {"clientInfo": {
            "name": "castorpollux", "title": "CastorPollux", "version": APP_VERSION}}})
        receive(1)
        send({"method": "initialized", "params": {}})
        send({"id": 2, "method": "account/rateLimits/read", "params": {"excludeResetCreditDetails": True}})
        return summarize_usage(receive(2))
    except (OSError, RuntimeError, TimeoutError, BrokenPipeError) as error:
        return {"agent": "codex", "status": "unavailable", "reason": str(error)[:250]}
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
