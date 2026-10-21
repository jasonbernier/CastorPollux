"""REA MCP decompilation in one persistent Ghidra-backed binary session."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path


BATCH_SIZE = 12


class ReaMcpClient:
    def __init__(self, node: Path, rea: Path, env: dict[str, str], log: Path,
                 cancelled, set_process):
        self.cancelled = cancelled
        self.set_process = set_process
        self.log = log
        self.events: queue.Queue[dict | None] = queue.Queue()
        self.next_id = 0
        self.process = subprocess.Popen([str(node), str(rea), "--mcp"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                        text=True, encoding="utf-8", errors="replace",
                                        bufsize=1, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.set_process(self.process)
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self):
        try:
            for line in self.process.stdout:
                try:
                    self.events.put(json.loads(line))
                except ValueError:
                    self.events.put({"invalid_line": line[:200]})
        finally:
            self.events.put(None)

    def _read_stderr(self):
        with self.log.open("a", encoding="utf-8", errors="replace") as stream:
            for line in self.process.stderr:
                stream.write(line)

    def _send(self, message: dict):
        if self.process.poll() is not None:
            raise RuntimeError(f"REA MCP server exited ({self.process.returncode}); see {self.log.name}")
        self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict, timeout: int = 600) -> dict:
        self.next_id += 1
        request_id = self.next_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.cancelled():
                raise InterruptedError("REA decompilation cancelled")
            try:
                reply = self.events.get(timeout=1)
            except queue.Empty:
                continue
            if reply is None:
                raise RuntimeError(f"REA MCP server stopped; see {self.log.name}")
            if reply.get("id") != request_id:
                if reply.get("method") == "ping":
                    self._send({"jsonrpc": "2.0", "id": reply.get("id"), "result": {}})
                continue
            if "error" in reply:
                raise RuntimeError(f"REA {method}: {reply['error']}")
            return reply.get("result", {})
        raise TimeoutError(f"REA {method} exceeded {timeout} seconds")

    def initialize(self):
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "CastorPollux", "version": "1.5.0"}}, 60)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def tool(self, name: str, arguments: dict, timeout: int = 600):
        reply = self.request("tools/call", {"name": name, "arguments": arguments}, timeout)
        if reply.get("isError"):
            content = reply.get("structuredContent") or reply.get("content")
            raise RuntimeError(f"REA {name}: {str(content)[:1200]}")
        return reply.get("structuredContent", {})

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.stdin.close()
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
        finally:
            self.set_process(None)


def _atomic_json(path: Path, data: dict):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def decompile_with_rea(binary: Path, output: Path, node: Path, rea: Path, jdk: Path,
                       ghidra: Path, target_sha256: str, notify, cancelled, set_process,
                       timeout_seconds: int = 1800, heap_mb: int = 2048) -> dict:
    """Export all provider-listed local procedures, checkpointing every batch."""
    output = Path(output)
    checkpoint = output / "rea-decompilation-progress.json"
    final_json = output / "rea-decompilation.json"
    source = output / "rea-pseudocode.c"
    snapshot = output / "rea-snapshot.json"
    try:
        progress = json.loads(checkpoint.read_text(encoding="utf-8"))
        if progress.get("sha256") != target_sha256 or not isinstance(progress.get("items"), dict):
            progress = {"sha256": target_sha256, "items": {}}
    except (OSError, ValueError):
        progress = {"sha256": target_sha256, "items": {}}
    env = os.environ.copy()
    env.update({"JAVA_HOME": str(jdk), "GHIDRA_INSTALL_DIR": str(ghidra)})
    env["NODE_OPTIONS"] = "--max-old-space-size=" + str(heap_mb)
    env["PATH"] = str(jdk / "bin") + os.pathsep + env.get("PATH", "")
    client = ReaMcpClient(node, rea, env, output / "rea-decompile.log", cancelled, set_process)
    deadline = time.monotonic() + timeout_seconds
    try:
        notify("REA: opening one Ghidra-backed decompilation session…")
        client.initialize()
        opened = client.tool("open_binary", {"path": str(binary.resolve()), "provider_id": "ghidra",
                                             **({"snapshot_path": str(snapshot.resolve())} if snapshot.is_file() else {})},
                             240)
        if not isinstance(opened.get("result"), dict):
            raise RuntimeError("REA did not open the selected binary")
        inventory = client.tool("list_procedures", {}, 240)
        rows = inventory.get("normalized_result")
        if not isinstance(rows, list):
            raise RuntimeError("REA did not return a procedure inventory")
        addresses = list(dict.fromkeys(row["address"] for row in rows
                                       if isinstance(row, dict) and isinstance(row.get("address"), str)
                                       and not row.get("procedure", {}).get("external", False)))
        if not addresses:
            raise RuntimeError("REA found no local procedures to decompile")
        progress["total"] = len(addresses)
        progress["addresses"] = addresses
        _atomic_json(checkpoint, progress)
        remaining = [address for address in addresses
                     if progress["items"].get(address, {}).get("status") != "ok"]
        notify(f"REA: {len(addresses)} local procedures; {len(remaining)} remain to decompile.")
        for offset in range(0, len(remaining), BATCH_SIZE):
            if cancelled():
                raise InterruptedError("REA decompilation cancelled")
            batch = remaining[offset:offset + BATCH_SIZE]
            remaining_seconds = int(deadline - time.monotonic())
            if remaining_seconds <= 0:
                raise TimeoutError("REA decompilation exceeded the configured time limit")
            result = client.tool("batch_decompile", {"addresses": batch}, min(600, remaining_seconds))
            normalized = result.get("normalized_result")
            if not isinstance(normalized, dict) or not isinstance(normalized.get("items"), list):
                raise RuntimeError("REA returned an invalid batch decompilation result")
            for item in normalized["items"]:
                if isinstance(item, dict) and item.get("address") in batch:
                    progress["items"][item["address"]] = item
            _atomic_json(checkpoint, progress)
            done = len(progress["items"])
            succeeded = sum(item.get("status") == "ok" for item in progress["items"].values())
            notify(f"REA decompilation: {done}/{len(addresses)} processed; {succeeded} reconstructed.")
        try:
            client.tool("close_binary", {"snapshot_path": str(snapshot.resolve()), "overwrite": True}, 60)
        except Exception as error:
            notify(f"REA snapshot save warning: {error}")
    finally:
        client.close()
    ordered = [progress["items"].get(address, {"address": address, "status": "missing",
                                               "error": "REA did not return this procedure"})
               for address in addresses]
    succeeded = [item for item in ordered if item.get("status") == "ok" and item.get("pseudocode")]
    if not succeeded:
        raise RuntimeError("REA did not reconstruct any procedure source; inspect rea-decompile.log")
    report = {"tool": "REA", "provider": "ghidra", "target_sha256": target_sha256,
              "generated_at": datetime.now().astimezone().isoformat(),
              "total": len(addresses), "processed": len(ordered), "succeeded": len(succeeded),
              "failed": len(addresses) - len(succeeded), "items": ordered,
              "note": "Reconstructed Ghidra pseudocode via REA, not the original source code."}
    _atomic_json(final_json, report)
    with source.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write("/* REA / Ghidra reconstructed pseudocode. This is not original source. */\n")
        stream.write(f"/* Target SHA-256: {target_sha256}; procedures: {len(succeeded)}/{len(addresses)} */\n")
        for item in succeeded:
            procedure = item.get("procedure") or {}
            stream.write(f"\n/* ===== {procedure.get('name') or item['address']} @ {item['address']} ===== */\n")
            stream.write(item["pseudocode"].rstrip() + "\n")
    try:
        from castorpollux_report_evidence import export_source_map
        export_source_map(output)
    except (OSError, ValueError) as error:
        notify(f"Reconstructed source-map export warning: {error}")
    return {key: report[key] for key in ("total", "processed", "succeeded", "failed")}
