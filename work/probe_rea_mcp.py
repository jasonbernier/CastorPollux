import json
import os
import queue
import subprocess
import threading
from pathlib import Path

root = Path(__file__).parent
env = os.environ.copy()
env["GHIDRA_INSTALL_DIR"] = str(Path(os.environ["LOCALAPPDATA"]) / "CastorPollux" / "Tools" / "ghidra_12.1.4_PUBLIC")
env["JAVA_HOME"] = str(Path(os.environ["LOCALAPPDATA"]) / "CastorPollux" / "Tools" / "jdk-21.0.12.1+1")
process = subprocess.Popen([str(root / "runtime" / "node.exe"), str(root / "runtime" / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"), "--mcp"],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, encoding="utf-8", env=env)
lines = queue.Queue()
threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True).start()


def request(payload):
    process.stdin.write(json.dumps(payload) + "\n")
    process.stdin.flush()
    if "id" in payload:
        while True:
            response = json.loads(lines.get(timeout=180))
            if response.get("id") == payload["id"]:
                print("RPC", payload.get("method"), "id", payload["id"], "error", response.get("error"))
                return response


try:
    request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "CastorPollux", "version": "1.3.0"}}})
    request({"jsonrpc": "2.0", "method": "notifications/initialized"})
    response = request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    for tool in response.get("result", {}).get("tools", []):
        if tool["name"] in {"open_binary", "list_procedures", "batch_decompile", "close_binary"}:
            print(tool["name"], json.dumps(tool.get("inputSchema"))[:2000])
    target = (root / "castorpollux-v110-test" / "where-20261015-185842-148195" / "source-binary.exe").resolve()
    for name, arguments in (("open_binary", {"path": str(target), "provider_id": "ghidra"}),
                            ("list_procedures", {}),
                            ("batch_decompile", {"addresses": ["0x140001010", "0x1400010f0"]}),
                            ("close_binary", {})):
        reply = request({"jsonrpc": "2.0", "id": 10 + len(name), "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}})
        data = reply.get("result", {}).get("structuredContent", {})
        print("TOOL", name, "structured keys", list(data), "result type", type(data.get("result")).__name__)
        if "normalized_result" in data:
            observed = data["normalized_result"]
            print("NORMALIZED", type(observed).__name__, list(observed)[:5] if isinstance(observed, dict) else json.dumps(observed[:2])[:550])
        value = data.get("result")
        if isinstance(value, dict):
            print("RESULT KEYS", list(value), "normalized", list(value.get("normalized_result", {})))
        if name == "batch_decompile":
            print("BATCH", {key: data.get("normalized_result", {}).get(key) for key in ("total", "succeeded", "failed")})
            print("FIRST", json.dumps(data.get("normalized_result", {}).get("items", [])[:1])[:700])
finally:
    process.terminate()
