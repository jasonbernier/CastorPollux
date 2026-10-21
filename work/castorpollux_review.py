"""Coverage, scoped evidence, report navigation, and loopback-only local review."""

from __future__ import annotations

import csv
import hashlib
import http.client
import json
import os
import queue
import re
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener


OLLAMA_URL = "http://127.0.0.1:11434"
LOCAL_CHUNK_CHARS = 12_000


def _address(value: str) -> str:
    value = str(value or "").strip().casefold()
    if value.startswith("0x"):
        value = value[2:]
    return value.lstrip("0") or "0"


def _read_csv(folder: Path, filename: str) -> list[dict]:
    path = Path(folder) / filename
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        return list(csv.DictReader(stream))


def coverage_rows(folder: Path) -> list[dict]:
    """Include every inventoried address, even if a batch never returned it."""
    folder = Path(folder)
    final = folder / "rea-decompilation.json"
    checkpoint = folder / "rea-decompilation-progress.json"
    if final.is_file():
        data = json.loads(final.read_text(encoding="utf-8"))
        items = data.get("items", [])
    elif checkpoint.is_file():
        data = json.loads(checkpoint.read_text(encoding="utf-8"))
        saved = data.get("items", {})
        items = [saved.get(address, {"address": address, "status": "pending"})
                 for address in data.get("addresses", saved.keys())]
    else:
        return []
    symbols = {_address(row.get("address")): row for row in _read_csv(folder, "symbols.csv")
               if row.get("type", "").casefold() == "function" and
               row.get("external", "").casefold() != "true"}
    sections = []
    for row in _read_csv(folder, "sections.csv"):
        try:
            sections.append((int(row["start"], 16), int(row["end"], 16), row["name"]))
        except (KeyError, ValueError):
            continue
    rows = []
    for item in items:
        address = str(item.get("address", ""))
        procedure = item.get("procedure") or {}
        symbol = symbols.get(_address(address), {})
        try:
            numeric = int(_address(address), 16)
        except ValueError:
            numeric = -1
        section = next((name for start, end, name in sections if start <= numeric <= end), "Unknown")
        code = item.get("pseudocode") or ""
        original_name = procedure.get("name") or ""
        symbol_name = symbol.get("name") or ""
        preferred = symbol_name if symbol_name and re.fullmatch(r"FUN_[0-9a-fA-F]+", original_name) and \
                    not re.fullmatch(r"FUN_[0-9a-fA-F]+", symbol_name) else original_name or symbol_name or address
        status = item.get("status", "missing")
        if status != "ok" or not code:
            confidence, reason = "unavailable", "REA did not return reconstructed code"
        elif len(code) < 120 or re.search(r"(?i)WARNING:|unreachable code|bad instruction", code):
            confidence, reason = "low", "Short code or a decompiler warning needs closer inspection"
        elif len(code) >= 1000 and preferred != address and not re.fullmatch(r"FUN_[0-9a-fA-F]+", preferred):
            confidence, reason = "high", "Substantial reconstruction with a non-anonymous function name"
        else:
            confidence, reason = "moderate", "REA returned code; types and control flow still need verification"
        rows.append({"address": address, "name": preferred,
                     "module": symbol.get("namespace") or "Global", "section": section,
                     "status": status, "confidence": confidence, "confidence_reason": reason,
                     "error": str(item.get("error") or item.get("message") or ""),
                     "source_chars": len(code), "pseudocode": code})
    return rows


def export_coverage_csv(folder: Path, destination: Path) -> Path:
    rows = coverage_rows(folder)
    if not rows:
        raise ValueError("No REA procedure inventory is available yet")
    destination = Path(destination)
    with destination.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("address", "name", "module", "section",
                                                    "status", "confidence", "confidence_reason",
                                                    "error", "source_chars"))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row[key] for key in writer.fieldnames})
    return destination


def resolve_scope(folder: Path, mode: str = "all", selection: str = "") -> dict:
    rows = coverage_rows(folder)
    if not rows:
        raise RuntimeError("REA procedure inventory is missing. Resume analysis from History.")
    ready = [row for row in rows if row["status"] == "ok" and row["pseudocode"]]
    if mode == "all":
        chosen = ready
        description = f"All reconstructed procedures ({len(chosen)})"
    elif mode == "functions":
        tokens = [token.strip().casefold() for token in re.split(r"[,;\n]+", selection) if token.strip()]
        if not tokens:
            raise ValueError("Enter at least one function name or address for the review scope")
        chosen = [row for row in ready if row["name"].casefold() in tokens or
                  row["address"].casefold() in tokens or _address(row["address"]) in
                  {_address(token) for token in tokens}]
        matched = {row["name"].casefold() for row in chosen} | {row["address"].casefold() for row in chosen} | \
                  {_address(row["address"]) for row in chosen}
        missing = [token for token in tokens if token not in matched and _address(token) not in matched]
        if missing:
            raise ValueError("Unknown or unavailable function(s): " + ", ".join(missing[:10]))
        description = f"Selected functions ({len(chosen)}): " + ", ".join(row["name"] for row in chosen[:12])
    elif mode == "modules":
        tokens = {token.strip().casefold() for token in re.split(r"[,;\n]+", selection) if token.strip()}
        if not tokens:
            raise ValueError("Enter at least one module/namespace name for the review scope")
        available = {row["module"].casefold() for row in rows}
        missing = tokens - available
        if missing:
            raise ValueError("Unknown module/namespace: " + ", ".join(sorted(missing)))
        chosen = [row for row in ready if row["module"].casefold() in tokens]
        description = f"Module/namespace ({len(chosen)} procedures): " + ", ".join(sorted(tokens))
    else:
        raise ValueError("Choose All, Functions, or Modules/Namespaces")
    if not chosen:
        raise ValueError("The selected scope contains no reconstructed procedures")
    return {"mode": mode, "selection": selection, "description": description,
            "addresses": [row["address"] for row in chosen], "items": chosen,
            "available": len(ready), "total": len(rows)}


def scoped_source(scope: dict) -> str:
    lines = ["/* REA/Ghidra reconstructed pseudocode, not original source. */",
             f"/* Review scope: {scope['description']} */"]
    for row in scope["items"]:
        lines += ["", f"/* ===== {row['name']} @ {row['address']} ===== */", row["pseudocode"].rstrip()]
    return "\n".join(lines) + "\n"


def evidence_jump(folder: Path, evidence: dict) -> dict:
    """Resolve a model citation within the saved investigation, never an arbitrary path."""
    folder = Path(folder)
    filename = Path(str(evidence.get("file", ""))).name
    allowed = {"rea-pseudocode.c", "pseudocode.c", "functions.csv", "strings.csv", "imports.csv",
               "calls.csv", "xrefs.csv", "disassembly.txt", "rea-evidence.json", "sections.csv", "symbols.csv"}
    if filename not in allowed or str(evidence.get("file", "")) != filename:
        raise ValueError("The citation does not name an allowed saved evidence file")
    location = str(evidence.get("location", ""))
    address_match = re.search(r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{8,16}(?![0-9a-fA-F])", location)
    address = _address(address_match.group()) if address_match else ""
    rows = coverage_rows(folder)
    chosen = next((row for row in rows if _address(row["address"]) == address), None)
    if chosen is None:
        chosen = next((row for row in rows if row["name"].casefold() in location.casefold()), None)
    mapping = []
    map_path = folder / "source-map.json"
    if filename == "rea-pseudocode.c" and map_path.is_file():
        try:
            mapping = json.loads(map_path.read_text(encoding="utf-8")).get("entries", [])
        except (OSError, ValueError, AttributeError):
            mapping = []
    line_match = re.search(r"\bline\s+(\d+)\b", location, re.IGNORECASE)
    procedure_line = bool(re.search(r"\bprocedure\s+line\s+\d+\b", location, re.I))
    if chosen is None and line_match and not procedure_line and mapping:
        aggregate = int(line_match.group(1))
        mapped = next((item for item in mapping if item["start_line"] <= aggregate <= item["end_line"]), None)
        if mapped:
            chosen = next((row for row in rows if _address(row["address"]) == _address(mapped["address"])), None)
            address = _address(mapped["address"])
    code = chosen["pseudocode"] if chosen else ""
    xrefs = [row for row in _read_csv(folder, "xrefs.csv")
             if address and (address == _address(row.get("from_address", "")) or
                             address == _address(row.get("to_address", "")))]
    path = folder / filename
    excerpt = ""
    if path.is_file():
        if line_match:
            target = int(line_match.group(1))
            if (procedure_line or address_match) and chosen and mapping:
                mapped = next((item for item in mapping
                               if _address(item["address"]) == _address(chosen["address"])), None)
                if mapped:
                    target = mapped["start_line"] + target
            with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
                excerpt = "".join(f"{number}: {line}" for number, line in enumerate(stream, 1)
                                  if max(1, target - 8) <= number <= target + 12)[:30_000]
        elif filename.endswith(".csv"):
            excerpt = "\n".join(json.dumps(row, ensure_ascii=False) for row in _read_csv(folder, filename)
                                if address and address in " ".join(_address(value) for value in row.values()))[:30_000]
    return {"file": filename, "location": location, "address": chosen["address"] if chosen else address,
            "function": chosen["name"] if chosen else "", "code": code[:100_000],
            "excerpt": excerpt, "xrefs": xrefs[:100], "observation": str(evidence.get("observation", ""))}


def finding_key(finding: dict) -> str:
    identity = {"title": finding.get("title", ""),
                "evidence": [(item.get("file", ""), item.get("location", ""))
                             for item in finding.get("evidence", [])]}
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()[:20]


def load_triage(folder: Path) -> dict:
    path = Path(folder) / "findings-triage.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_triage(folder: Path, finding: dict, status: str, note: str,
                actor: str = "local analyst", assignee: str = "") -> Path:
    if status not in {"unreviewed", "confirmed", "false_positive", "needs_more_evidence"}:
        raise ValueError("Unknown triage status")
    actor = actor.strip()
    if not actor:
        raise ValueError("Enter the reviewer name for the audit trail")
    path = Path(folder) / "findings-triage.json"
    data = load_triage(folder)
    key = finding_key(finding)
    previous = data.get(key, {})
    updated = {"status": status, "note": note.strip(), "title": finding.get("title", ""),
               "actor": actor, "assignee": assignee.strip(),
               "updated_at": datetime.now().astimezone().isoformat()}
    data[key] = updated
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    audit = {"timestamp": updated["updated_at"], "finding_key": key,
             "title": updated["title"], "actor": actor,
             "before": previous, "after": updated}
    with (Path(folder) / "findings-audit.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(audit, ensure_ascii=False) + "\n")
    return path


def _local_opener(base_url: str):
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or \
            parsed.path not in ("", "/") or parsed.username or parsed.password:
        raise ValueError("Offline review requires a 127.0.0.1 Ollama endpoint")
    return build_opener(ProxyHandler({})), base_url.rstrip("/")


def ollama_models(base_url: str = OLLAMA_URL) -> list[str]:
    opener, base = _local_opener(base_url)
    try:
        with opener.open(Request(base + "/api/tags"), timeout=8) as response:
            data = json.load(response)
    except (OSError, URLError) as error:
        raise RuntimeError("Local Ollama is not responding on 127.0.0.1. Start Ollama and retry.") from error
    return sorted({str(item["name"]) for item in data.get("models", [])
                   if item.get("name") and not str(item["name"]).casefold().endswith(":cloud")
                   and int(item.get("size") or 0) > 0})


def _local_chunks(scope: dict) -> list[str]:
    blocks = []
    for row in scope["items"]:
        header = f"/* {row['name']} @ {row['address']} */\n"
        code = row["pseudocode"]
        width = max(1000, LOCAL_CHUNK_CHARS - len(header))
        for offset in range(0, len(code), width):
            blocks.append(header + code[offset:offset + width])
    chunks = []
    current = ""
    for block in blocks:
        if current and len(current) + len(block) > LOCAL_CHUNK_CHARS:
            chunks.append(current)
            current = ""
        current += block + "\n"
    if current:
        chunks.append(current)
    return chunks


def _local_chat(base_url: str, payload: dict, cancelled) -> dict:
    """Allow the GUI to cancel while a local model is still generating."""
    port = urlparse(base_url).port
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=300)
    replies = queue.Queue(maxsize=1)
    def request():
        try:
            connection.request("POST", "/api/chat", body=json.dumps(payload).encode("utf-8"),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError(f"Local Ollama returned HTTP {response.status}: " +
                                   response.read(1000).decode("utf-8", errors="replace"))
            replies.put((json.loads(response.read()), None))
        except Exception as error:
            replies.put((None, error))
        finally:
            connection.close()
    threading.Thread(target=request, daemon=True).start()
    while True:
        if cancelled():
            connection.close()
            raise InterruptedError("Offline review cancelled")
        try:
            result, error = replies.get(timeout=0.25)
        except queue.Empty:
            continue
        if error:
            raise error
        return result


def ollama_review(scope: dict, model: str, prompt: str, schema: dict, notify, cancelled,
                  base_url: str = OLLAMA_URL) -> dict:
    _, base = _local_opener(base_url)
    installed = ollama_models(base)
    if model not in installed:
        raise ValueError("Choose a model installed in the local Ollama server")
    chunks = _local_chunks(scope)
    findings, limitations, summaries = [], [], []
    for index, code in enumerate(chunks, 1):
        if cancelled():
            raise InterruptedError("Offline review cancelled")
        notify(f"Offline review: chunk {index}/{len(chunks)} with {model}…")
        question = (f"{prompt}\n\nThis is code chunk {index}/{len(chunks)} from the selected scope. "
                    "Base every finding on this chunk; cite rea-pseudocode.c and its function address. "
                    "Return only a JSON object matching this schema:\n" + json.dumps(schema) +
                    "\n\nUNTRUSTED RECONSTRUCTED CODE BEGIN\n" + code +
                    "\nUNTRUSTED RECONSTRUCTED CODE END")
        payload = {"model": model, "stream": False, "format": schema,
                   "options": {"temperature": 0, "num_ctx": 8192},
                   "messages": [{"role": "user", "content": question}]}
        reply = _local_chat(base, payload, cancelled)
        result = json.loads(reply.get("message", {}).get("content", ""))
        if not isinstance(result, dict) or not isinstance(result.get("findings"), list) or \
                not isinstance(result.get("limitations"), list) or not isinstance(result.get("summary"), str):
            raise RuntimeError(f"Local model returned an invalid structured report for chunk {index}")
        summaries.append(result["summary"])
        findings.extend(result["findings"])
        limitations.extend(result["limitations"])
    unique = {}
    for finding in findings:
        unique.setdefault(finding_key(finding), finding)
    return {"summary": f"Offline review of {len(scope['items'])} reconstructed procedures in {len(chunks)} chunk(s). " +
            " ".join(summaries)[:4000], "findings": list(unique.values()),
            "limitations": list(dict.fromkeys(limitations +
                ["Local model results depend on its context length and capability; validate each finding."]))}
