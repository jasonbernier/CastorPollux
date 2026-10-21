"""Surface-level cross-checks between saved instructions and reconstructed procedures."""

from __future__ import annotations

import bisect
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_review import coverage_rows


INSTRUCTION = re.compile(r"^([0-9a-fA-F]{8,16})\s+([A-Za-z][A-Za-z0-9.]*)\b(.*)$")
BRANCHES = {"JZ", "JNZ", "JE", "JNE", "JA", "JAE", "JB", "JBE", "JG", "JGE", "JL", "JLE",
            "JC", "JNC", "JO", "JNO", "JS", "JNS", "LOOP", "CBZ", "CBNZ", "B.EQ", "B.NE"}
TRAPS = {"UD2", "INT3", "BRK", "BKPT"}


def check_consistency(folder: Path) -> dict:
    folder = Path(folder)
    functions = []
    path = folder / "functions.csv"
    if path.is_file():
        with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
            for row in csv.DictReader(stream):
                try:
                    functions.append((int(row["entry"], 16), row))
                except (KeyError, ValueError):
                    continue
    functions.sort(key=lambda item: item[0])
    addresses = [item[0] for item in functions]
    asm = {entry: {"instructions": 0, "calls": 0, "branches": 0, "traps": 0,
                   "sample": []} for entry, _ in functions}
    disassembly = folder / "disassembly.txt"
    scanned = 0
    truncated = False
    if disassembly.is_file() and functions:
        with disassembly.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                scanned += len(line)
                if scanned > 30 * 1024 * 1024:
                    truncated = True
                    break
                match = INSTRUCTION.match(line)
                if not match:
                    continue
                address = int(match.group(1), 16)
                index = bisect.bisect_right(addresses, address) - 1
                if index < 0:
                    continue
                entry, row = functions[index]
                try:
                    body = int(row.get("body_bytes", "0"))
                except ValueError:
                    body = 0
                if body <= 0 or address >= entry + max(64, body * 4):
                    continue
                item = asm[entry]
                item["instructions"] += 1
                mnemonic = match.group(2).upper()
                if mnemonic.startswith("CALL") or mnemonic in {"BL", "BLR", "JAL", "JALR"}:
                    item["calls"] += 1
                if mnemonic in BRANCHES or mnemonic.startswith("J") and mnemonic not in {"JMP", "JAL", "JALR"}:
                    item["branches"] += 1
                if mnemonic in TRAPS:
                    item["traps"] += 1
                if len(item["sample"]) < 8:
                    item["sample"].append(line.strip()[:220])
    rea = {}
    for row in coverage_rows(folder):
        try:
            rea[int(row["address"], 16)] = row
        except ValueError:
            pass
    results = []
    for entry, function in functions:
        saved = asm[entry]
        reconstructed = rea.get(entry, {})
        code = reconstructed.get("pseudocode", "")
        if not code:
            # Supplemental Ghidra pseudocode still permits a limited check when REA is unavailable.
            code = ""
        body = re.sub(r"^.*?\{", "", code, count=1, flags=re.S)
        reasons = []
        if saved["instructions"] == 0:
            status = "unavailable"
            reasons.append("No disassembly instructions aligned to this procedure")
        elif not code:
            status = "review"
            reasons.append("Instructions exist but REA reconstructed code is missing")
        else:
            if saved["calls"] and not re.search(r"\b[A-Za-z_][A-Za-z_0-9]*\s*\(", body):
                reasons.append("Assembly has calls; no call expression was recognized in reconstructed body")
            if saved["branches"] and not re.search(r"\b(?:if|for|while|switch|goto)\b|\?", body):
                reasons.append("Assembly has conditional branches; no high-level branch was recognized")
            if saved["traps"] and not re.search(r"\b(?:trap|breakpoint|abort|panic)\b", body, re.I):
                reasons.append("Assembly trap instruction is not apparent in reconstructed body")
            status = "review" if reasons else "surface_aligned"
        results.append({"entry": function["entry"], "name": function.get("name", ""),
                        "status": status, "reasons": reasons, "assembly": saved,
                        "rea_status": reconstructed.get("status", "unavailable"),
                        "limitation": "These are syntax and coverage checks, not semantic-equivalence proofs."})
    summary = {key: sum(row["status"] == key for row in results)
               for key in ("surface_aligned", "review", "unavailable")}
    result = {"generated_at": datetime.now(timezone.utc).isoformat(), "summary": summary,
              "procedures": results, "disassembly_scanned_bytes": scanned,
              "disassembly_truncated": truncated,
              "limitation": "Function spans are approximate; branches, inlining, optimized code and indirect calls may create false leads. Surface alignment does not establish correctness."}
    (folder / "consistency-checks.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
