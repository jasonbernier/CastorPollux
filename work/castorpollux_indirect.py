"""Conservative indirect-call candidates from saved instructions and references."""

from __future__ import annotations

import bisect
import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


CALL = re.compile(r"^([0-9a-fA-F]{8,16})\s+(CALL\w*|BLR|JALR)\s+(.+)$", re.I)
REGISTER = re.compile(r"^(?:R(?:[0-9]+|[A-Z]{2})|E[A-Z]{2}|[A-Z]{2}|X\d+|W\d+)\b", re.I)


def resolve_indirect_calls(folder: Path) -> dict:
    folder = Path(folder)
    functions = []
    with (folder / "functions.csv").open(encoding="utf-8-sig", newline="", errors="replace") as stream:
        for row in csv.DictReader(stream):
            try:
                functions.append((int(row["entry"], 16), row))
            except (KeyError, ValueError):
                continue
    functions.sort()
    starts = [entry for entry, _ in functions]
    by_address = {entry: row for entry, row in functions}
    imports = {}
    import_file = folder / "imports.csv"
    if import_file.is_file():
        with import_file.open(encoding="utf-8-sig", newline="", errors="replace") as stream:
            imports = {row.get("address", "").casefold(): row for row in csv.DictReader(stream)}
    references = defaultdict(list)
    xref_file = folder / "xrefs.csv"
    if xref_file.is_file():
        with xref_file.open(encoding="utf-8-sig", newline="", errors="replace") as stream:
            for row in csv.DictReader(stream):
                references[row.get("from_address", "").casefold().removeprefix("0x")].append(row)
    candidates, unresolved = [], []
    scanned = 0
    disassembly = folder / "disassembly.txt"
    if not disassembly.is_file():
        raise ValueError("Ghidra disassembly.txt is missing")
    with disassembly.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            scanned += len(line)
            if scanned > 30 * 1024 * 1024 or len(candidates) + len(unresolved) >= 10000:
                break
            match = CALL.match(line.strip())
            if not match:
                continue
            site, mnemonic, operand = match.groups()
            if not ("[" in operand or "(" in operand or REGISTER.match(operand) or mnemonic.upper() in {"BLR", "JALR"}):
                continue
            address = int(site, 16)
            index = bisect.bisect_right(starts, address) - 1
            if index < 0:
                continue
            entry, caller = functions[index]
            try:
                span = int(caller.get("body_bytes", "0"))
            except ValueError:
                span = 0
            if span <= 0 or address >= entry + max(64, span * 4):
                continue
            base = {"site": site, "caller_entry": caller["entry"], "caller_name": caller.get("name", ""),
                    "instruction": line.strip()[:240]}
            resolved = []
            for ref in references.get(site.casefold(), []):
                target = ref.get("to_address", "")
                kind = ref.get("type", "").upper()
                try:
                    numeric = int(target, 16)
                except ValueError:
                    numeric = -1
                if numeric in by_address and "CALL" in kind:
                    callee = by_address[numeric]
                    resolved.append({**base, "callee_entry": callee["entry"],
                                     "callee_name": callee.get("name", ""), "confidence": "medium",
                                     "reason": f"Ghidra {kind} reference to a known function entry"})
                elif target.casefold() in imports and kind in {"READ", "DATA", "INDIRECTION"}:
                    imported = imports[target.casefold()]
                    resolved.append({**base, "callee_entry": target, "callee_name": imported.get("name", ""),
                                     "confidence": "low", "reason": "Pointer/data reference matches an import address; dispatch target is unverified"})
            if resolved:
                candidates.extend(resolved[:8])
            else:
                unresolved.append({**base, "confidence": "unresolved",
                                   "reason": "Register or memory call with no saved target reference"})
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "resolved": candidates,
              "unresolved": unresolved, "scanned_bytes": scanned,
              "truncated": scanned > 30 * 1024 * 1024 or len(candidates) + len(unresolved) >= 10000,
              "limitations": ["Medium means a Ghidra computed-call reference; low means an import/data pointer candidate.",
                              "Unresolved targets, callbacks, virtual dispatch and runtime loading can hide real edges.",
                              "An inferred edge does not prove that code executes or that a call target is reachable."]}
    (folder / "indirect-calls.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
