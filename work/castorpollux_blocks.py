"""Approximate basic-block maps and bounded cross-build instruction diffs."""

from __future__ import annotations

import bisect
import csv
import difflib
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


INSTRUCTION = re.compile(r"^([0-9a-fA-F]{8,16})\s+([A-Za-z][\w.]*)\b(.*)$")
NUMBER = re.compile(r"(?i)\b(?:0x[0-9a-f]+|[0-9a-f]{6,}h?|\d{4,})\b")


def _address(value: str) -> str:
    try:
        return format(int(str(value), 16), "x")
    except (TypeError, ValueError):
        return ""


def _function_rows(folder: Path) -> list[tuple[int, dict]]:
    with (folder / "functions.csv").open(encoding="utf-8-sig", newline="", errors="replace") as stream:
        rows = []
        for row in csv.DictReader(stream):
            try:
                rows.append((int(row["entry"], 16), row))
            except (KeyError, ValueError):
                continue
    return sorted(rows)


def _block_map(folder: Path, selected: set[str]) -> dict[str, list[dict]]:
    functions = _function_rows(folder)
    starts = [entry for entry, _ in functions]
    instructions = defaultdict(list)
    source = folder / "disassembly.txt"
    if not source.is_file():
        return {}
    scanned = 0
    with source.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            scanned += len(line)
            if scanned > 30 * 1024 * 1024:
                break
            match = INSTRUCTION.match(line.strip())
            if not match:
                continue
            address = int(match.group(1), 16)
            index = bisect.bisect_right(starts, address) - 1
            if index < 0:
                continue
            entry, row = functions[index]
            key = format(entry, "x")
            if key not in selected or len(instructions[key]) >= 5000:
                continue
            try:
                span = int(row.get("body_bytes", "0"))
            except ValueError:
                span = 0
            if span <= 0 or address >= entry + max(64, span * 4):
                continue
            instructions[key].append((address, match.group(2).upper(), match.group(3).strip()))
    jumps = defaultdict(set)
    xref_path = folder / "xrefs.csv"
    if xref_path.is_file():
        with xref_path.open(encoding="utf-8-sig", newline="", errors="replace") as stream:
            for row in csv.DictReader(stream):
                if "JUMP" not in row.get("type", "").upper():
                    continue
                try:
                    source_address = int(row["from_address"], 16)
                    target = int(row["to_address"], 16)
                except (KeyError, ValueError):
                    continue
                jumps[source_address].add(target)
    result = {}
    for key, values in instructions.items():
        values.sort()
        address_set = {address for address, _, _ in values}
        leaders = {values[0][0]}
        for index, (address, mnemonic, _) in enumerate(values):
            targets = jumps.get(address, set()) & address_set
            leaders.update(targets)
            if targets or mnemonic.startswith("J") or mnemonic in {"RET", "RETN", "B", "BR", "BX", "BLR"}:
                if index + 1 < len(values):
                    leaders.add(values[index + 1][0])
        blocks, active = [], []
        for instruction in values:
            if active and instruction[0] in leaders:
                blocks.append(active)
                active = []
            active.append(instruction)
        if active:
            blocks.append(active)
        converted = []
        for block in blocks[:250]:
            normalized = [mnemonic + " " + NUMBER.sub("#", operand.casefold()) for _, mnemonic, operand in block]
            digest = hashlib.sha256("\n".join(normalized).encode("utf-8")).hexdigest()
            converted.append({"entry": format(block[0][0], "x"), "end": format(block[-1][0], "x"),
                              "instruction_count": len(block), "normalized": normalized,
                              "instructions": [f"{address:x}  {mnemonic} {operand}" for address, mnemonic, operand in block],
                              "hash": digest})
        result[key] = converted
    return result


def build_basic_block_diff(left: Path, right: Path, pairs: list[dict], destination: Path) -> dict:
    left, right, destination = Path(left), Path(right), Path(destination)
    pairs_truncated = len(pairs) > 300
    pairs = pairs[:300]
    old = _block_map(left, {_address(item["old_entry"]) for item in pairs})
    new = _block_map(right, {_address(item["new_entry"]) for item in pairs})
    procedures = []
    for pair in pairs:
        previous = old.get(_address(pair["old_entry"]), [])
        current = new.get(_address(pair["new_entry"]), [])
        matches, used_old, used_new = [], set(), set()
        hashes_old, hashes_new = defaultdict(list), defaultdict(list)
        for index, block in enumerate(previous):
            hashes_old[block["hash"]].append(index)
        for index, block in enumerate(current):
            hashes_new[block["hash"]].append(index)
        for digest in hashes_old.keys() & hashes_new.keys():
            repeated = len(hashes_old[digest]) > 1 or len(hashes_new[digest]) > 1
            for a, b in zip(hashes_old[digest], hashes_new[digest]):
                matches.append({"old_index": a, "new_index": b, "status": "unchanged", "similarity": 1.0,
                                "alignment": "order-only duplicate" if repeated else "unique hash"})
                used_old.add(a); used_new.add(b)
        candidates = []
        for a, block_a in enumerate(previous):
            if a in used_old:
                continue
            for b, block_b in enumerate(current):
                if b in used_new:
                    continue
                ratio = difflib.SequenceMatcher(None, block_a["normalized"], block_b["normalized"], autojunk=False).ratio()
                if ratio >= .55:
                    candidates.append((ratio, a, b))
        for ratio, a, b in sorted(candidates, reverse=True):
            if a not in used_old and b not in used_new:
                matches.append({"old_index": a, "new_index": b, "status": "changed", "similarity": round(ratio, 3)})
                used_old.add(a); used_new.add(b)
        counts = {"unchanged": sum(item["status"] == "unchanged" for item in matches),
                  "changed": sum(item["status"] == "changed" for item in matches),
                  "removed": len(previous) - len(used_old), "added": len(current) - len(used_new)}
        procedures.append({"name": pair.get("name", ""), "old_entry": pair["old_entry"],
                           "new_entry": pair["new_entry"], "old_blocks": previous,
                           "new_blocks": current, "matches": sorted(matches, key=lambda item: item["old_index"]),
                           "counts": counts, "truncated": len(previous) >= 250 or len(current) >= 250})
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "procedures": procedures,
              "procedure_count": len(procedures), "pairs_truncated": pairs_truncated,
              "limitations": ["Blocks use saved disassembly and Ghidra jump references with approximate function spans.",
                              "Normalized instruction matching is heuristic; changed or reordered blocks can be mispaired.",
                              "No control-flow equivalence or vulnerability fix is established by this view."]}
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "basic-block-diff.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
