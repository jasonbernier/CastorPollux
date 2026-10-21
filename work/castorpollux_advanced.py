"""Bounded, evidence-linked graph analysis over Ghidra's decompiler SSA export."""

from __future__ import annotations

import bisect
import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from castorpollux_flow import _lookup, load_rules


def _rows(path: Path, limit: int = 500_000) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        return [row for _, row in zip(range(limit), csv.DictReader(stream))]


def _hex(value: str) -> int | None:
    try:
        return int(value.removeprefix("0x"), 16)
    except (ValueError, AttributeError):
        return None


def _ssa_taint_leads(folder: Path, operations: list[dict]) -> list[dict]:
    """Propagate analyst-configured source values through SSA def-use within each function."""
    rules = load_rules(plugins=[])
    symbols = {}
    for filename, address_field in (("functions.csv", "entry"), ("symbols.csv", "address"),
                                    ("imports.csv", "address")):
        for row in _rows(folder / filename, 100_000):
            symbols[row.get(address_field, "").casefold()] = row.get("name", "")
    call_names = defaultdict(list)
    for ref in _rows(folder / "xrefs.csv"):
        if "CALL" in ref.get("type", "").upper():
            name = symbols.get(ref.get("to_address", "").casefold(), "")
            if name:
                call_names[ref.get("from_address", "").casefold()].append(name)
    by_function = defaultdict(list)
    for row in operations:
        by_function[row.get("function_entry", "").casefold()].append(row)
    leads = []
    for function, rows in by_function.items():
        origins = {}
        for row in rows:
            if row.get("opcode", "").upper() != "CALL":
                continue
            args = [part for part in row.get("inputs", "").split(";") if part]
            for name in call_names.get(row.get("address", "").casefold(), []):
                rule = _lookup(name, rules["sources"])
                if not rule:
                    continue
                output = rule.get("output", "return")
                variable = row.get("output", "") if output == "return" else \
                    args[1 + output] if isinstance(output, int) and len(args) > 1 + output else ""
                if variable:
                    origins[variable] = {"source_api": name, "source_site": row.get("address", ""),
                                         "source_varnode": variable, "chain": [variable]}
        # SSA identifiers are unique to a function; fixed-point handles non-topological block order.
        for _ in range(8):
            added = 0
            for row in rows:
                output = row.get("output", "")
                if not output or output in origins:
                    continue
                parts = [part for part in row.get("inputs", "").split(";") if part]
                inherited = next((origins[item] for item in parts if item in origins), None)
                if inherited:
                    origins[output] = {**inherited, "chain": (inherited["chain"] + [output])[-16:]}
                    added += 1
            if not added:
                break
        for row in rows:
            if row.get("opcode", "").upper() != "CALL":
                continue
            args = [part for part in row.get("inputs", "").split(";") if part]
            inherited = next((origins[item] for item in args[1:] if item in origins), None)
            if not inherited:
                continue
            for name in call_names.get(row.get("address", "").casefold(), []):
                if _lookup(name, rules["sinks"]) and len(leads) < 1000:
                    leads.append({"function_entry": function, **inherited, "sink_api": name,
                                  "sink_site": row.get("address", ""), "confidence": "low",
                                  "assessment": "candidate", "evidence_file": "pcode-ssa.csv"})
    return leads


def build_advanced_graph(folder: Path) -> dict:
    folder = Path(folder)
    operations = _rows(folder / "pcode-ssa.csv")
    functions = _rows(folder / "functions.csv", 100_000)
    xrefs = _rows(folder / "xrefs.csv")
    names = {row.get("entry", "").casefold().removeprefix("0x"): row.get("name", "") for row in functions}
    definitions: dict[tuple[str, str], dict] = {}
    aliases: list[dict] = []
    flows: list[dict] = []
    indirect: list[dict] = []
    memory: list[dict] = []
    for index, row in enumerate(operations):
        function = row.get("function_entry", "").casefold().removeprefix("0x")
        output = row.get("output", "")
        inputs = [item for item in row.get("inputs", "").split(";") if item]
        opcode = row.get("opcode", "").upper()
        site = row.get("address", "")
        base = {"function_entry": function, "function": names.get(function, ""), "address": site,
                "opcode": opcode, "output": output, "inputs": inputs, "op_index": index}
        if output:
            definitions[(function, output)] = base
        if opcode in {"COPY", "CAST", "PTRADD", "PTRSUB", "MULTIEQUAL"} and output and inputs and len(aliases) < 50_000:
            aliases.append({**base, "relation": "possible_pointer_alias" if opcode in {"COPY", "CAST", "MULTIEQUAL"}
                            else "pointer_offset", "confidence": "low" if opcode == "MULTIEQUAL" else "medium"})
        if opcode in {"LOAD", "STORE"} and len(memory) < 50_000:
            memory.append(base)
        if opcode in {"CALLIND", "BRANCHIND"} and len(indirect) < 10_000:
            indirect.append({**base, "dispatch": "indirect_call" if opcode == "CALLIND" else "computed_jump",
                             "confidence": "unresolved"})
    for index, row in enumerate(operations):
        function = row.get("function_entry", "").casefold().removeprefix("0x")
        for slot, item in enumerate(part for part in row.get("inputs", "").split(";") if part):
            origin = definitions.get((function, item))
            if origin and len(flows) < 100_000:
                flows.append({"function_entry": function, "from_index": origin["op_index"],
                              "to_index": index, "varnode": item, "input_slot": slot})
    pointer_values = {(row["function_entry"], row["inputs"][1]) for row in memory if len(row["inputs"]) > 1}
    pointer_values.update((row["function_entry"], row["inputs"][0]) for row in indirect if row["inputs"])
    for _ in range(8):
        old_size = len(pointer_values)
        for alias in aliases:
            if (alias["function_entry"], alias["output"]) in pointer_values:
                pointer_values.update((alias["function_entry"], item) for item in alias["inputs"])
        if len(pointer_values) == old_size:
            break
    aliases = [row for row in aliases if (row["function_entry"], row["output"]) in pointer_values]
    references = defaultdict(list)
    for row in xrefs:
        references[row.get("from_address", "").casefold().removeprefix("0x")].append(row)
    for site in indirect:
        candidates = []
        for ref in references.get(site["address"].casefold().removeprefix("0x"), []):
            target = ref.get("to_address", "").casefold().removeprefix("0x")
            if target in names:
                candidates.append({"entry": target, "name": names[target], "xref_type": ref.get("type", "")})
        site["candidates"] = candidates[:32]
        if candidates:
            site["confidence"] = "medium"
    # A CALLIND through LOAD/PTRADD chains is a virtual-dispatch lead, never a proven class-method edge.
    by_output = {(row.get("function_entry", "").casefold().removeprefix("0x"), row.get("output", "")): row
                 for row in operations if row.get("output")}
    virtual = []
    for site in indirect:
        if site["dispatch"] != "indirect_call":
            continue
        pointer = site["inputs"][0] if site["inputs"] else ""
        chain = []
        seen = set()
        for _ in range(5):
            key = (site["function_entry"], pointer)
            if key in seen or key not in by_output:
                break
            seen.add(key)
            operation = by_output[key]
            chain.append({"opcode": operation.get("opcode", ""), "address": operation.get("address", ""),
                          "output": pointer})
            parts = [part for part in operation.get("inputs", "").split(";") if part]
            pointer = parts[-1] if parts else ""
        if any(item["opcode"] in {"LOAD", "PTRADD", "PTRSUB"} for item in chain):
            virtual.append({**site, "dispatch_chain": chain, "kind": "possible_vtable_dispatch",
                            "limitations": "Could be a callback or function pointer; class and target are unverified."})
    jump_groups = defaultdict(list)
    for row in xrefs:
        kind = row.get("type", "").upper()
        if "COMPUTED_JUMP" in kind:
            jump_groups[row.get("from_address", "")].append(row)
    starts = sorted((_hex(row.get("entry", "")), row) for row in functions if _hex(row.get("entry", "")) is not None)
    addresses = [entry for entry, _ in starts]
    jump_tables = []
    for site, refs in list(jump_groups.items())[:10_000]:
        numeric = _hex(site)
        position = bisect.bisect_right(addresses, numeric) - 1 if numeric is not None else -1
        owner = starts[position][1] if position >= 0 else {}
        jump_tables.append({"site": site, "function_entry": owner.get("entry", ""),
                            "function": owner.get("name", ""),
                            "targets": sorted({row.get("to_address", "") for row in refs}),
                            "case_count": len({row.get("to_address", "") for row in refs}),
                            "confidence": "medium", "limitation": "Computed-jump references may be incomplete."})
    source_sink_leads = _ssa_taint_leads(folder, operations)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "engine": "Ghidra HighFunction SSA/P-code export",
              "ssa_ops": len(operations), "def_use_edges": len(flows), "pointer_alias_leads": len(aliases),
              "memory_operations": len(memory), "indirect_sites": len(indirect),
              "virtual_dispatch_leads": len(virtual), "jump_tables": len(jump_tables),
              "ssa_source_sink_leads": source_sink_leads, "ssa_source_sink_count": len(source_sink_leads),
              "aliases": aliases, "flows": flows, "memory": memory, "indirect": indirect,
              "virtual_calls": virtual, "jump_table_details": jump_tables,
              "truncated": len(operations) >= 500_000,
              "limitations": ["SSA varnodes and def-use edges come from Ghidra's decompiler IR; points-to and class hierarchy are not solved.",
                              "Source-to-sink SSA propagation is within one function, bounded to eight passes, and uses configured API names.",
                              "COPY/CAST/PHI pointer aliases are possible aliases, including non-pointer values.",
                              "Virtual calls and jump tables are candidates until corroborated with runtime or independent disassembly."]}
    (folder / "advanced-graph.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def check_call_edges(folder: Path) -> dict:
    """Cross-check saved Ghidra graph edges against independent instruction and REA text evidence."""
    folder = Path(folder)
    from castorpollux_pecheck import pe_layout, decode_call
    layout = pe_layout(folder / "source-binary.exe")
    if layout is None:
        candidate = next(folder.glob("source-binary.*"), None)
        layout = pe_layout(candidate) if candidate else None
    calls = _rows(folder / "calls.csv")
    function_rows = _rows(folder / "functions.csv", 100_000)
    spans = {}
    for row in function_rows:
        start = _hex(row.get("entry", ""))
        try:
            size = int(row.get("body_bytes", "0"))
        except ValueError:
            size = 0
        if start is not None:
            spans[row.get("entry", "").casefold().removeprefix("0x")] = (start, start + max(1, size * 4))
    ordered_starts = sorted(lower for lower, _ in spans.values())
    for key, (lower, upper) in list(spans.items()):
        position = bisect.bisect_right(ordered_starts, lower)
        spans[key] = (lower, min(upper, ordered_starts[position]) if position < len(ordered_starts) else upper)
    xrefs = _rows(folder / "xrefs.csv")
    indirect_path = folder / "indirect-calls.json"
    inferred = json.loads(indirect_path.read_text(encoding="utf-8")) if indirect_path.is_file() else {}
    instructions = {}
    source = folder / "disassembly.txt"
    if source.is_file():
        with source.open(encoding="utf-8", errors="replace") as stream:
            for _, line in zip(range(2_000_000), stream):
                match = re.match(r"^([0-9a-fA-F]{8,16})\s+(.+)$", line)
                if match:
                    instructions[match.group(1).casefold().removeprefix("0x")] = match.group(2).strip()
    targets = defaultdict(list)
    for row in xrefs:
        if "CALL" in row.get("type", "").upper():
            targets[row.get("to_address", "").casefold().removeprefix("0x")].append(row)
    rows = []
    for item in calls[:50_000]:
        target = item.get("callee_entry", "").casefold().removeprefix("0x")
        caller = item.get("caller_entry", "").casefold().removeprefix("0x")
        lower, upper = spans.get(caller, (-1, -1))
        corroborating = [{"site": ref.get("from_address"), "instruction": instructions.get(
            ref.get("from_address", "").casefold().removeprefix("0x"), "")}
                         for ref in targets.get(target, []) if ref.get("from_address") and
                         (numeric := _hex(ref.get("from_address", ""))) is not None and lower <= numeric < upper]
        status = "corroborated" if any(re.search(r"\b(CALL\w*|BL|JAL|JMP)\b", ref["instruction"], re.I)
                                     for ref in corroborating) else "disputed"
        checks = [decode_call(layout, numeric, _hex(target)) for ref in corroborating
                  if (numeric := _hex(ref.get("site", ""))) is not None]
        independent = next((item for item in checks if item["status"] in {"verified", "tail_jump_verified"}), None) or \
            next((item for item in checks if item["status"] == "site_only"), None) or \
            (checks[0] if checks else {"status": "unavailable", "reason": "No instruction-level call site was exported"})
        rows.append({**item, "status": status, "cross_check": corroborating[:12],
                     "independent_check": independent,
                     "reason": "Instruction-level CALL reference present" if status == "corroborated"
                     else "No matching instruction-level CALL reference in saved export"})
    for item in inferred.get("resolved", [])[:10_000]:
        site = item.get("site", "").casefold().removeprefix("0x")
        instruction = instructions.get(site, "")
        rows.append({"caller_entry": item.get("caller_entry", ""), "callee_entry": item.get("callee_entry", ""),
                     "caller_name": item.get("caller_name", ""), "callee_name": item.get("callee_name", ""),
                     "site": site, "instruction": instruction,
                     "status": "corroborated" if re.search(r"\b(CALL\w*|BLR|JALR)\b", instruction, re.I)
                     else "disputed", "independent_check": decode_call(layout, _hex(site), None) if _hex(site) is not None
                     else {"status": "unavailable"},
                     "reason": "Computed target is still unproven even when the call site is confirmed"})
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "edges": rows,
              "corroborated": sum(row["status"] == "corroborated" for row in rows),
              "disputed": sum(row["status"] == "disputed" for row in rows),
              "independently_verified": sum(row["independent_check"]["status"] in {"verified", "tail_jump_verified"} for row in rows),
              "independent_decoder": "PE x86/x64 E8 and FF /2 raw-byte check" if layout else "unavailable",
              "limitations": ["PE x86/x64 direct-call and tail-jump checks decode saved target bytes independently of Ghidra; other formats remain unavailable.",
                              "FF /2 proves only an indirect call site, never its runtime target.",
                              "A missing reference can mean incomplete export, a thunk, or dynamic dispatch; it does not disprove an edge."]}
    (folder / "call-edge-checks.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
