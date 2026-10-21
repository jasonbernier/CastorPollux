"""Bounded, evidence-linked cross-procedure data-flow candidates."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_flow import ASSIGN, CALL, IDENT, _argument, _lookup, load_rules
from castorpollux_review import coverage_rows


PARAM = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*$")


def _parameters(code: str) -> list[str]:
    header = code.split("{", 1)[0]
    signatures = re.findall(r"\(([^()]*)\)", header)
    if not signatures:
        return []
    names = []
    for declaration in signatures[-1].split(","):
        declaration = declaration.strip()
        if declaration in {"", "void", "..."}:
            continue
        match = PARAM.search(declaration)
        names.append(match.group(1) if match else "")
    return names


def _call_edges(folder: Path) -> dict[str, dict[str, str]]:
    edges = {}
    path = folder / "calls.csv"
    if not path.is_file():
        return edges
    with path.open(encoding="utf-8-sig", newline="", errors="replace") as stream:
        for row in csv.DictReader(stream):
            source, target = row.get("caller_entry", "").casefold().removeprefix("0x"), row.get("callee_entry", "").casefold().removeprefix("0x")
            name = row.get("callee_name", "")
            if source and target and name:
                previous = edges.setdefault(source, {}).get(name)
                edges[source][name] = target if previous in (None, target) else ""
    return edges


def build_cross_function_flow(folder: Path, rules_file: Path | None = None,
                              plugins: list[dict] | None = None) -> dict:
    folder = Path(folder)
    rules = load_rules(rules_file, plugins)
    rows = {row["address"].casefold().removeprefix("0x"): row for row in coverage_rows(folder)
            if row.get("status") == "ok" and row.get("pseudocode")}
    edges = _call_edges(folder)
    leads, seen = [], set()
    traversed = 0
    truncated = False

    def analyze(address: str, seeds: dict[str, dict], path: list[str]):
        nonlocal traversed, truncated
        if address not in rows or address in path or len(path) >= 4 or traversed >= 2500:
            truncated = truncated or traversed >= 2500
            return None
        traversed += 1
        row = rows[address]
        chain = path + [address]
        tainted = dict(seeds)
        returned = None
        for line_number, line in enumerate(row["pseudocode"].splitlines(), 1):
            calls = list(CALL.finditer(line))
            assignment = ASSIGN.match(line)
            source = next(((match, _lookup(match.group(1), rules["sources"])) for match in calls
                           if _lookup(match.group(1), rules["sources"])), None)
            sanitizers = [(match, _lookup(match.group(1), rules["sanitizers"])) for match in calls
                          if _lookup(match.group(1), rules["sanitizers"])]
            for match, rule in sanitizers:
                if rule["output"] == "return" and assignment:
                    tainted.pop(assignment.group(1), None)
                elif isinstance(rule["output"], int):
                    variable = _argument(match, rule["output"])
                    if variable:
                        tainted.pop(variable, None)
            if source:
                match, rule = source
                variable = assignment.group(1) if rule["output"] == "return" and assignment else \
                           _argument(match, rule["output"]) if isinstance(rule["output"], int) else None
                if variable:
                    tainted[variable] = {"source_api": match.group(1), "source_function": row["name"],
                                         "source_address": row["address"], "source_line": line_number,
                                         "source_text": line.strip(), "variables": [variable],
                                         "flow_path": [address]}
            elif assignment and not sanitizers:
                variable, expression = assignment.groups()
                origin = next((tainted[token] for token in IDENT.findall(expression) if token in tainted), None)
                if origin:
                    tainted[variable] = {**origin, "variables": (origin["variables"] + [variable])[-12:]}
                else:
                    tainted.pop(variable, None)
            for match in calls:
                name = match.group(1)
                if _lookup(name, rules["sinks"]):
                    origin = next((tainted[token] for token in IDENT.findall(match.group(2)) if token in tainted), None)
                    if origin and len(origin.get("flow_path", [])) > 1:
                        key = (origin["source_address"], origin["source_line"], address, line_number, name)
                        if key not in seen and len(leads) < 500:
                            seen.add(key)
                            leads.append({**{key: value for key, value in origin.items() if key != "flow_path"},
                                          "sink_api": name, "sink_function": row["name"],
                                          "sink_address": row["address"], "sink_line": line_number,
                                          "sink_text": line.strip(), "call_path":
                                          [{"address": rows[item]["address"], "name": rows[item]["name"]}
                                           for item in origin["flow_path"]], "confidence": "low", "assessment": "candidate",
                                          "evidence_file": "rea-pseudocode.c"})
                target = edges.get(address, {}).get(name)
                if not target or target not in rows or _lookup(name, rules["sanitizers"]):
                    continue
                arguments = [part.strip() for part in match.group(2).split(",")]
                parameters = _parameters(rows[target]["pseudocode"])
                child_seeds = {}
                for index, argument in enumerate(arguments[:len(parameters)]):
                    if parameters[index]:
                        origin = next((tainted[token] for token in IDENT.findall(argument) if token in tainted), None)
                        if origin:
                            child_seeds[parameters[index]] = {**origin,
                                "flow_path": (origin.get("flow_path", [address]) + [target])[-8:]}
                # A returned source can also flow back to the caller. Limit untainted exploration.
                if not child_seeds and (not assignment or not any(
                    source_rule["name"].casefold() in rows[target]["pseudocode"].casefold()
                    for source_rule in rules["sources"])):
                    continue
                child_return = analyze(target, child_seeds, chain)
                if child_return and assignment:
                    tainted[assignment.group(1)] = {**child_return,
                        "flow_path": (child_return.get("flow_path", [target]) + [address])[-8:]}
            if re.search(r"\breturn\b", line):
                origin = next((tainted[token] for token in IDENT.findall(line.split("return", 1)[-1])
                               if token in tainted), None)
                if origin:
                    returned = origin
        return returned

    for address in rows:
        if traversed >= 2500:
            truncated = True
            break
        analyze(address, {}, [])
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "method": "bounded named-parameter and direct-call propagation",
              "rules_file": rules["rules_file"], "procedures_scanned": len(rows),
              "traversals": traversed, "truncated": truncated or len(leads) >= 500,
              "leads": leads, "limitations": [
                  "These are low-confidence static candidates, not proven vulnerabilities or executable paths.",
                  "Only unique direct callees from calls.csv and simple named parameters/assignments are followed; depth is four procedures.",
                  "Pointers, structures, aliases, indirect calls, and sanitizer semantics may be missed or misread."]}
    (folder / "cross-function-flow.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
