"""Connect changed procedures to cited findings through saved call edges."""

from __future__ import annotations

import csv
import json
import re
from collections import deque
from pathlib import Path

from castorpollux_tracking import finding_signature


def _rows(folder: Path, filename: str) -> list[dict]:
    try:
        with (folder / filename).open("r", encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))
    except OSError:
        return []


def _review(folder: Path) -> list[dict]:
    for filename in ("security-review-data.json", "security-report.json"):
        try:
            return json.loads((folder / filename).read_text(encoding="utf-8"))["result"]["findings"]
        except (OSError, ValueError, KeyError, TypeError):
            pass
    return []


def _path(graph: dict[str, set[str]], start: str, targets: set[str], limit: int = 4) -> list[str]:
    queue = deque([(start, [start])])
    seen = {start}
    while queue:
        node, path = queue.popleft()
        if node in targets:
            return path
        if len(path) > limit:
            continue
        for adjacent in sorted(graph.get(node, set()) - seen):
            seen.add(adjacent)
            queue.append((adjacent, path + [adjacent]))
    return []


def patch_impact_map(folder: Path, comparison: dict) -> dict:
    folder = Path(folder)
    functions = _rows(folder, "functions.csv")
    names = {row.get("entry", "").casefold(): row.get("name", "") for row in functions}
    by_name = {name.casefold(): address for address, name in names.items() if name}
    changed_names = {row["function"].casefold() for row in comparison["functions"]["changed"]}
    changed_names.update(name.casefold() for name in comparison["functions"]["added"])
    changed = {address for address, name in names.items() if name.casefold() in changed_names}
    changed.update(str(row.get("new_entry", "")).casefold() for row in comparison["functions"]["changed"])
    changed.discard("")
    graph: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for row in _rows(folder, "calls.csv"):
        source = row.get("caller_entry", "").casefold()
        target = row.get("callee_entry", "").casefold()
        if source in names and target in names:
            graph.setdefault(source, set()).add(target)
            reverse.setdefault(target, set()).add(source)
    impacts = []
    for finding in _review(folder):
        cited = set()
        for evidence in finding.get("evidence", []):
            location = str(evidence.get("location", "")).casefold()
            cited.update(match.group(1) for match in re.finditer(r"(?:0x)?([0-9a-f]{8,16})\b", location)
                         if match.group(1) in names)
            cited.update(address for name, address in by_name.items() if name and name in location)
        relation, path = "unresolved citation", []
        for address in sorted(cited):
            if address in changed:
                relation, path = "cited function changed", [address]
                break
            downstream = _path(graph, address, changed)
            if downstream:
                relation, path = "called function changed", downstream
                break
            upstream = _path(reverse, address, changed)
            if upstream:
                relation, path = "caller changed", list(reversed(upstream))
                break
            relation = "no observed call-path link"
        impacts.append({"signature": finding_signature(finding), "title": finding.get("title", ""),
                        "severity": finding.get("severity", ""), "relation": relation,
                        "cited_functions": sorted(cited),
                        "call_path": [{"address": address, "name": names.get(address, "")} for address in path]})
    return {"changed_function_count": len(changed), "finding_count": len(impacts), "findings": impacts,
            "limitations": "A static call-path link is a review priority, not proof that a patch changed behavior or resolved a vulnerability. Indirect calls and unmatched anonymous functions may be missed."}
