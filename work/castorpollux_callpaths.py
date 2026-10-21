"""Bounded navigation of saved static Ghidra call edges."""

from __future__ import annotations

import csv
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


def load_graph(folder: Path) -> dict:
    path = Path(folder) / "calls.csv"
    if not path.is_file():
        raise ValueError("No Ghidra calls.csv export is saved for this investigation")
    names, edges, details = {}, defaultdict(set), {}
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        for row in csv.DictReader(stream):
            source, target = row.get("caller_entry", ""), row.get("callee_entry", "")
            if not source or not target:
                continue
            names[source] = row.get("caller_name") or source
            names[target] = row.get("callee_name") or target
            edges[source].add(target)
            details[(source, target)] = {"confidence": "high", "kind": "direct",
                                         "reason": "Saved Ghidra direct-call edge"}
    inferred = Path(folder) / "indirect-calls.json"
    if inferred.is_file():
        data = json.loads(inferred.read_text(encoding="utf-8"))
        for item in data.get("resolved", []):
            source, target = item.get("caller_entry", ""), item.get("callee_entry", "")
            if not source or not target:
                continue
            names.setdefault(source, item.get("caller_name") or source)
            names.setdefault(target, item.get("callee_name") or target)
            edges[source].add(target)
            details.setdefault((source, target), {"confidence": item["confidence"],
                                                  "kind": "indirect candidate", "reason": item["reason"],
                                                  "site": item.get("site", "")})
    return {"names": names, "edges": {key: sorted(value) for key, value in edges.items()},
            "edge_details": {source + "|" + target: value for (source, target), value in details.items()}}


def _resolve(names: dict, query: str) -> str:
    query = query.strip().casefold()
    if not query:
        raise ValueError("Enter a function name or address")
    exact = [address for address, name in names.items() if query in (address.casefold(), name.casefold())]
    if len(exact) == 1:
        return exact[0]
    partial = exact or [address for address, name in names.items() if query in name.casefold()]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise ValueError(f"No saved function matches {query!r}")
    raise ValueError(f"Ambiguous function {query!r}; use an address. Candidates: " +
                     ", ".join(f"{names[address]} @ {address}" for address in partial[:8]))


def explore_paths(folder: Path, source: str, target: str, max_depth: int = 12,
                  max_paths: int = 5) -> dict:
    folder = Path(folder)
    graph = load_graph(folder)
    names, edges = graph["names"], graph["edges"]
    start, end = _resolve(names, source), _resolve(names, target)
    queue = deque([[start]])
    paths = []
    expansions = 0
    while queue and len(paths) < max_paths and expansions < 100_000:
        path = queue.popleft()
        if path[-1] == end:
            paths.append([{"entry": address, "name": names[address],
                           "callers": sum(address in children for children in edges.values()),
                           "callees": len(edges.get(address, [])),
                           "incoming": graph["edge_details"].get(path[index - 1] + "|" + address)
                           if index else None} for index, address in enumerate(path)])
            continue
        if len(path) >= max_depth:
            continue
        for neighbour in edges.get(path[-1], [])[:500]:
            if neighbour not in path:
                queue.append(path + [neighbour])
                expansions += 1
    result = {"created_at": datetime.now(timezone.utc).isoformat(),
              "source": {"entry": start, "name": names[start]},
              "target": {"entry": end, "name": names[end]},
              "paths": paths, "truncated": bool(queue) or expansions >= 100_000,
              "limitation": "Direct calls and labeled indirect candidates only. Unresolved dispatch and dynamic loading can hide real paths; inferred edges do not prove execution."}
    (folder / "call-path-explorer.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
