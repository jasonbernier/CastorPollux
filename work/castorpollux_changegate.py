"""Cross-build signature changes and reproducible CI gates for newly introduced call paths."""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


def _rows(folder: Path, name: str) -> list[dict]:
    path = Path(folder) / name
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        return list(csv.DictReader(stream))


def _signature(value: str) -> dict:
    text = re.sub(r"\s+", " ", value or "").strip()
    match = re.match(r"^(.*?)\((.*)\)$", text)
    if not match:
        return {"raw": text, "return_type": "", "parameters": [], "parsed": False}
    before, args = match.groups()
    # Keep full declaration to avoid pretending C++ templates/function pointers parse cleanly.
    pieces = before.rsplit(" ", 1)
    return {"raw": text, "return_type": pieces[0] if len(pieces) > 1 else "",
            "parameters": [] if args.strip() in {"", "void"} else [item.strip() for item in args.split(",")],
            "parsed": True}


def compare_type_signatures(left: Path, right: Path, matches: list[dict], destination: Path) -> dict:
    old = {row.get("entry", "").casefold(): row for row in _rows(left, "functions.csv")}
    new = {row.get("entry", "").casefold(): row for row in _rows(right, "functions.csv")}
    changes = []
    for match in matches:
        a = old.get(match.get("old_entry", "").casefold())
        b = new.get(match.get("new_entry", "").casefold())
        if not a or not b or a.get("signature") == b.get("signature"):
            continue
        before, after = _signature(a.get("signature", "")), _signature(b.get("signature", ""))
        changes.append({"function": b.get("name", ""), "old_entry": a["entry"], "new_entry": b["entry"],
                        "before": before, "after": after,
                        "return_type_changed": before["return_type"] != after["return_type"],
                        "arity_changed": len(before["parameters"]) != len(after["parameters"]),
                        "parameters_changed": before["parameters"] != after["parameters"],
                        "confidence": "medium" if before["parsed"] and after["parsed"] else "low"})
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "changes": changes,
              "count": len(changes), "limitations": ["Decompiler-inferred types can change without an ABI change.",
                                               "Complex C++ templates/function pointers are preserved as raw declarations."]}
    (Path(destination) / "type-signature-diff.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _graph(folder: Path) -> tuple[dict[str, str], dict[str, set[str]]]:
    names = {row.get("entry", "").casefold(): row.get("name", "") for row in _rows(folder, "functions.csv")}
    edges = defaultdict(set)
    for row in _rows(folder, "calls.csv"):
        src, dst = row.get("caller_entry", "").casefold(), row.get("callee_entry", "").casefold()
        if src and dst:
            edges[src].add(dst)
    return names, edges


def _paths(folder: Path, sources: list[str], sinks: list[str], depth: int = 6) -> dict[str, list[list[str]]]:
    names, edges = _graph(folder)
    source_ids = {entry for entry, name in names.items() if entry in sources or name in sources}
    sink_ids = {entry for entry, name in names.items() if entry in sinks or name in sinks}
    results = defaultdict(list)
    for source in sorted(source_ids)[:200]:
        queue = deque([(source, [source])])
        while queue and sum(map(len, results.values())) < 5000:
            node, path = queue.popleft()
            if node in sink_ids and len(path) > 1:
                results[names.get(source, source) + " → " + names.get(node, node)].append(
                    [names.get(item, item) for item in path])
            if len(path) < depth:
                queue.extend((target, path + [target]) for target in sorted(edges[node]) if target not in path)
    return dict(results)


def gate_new_call_paths(baseline: Path, current: Path, sources: list[str], sinks: list[str],
                        destination: Path | None = None) -> dict:
    if not sources or not sinks:
        raise ValueError("Call-path gate requires nonempty source and sink function lists")
    before = _paths(Path(baseline), sources, sinks)
    after = _paths(Path(current), sources, sinks)
    old_paths = {tuple(path) for paths in before.values() for path in paths}
    changed_paths = {pair: [path for path in paths if tuple(path) not in old_paths]
                     for pair, paths in after.items()}
    changed_paths = {pair: paths for pair, paths in changed_paths.items() if paths}
    new_pairs = sorted(changed_paths)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "baseline": str(baseline),
              "current": str(current), "sources": sources, "sinks": sinks,
              "status": "fail" if new_pairs else "pass", "new_pairs": new_pairs,
              "new_path_count": sum(len(paths) for paths in changed_paths.values()),
              "paths": {pair: changed_paths[pair][:10] for pair in new_pairs},
              "limitations": ["Gate uses saved direct call edges and bounded depth six; indirect and runtime calls can be missed.",
                              "A new path is a review trigger, not proof of a vulnerability."]}
    output = Path(destination) if destination else Path(current)
    output.mkdir(parents=True, exist_ok=True)
    (output / "call-path-gate.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
