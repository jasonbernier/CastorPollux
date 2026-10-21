"""Configurable, conservative source-to-sink leads in REA pseudocode."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

from castorpollux_core import home
from castorpollux_plugins import load_plugins, validate_plugin
from castorpollux_review import coverage_rows

DEFAULT_RULES = {
    "schema": 1,
    "sources": [
        {"name": "ReadFile", "output": 1}, {"name": "recv", "output": 1},
        {"name": "recvfrom", "output": 1}, {"name": "fgets", "output": 0},
        {"name": "gets", "output": 0}, {"name": "scanf", "output": 0},
        {"name": "getenv", "output": "return"},
        {"name": "GetEnvironmentVariable", "output": 1},
        {"name": "GetCommandLine", "output": "return"},
        {"name": "InternetReadFile", "output": 1}, {"name": "read", "output": 1},
        {"name": "fread", "output": 0}],
    "sinks": ["strcpy", "strcat", "sprintf", "memcpy", "memmove", "system", "popen",
              "WinExec", "CreateProcess", "ShellExecute", "LoadLibrary", "VirtualAlloc",
              "VirtualProtect", "WriteProcessMemory", "execve"],
    "sanitizers": [],
}
CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^;]*)\)")
ASSIGN = re.compile(r"^\s*(?:[A-Za-z_]\w*(?:\s*\*)?\s+)?([A-Za-z_]\w*)\s*=\s*(.+);\s*$")
IDENT = re.compile(r"\b[A-Za-z_]\w*\b")


def rules_path() -> Path:
    return home() / "data-flow-rules.json"


def create_default_rules(path: Path | None = None) -> Path:
    path = Path(path or rules_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_RULES, indent=2), encoding="utf-8")
    return path


def load_rules(path: Path | None = None, plugins: list[dict] | None = None) -> dict:
    path = Path(path or rules_path())
    base = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else DEFAULT_RULES
    validate_plugin({"schema": 1, "id": "flow-rules", "enabled": True, "flow": base})
    if base.get("schema") != 1:
        raise ValueError("Flow rules need schema 1")
    merged = {key: list(base.get(key, [])) for key in ("sources", "sinks", "sanitizers")}
    active = load_plugins() if plugins is None else plugins
    for plugin in active:
        for key in merged:
            merged[key].extend(plugin.get("flow", {}).get(key, []))
    return {"schema": 1, **merged, "plugins": [item["id"] for item in active],
            "rules_file": str(path) if path.is_file() else "built-in"}


def _lookup(name: str, rules: list) -> dict | None:
    name = name.lstrip("_").casefold()
    for item in rules:
        candidate = item if isinstance(item, str) else item["name"]
        if candidate.casefold() == name:
            return {"output": "return", **item} if isinstance(item, dict) else {"name": item, "output": "return"}
    return None


def _argument(match: re.Match, position: int) -> str | None:
    arguments = [part.strip() for part in match.group(2).split(",")]
    if len(arguments) <= position:
        return None
    variable = re.sub(r"^[&*\s]+", "", arguments[position])
    return variable if re.fullmatch(r"[A-Za-z_]\w*", variable) else None


def trace_procedure(row: dict, rules: dict | None = None) -> list[dict]:
    if row.get("status") != "ok" or not row.get("pseudocode"):
        return []
    rules = rules or load_rules(plugins=[])
    tainted: dict[str, dict] = {}
    leads = []
    for line_number, line in enumerate(row["pseudocode"].splitlines(), 1):
        calls = list(CALL.finditer(line))
        assignment = ASSIGN.match(line)
        source = next(((match, _lookup(match.group(1), rules["sources"])) for match in calls
                       if _lookup(match.group(1), rules["sources"])), None)
        sanitizers = [(match, _lookup(match.group(1), rules["sanitizers"])) for match in calls
                      if _lookup(match.group(1), rules["sanitizers"])]
        if sanitizers:
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
                tainted[variable] = {"api": match.group(1), "line": line_number,
                                     "text": line.strip(), "chain": [variable]}
        elif assignment and not sanitizers:
            variable, expression = assignment.groups()
            carried = next((tainted[token] for token in IDENT.findall(expression) if token in tainted), None)
            if carried:
                tainted[variable] = {**carried, "chain": (carried["chain"] + [variable])[-12:]}
            else:
                tainted.pop(variable, None)
        for match in calls:
            if not _lookup(match.group(1), rules["sinks"]):
                continue
            args = match.group(2)
            if any(re.search(r"\b" + re.escape(item[0].group(1)) + r"\s*\(", args) for item in sanitizers):
                continue
            carried = next((tainted[token] for token in IDENT.findall(args) if token in tainted), None)
            if not carried and (not source or source[0].start() > match.start()):
                continue
            origin = carried or {"api": source[0].group(1), "line": line_number,
                                 "text": line.strip(), "chain": []}
            leads.append({"function": row["name"], "address": row["address"],
                          "source_api": origin["api"], "source_line": origin["line"],
                          "source_text": origin["text"], "variables": origin["chain"],
                          "sink_api": match.group(1), "sink_line": line_number,
                          "sink_text": line.strip(), "evidence_file": "rea-pseudocode.c",
                          "assessment": "candidate", "confidence": "low"})
    return leads


def build_data_flow(folder: Path, rules_file: Path | None = None,
                    plugins: list[dict] | None = None) -> dict:
    folder = Path(folder)
    rows = coverage_rows(folder)
    if not rows:
        raise ValueError("REA procedure inventory is missing")
    rules = load_rules(rules_file, plugins)
    leads = [lead for row in rows for lead in trace_procedure(row, rules)]
    serialized = json.dumps(rules, sort_keys=True).encode("utf-8")
    report = {"created_at": datetime.now().astimezone().isoformat(),
              "method": "intra-procedural heuristic assignment tracing",
              "rules_sha256": hashlib.sha256(serialized).hexdigest(),
              "rules_file": rules["rules_file"], "plugins": rules["plugins"],
              "procedures_scanned": sum(row["status"] == "ok" for row in rows),
              "procedures_total": len(rows), "leads": leads,
              "limitations": ["These are candidates, not proven vulnerabilities or complete taint paths.",
                              "Pointer aliases, casts, field writes, and cross-procedure data transfer are not resolved.",
                              "Sanitizers are recognized by name only; their real behavior is not verified.",
                              "A missing lead does not imply the binary is safe."]}
    (folder / "data-flow.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _lead_key(lead: dict) -> tuple[str, str, str]:
    return (str(lead.get("function", "")).casefold(),
            str(lead.get("source_api", "")).casefold(),
            str(lead.get("sink_api", "")).casefold())


def evaluate_rule_change(candidate: Path, corpus_file: Path, folders: list[Path]) -> dict:
    """Compare active and candidate rules against manually labeled flow answers."""
    from castorpollux_tracking import load_corpus
    candidate = Path(candidate).resolve()
    if not candidate.is_file():
        raise ValueError("Candidate rules JSON is missing")
    active_path = rules_path().resolve()
    proposed = load_rules(candidate)
    active = load_rules(active_path)
    cases = {case.get("sha256"): case for case in load_corpus(corpus_file)["cases"]
             if case.get("complete") and isinstance(case.get("expected_flows"), list)}
    results = []
    totals = {name: {"tp": 0, "fp": 0, "fn": 0} for name in ("active", "candidate")}
    for folder in folders:
        folder = Path(folder)
        try:
            manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        case = cases.get(manifest.get("sha256"))
        if case is None:
            continue
        rows = coverage_rows(folder)
        if not rows:
            continue
        expected = {_lead_key(item) for item in case["expected_flows"]}
        entry = {"folder": str(folder), "sha256": manifest["sha256"]}
        for name, rules in (("active", active), ("candidate", proposed)):
            observed = {_lead_key(lead) for row in rows for lead in trace_procedure(row, rules)}
            metrics = {"tp": len(observed & expected), "fp": len(observed - expected),
                       "fn": len(expected - observed)}
            for key, value in metrics.items():
                totals[name][key] += value
            entry[name] = {**metrics, "unexpected": sorted(observed - expected),
                           "missed": sorted(expected - observed)}
        results.append(entry)
    baseline, trial = totals["active"], totals["candidate"]
    passed = bool(results) and trial["fp"] <= baseline["fp"] and trial["fn"] <= baseline["fn"]
    return {"status": "passed" if passed else "blocked", "cases_evaluated": len(results),
            "candidate_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "active": baseline, "candidate": trial, "results": results,
            "requirements": "Complete corpus cases need manually adjudicated expected_flows. Candidate must not increase false positives or missed flows.",
            "note": "A passing corpus is a regression check, not proof that rules are accurate on other binaries."}


def activate_rule_change(candidate: Path, corpus_file: Path, folders: list[Path],
                         expected_sha256: str) -> dict:
    result = evaluate_rule_change(candidate, corpus_file, folders)
    if result["candidate_sha256"] != expected_sha256 or result["status"] != "passed":
        raise ValueError("Candidate changed or failed the known-answer regression gate")
    destination = rules_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".new")
    shutil.copyfile(candidate, temporary)
    temporary.replace(destination)
    return result
