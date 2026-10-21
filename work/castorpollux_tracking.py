"""Finding identity, build lineage, and known-answer corpus scoring."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from castorpollux_review import finding_key, load_triage


def finding_signature(finding: dict) -> str:
    """Heuristic cross-build identity, insensitive to relocated addresses."""
    title = re.sub(r"(?:0x|FUN_)?[0-9a-f]{8,16}", "ADDR", str(finding.get("title", "")).casefold())
    title = " ".join(re.findall(r"[a-z_]+|ADDR", title))
    locations = []
    for item in finding.get("evidence", []):
        location = re.sub(r"(?:0x|FUN_)?[0-9a-f]{8,16}", "ADDR", str(item.get("location", "")).casefold())
        locations.append((str(item.get("file", "")).casefold(), location))
    identity = json.dumps({"title": title, "locations": sorted(locations)}, sort_keys=True)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def _report(folder: Path) -> dict | None:
    for name in ("security-review-data.json", "security-report.json"):
        path = Path(folder) / name
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data.get("result", {}).get("findings"), list):
                    return data
            except (OSError, ValueError, AttributeError):
                pass
    return None


def compare_findings(older: Path, newer: Path) -> dict:
    left, right = _report(older), _report(newer)
    if left is None or right is None:
        return {"status": "unavailable", "reason": "Both builds need saved structured agent reviews."}
    a = {finding_signature(f): f for f in left["result"]["findings"]}
    b = {finding_signature(f): f for f in right["result"]["findings"]}
    def rows(keys, source):
        return [{"signature": key, "title": source[key].get("title", ""),
                 "severity": source[key].get("severity", ""),
                 "triage": load_triage(older if source is a else newer).get(finding_key(source[key]), {}).get("status", "unreviewed")}
                for key in sorted(keys)]
    return {"status": "complete", "recurring": rows(a.keys() & b.keys(), b),
            "resolved": rows(a.keys() - b.keys(), a), "new": rows(b.keys() - a.keys(), b),
            "limitations": "Identity is heuristic. Resolved means absent from the newer agent report, not proven fixed. Compare scope and coverage before concluding."}


def load_corpus(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        return {"schema": 1, "cases": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("cases"), list):
        raise ValueError("Known-answer corpus requires schema 1 and a cases array")
    return data


def add_confirmed_case(path: Path, folder: Path, complete: bool = False) -> dict:
    corpus = load_corpus(path)
    manifest = json.loads((Path(folder) / "manifest.json").read_text(encoding="utf-8"))
    report = _report(folder)
    if report is None:
        raise ValueError("Review this investigation before adding a corpus case")
    triage = load_triage(folder)
    expected = [{"id": finding_signature(f), "title": f.get("title", ""),
                 "signature": finding_signature(f)} for f in report["result"]["findings"]
                if triage.get(finding_key(f), {}).get("status") == "confirmed"]
    if not expected and not complete:
        raise ValueError("Confirm at least one finding in Findings before adding this case")
    case = {"sha256": manifest["sha256"], "name": manifest.get("input_name", ""),
            "complete": complete, "expected": expected,
            "added_at": datetime.now().astimezone().isoformat()}
    previous = next((item for item in corpus["cases"] if item.get("sha256") == case["sha256"]), None)
    if previous and "expected_flows" in previous:
        case["expected_flows"] = previous["expected_flows"]
    corpus["cases"] = [item for item in corpus["cases"] if item.get("sha256") != case["sha256"]] + [case]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(corpus, indent=2), encoding="utf-8")
    return case


def set_flow_answers(path: Path, folder: Path, expected_flows: list[dict], complete: bool) -> dict:
    """Save explicitly adjudicated flow answers for a corpus case."""
    if not complete:
        raise ValueError("Mark all expected findings labeled before saving flow answers")
    if not isinstance(expected_flows, list) or any(
            not isinstance(item, dict) or
            not all(isinstance(item.get(key), str) and item[key].strip()
                    for key in ("function", "source_api", "sink_api"))
            for item in expected_flows):
        raise ValueError("Flow answers must be an array of function/source_api/sink_api objects")
    corpus = load_corpus(path)
    manifest = json.loads((Path(folder) / "manifest.json").read_text(encoding="utf-8"))
    if not (Path(folder) / "rea-decompilation.json").is_file():
        raise ValueError("The selected investigation needs saved REA decompilation")
    case = next((item for item in corpus["cases"] if item.get("sha256") == manifest["sha256"]), None)
    if case is None:
        case = {"sha256": manifest["sha256"], "name": manifest.get("input_name", ""),
                "expected": [], "added_at": datetime.now().astimezone().isoformat()}
        corpus["cases"].append(case)
    case["expected_flows"] = expected_flows
    case["complete"] = True
    case["flow_answers_updated_at"] = datetime.now().astimezone().isoformat()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(corpus, indent=2), encoding="utf-8")
    return case


def evaluate_corpus(path: Path, folders: list[Path]) -> dict:
    corpus = load_corpus(path)
    cases = {item.get("sha256"): item for item in corpus["cases"]}
    results = []
    tp = fp = fn = 0
    complete_count = complete_tp = 0
    for folder in folders:
        folder = Path(folder)
        try:
            manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        case = cases.get(manifest.get("sha256"))
        review = _report(folder)
        if not case or review is None:
            continue
        expected = {item["signature"] for item in case.get("expected", []) if item.get("signature")}
        observed = {finding_signature(item) for item in review["result"]["findings"]}
        matched = expected & observed
        missed = expected - observed
        unexpected = observed - expected
        complete = bool(case.get("complete"))
        tp += len(matched)
        fn += len(missed)
        if complete:
            complete_count += 1
            complete_tp += len(matched)
            fp += len(unexpected)
        results.append({"folder": str(folder), "sha256": manifest["sha256"],
                        "complete": complete, "matched": sorted(matched), "missed": sorted(missed),
                        "false_positives": sorted(unexpected) if complete else [],
                        "unlabeled": sorted(unexpected) if not complete else []})
    metrics = {"true_positives": tp, "false_positives": fp if complete_count else None,
               "false_negatives": fn, "recall": tp / (tp + fn) if tp + fn else None,
               "precision": complete_tp / (complete_tp + fp) if complete_count and complete_tp + fp else None}
    return {"created_at": datetime.now().astimezone().isoformat(), "corpus": str(path),
            "cases_evaluated": len(results), "complete_cases": complete_count,
            "metrics": metrics, "results": results,
            "limitations": "Only adjudicated complete cases contribute false positives and precision. Matching is heuristic and affected by review scope and agent output."}
