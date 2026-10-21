"""Indexed evidence navigation and conservative cross-engine review aids."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_review import coverage_rows
from castorpollux_tracking import evaluate_corpus, load_corpus, finding_signature

MARKER = re.compile(r"^/\* ===== (.+) @ (0x[0-9a-fA-F]+) ===== \*/$")
ADDRESS = re.compile(r"(?:0x)?[0-9a-fA-F]{8,16}")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_source_index(folder: Path, source_name: str = "rea-pseudocode.c") -> dict:
    """Keep a SQLite FTS index tied to the exact source hash."""
    folder = Path(folder)
    source = folder / source_name
    if not source.is_file():
        raise FileNotFoundError(source)
    fingerprint = _hash(source)
    index = folder / (source_name + ".search-v2.sqlite")
    try:
        db = sqlite3.connect(index)
        db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)")
        db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS source_lines USING fts5(text, entry UNINDEXED, address UNINDEXED, line UNINDEXED, tokenize='trigram')")
        existing = db.execute("SELECT value FROM metadata WHERE key='sha256'").fetchone()
        if existing != (fingerprint,):
            db.execute("DELETE FROM source_lines")
            current = ""
            batch = []
            with source.open("r", encoding="utf-8", errors="replace") as stream:
                for number, line in enumerate(stream, 1):
                    match = MARKER.match(line.strip())
                    if match:
                        current = match.group(2)
                    batch.append((line.rstrip("\r\n"), current, current, number))
                    if len(batch) >= 5000:
                        db.executemany("INSERT INTO source_lines(text,entry,address,line) VALUES (?,?,?,?)", batch)
                        batch.clear()
            if batch:
                db.executemany("INSERT INTO source_lines(text,entry,address,line) VALUES (?,?,?,?)", batch)
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('sha256',?)", (fingerprint,))
            db.commit()
        count = db.execute("SELECT count(*) FROM source_lines").fetchone()[0]
        return {"path": str(index), "sha256": fingerprint, "lines": count}
    finally:
        if 'db' in locals():
            db.close()


def search_index(folder: Path, query: str, limit: int = 400, source_name: str = "rea-pseudocode.c") -> list[dict]:
    if not query.strip():
        return []
    build_source_index(folder, source_name)
    db = sqlite3.connect(Path(folder) / (source_name + ".search-v2.sqlite"))
    try:
        needle = query.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = db.execute("SELECT entry,address,line,text FROM source_lines WHERE text LIKE ? ESCAPE '\\' LIMIT ?",
                          ("%" + needle + "%", max(1, min(limit, 5000)))).fetchall()
        return [{"entry": row[0].removeprefix("0x"), "address": row[1], "line": str(row[2]),
                 "text": row[3][:300]} for row in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        db.close()


def line_address(folder: Path, line: int, source_name: str = "rea-pseudocode.c") -> dict:
    build_source_index(folder, source_name)
    db = sqlite3.connect(Path(folder) / (source_name + ".search-v2.sqlite"))
    try:
        row = db.execute("SELECT address,text FROM source_lines WHERE line=?", (int(line),)).fetchone()
        if row is None:
            raise ValueError("Source line does not exist")
        # A procedure marker is an exact entry address. Other source lines have only
        # a procedure-level anchor, so the UI must not imply instruction precision.
        exact = bool(MARKER.match(row[1].strip()))
        return {"line": int(line), "address": row[0], "precision": "exact_entry" if exact else "procedure_entry",
                "source": source_name}
    finally:
        db.close()


def disagreement_heatmap(folder: Path) -> list[dict]:
    """Prioritize visible differences; these heuristics do not decide correctness."""
    folder = Path(folder)
    ghidra = folder / "pseudocode.c"
    ghidra_text = ghidra.read_text(encoding="utf-8", errors="replace") if ghidra.is_file() else ""
    markers = list(re.finditer(r"(?im)^/\* ===== .+ @ (?:0x)?([0-9a-f]+) ===== \*/$", ghidra_text))
    peers = {match.group(1).lower().lstrip("0") or "0":
             ghidra_text[match.end():markers[index + 1].start() if index + 1 < len(markers) else len(ghidra_text)]
             for index, match in enumerate(markers)}
    rows = []
    for row in coverage_rows(folder):
        code = row["pseudocode"]
        address = row["address"].lower().removeprefix("0x")
        peer = peers.get(address.lstrip("0") or "0", "")
        tokens = lambda value: set(re.findall(r"[A-Za-z_][A-Za-z_0-9]{2,}", value.casefold()))
        left, right = tokens(code), tokens(peer)
        overlap = len(left & right) / len(left | right) if left or right else 0.0
        missing = not code or not peer
        score = 1.0 if missing else round(1.0 - overlap, 3)
        rows.append({"address": row["address"], "name": row["name"], "score": score,
                     "rea_present": bool(code), "ghidra_present": bool(peer),
                     "label": "missing export" if missing else "token difference",
                     "precision": "heuristic token overlap; manually verify control flow"})
    return sorted(rows, key=lambda item: item["score"], reverse=True)


def review_priority(folder: Path) -> list[dict]:
    """Rank uncovered/high-interest code so analysts can scope review."""
    signals = ("memcpy", "strcpy", "sprintf", "recv", "read", "exec", "system", "CreateProcess", "VirtualAlloc")
    result = []
    for row in coverage_rows(folder):
        hits = [word for word in signals if word.casefold() in row["pseudocode"].casefold()]
        score = (3 if row["status"] != "ok" else 0) + (2 if row["confidence"] == "low" else 0) + min(5, len(hits))
        result.append({"address": row["address"], "name": row["name"], "score": score,
                       "status": row["status"], "confidence": row["confidence"], "signals": hits,
                       "basis": "coverage and API-name cues; not a vulnerability verdict"})
    return sorted(result, key=lambda item: (-item["score"], item["name"]))


def evidence_freshness(folder: Path, report: dict, evidence: dict) -> str:
    from castorpollux_workspace import review_is_stale
    if review_is_stale(folder, report):
        return "STALE"
    name = str(evidence.get("file", ""))
    if not name or Path(name).is_absolute() or ".." in Path(name).parts:
        return "UNVERIFIED"
    return "CURRENT" if (Path(folder) / name).is_file() else "MISSING"


def confidence_calibration(corpus_path: Path, folders: list[Path]) -> dict:
    measured = evaluate_corpus(corpus_path, folders)
    total = measured["cases_evaluated"]
    metrics = measured["metrics"]
    cases = {item.get("sha256"): item for item in load_corpus(corpus_path)["cases"] if item.get("complete")}
    bins = {}
    for folder in folders:
        folder = Path(folder)
        try:
            manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
            case = cases.get(manifest.get("sha256"))
            if not case:
                continue
            report = json.loads((folder / "security-review-data.json").read_text(encoding="utf-8"))
            expected = {item.get("signature") for item in case.get("expected", [])}
            for finding in report.get("result", {}).get("findings", []):
                label = str(finding.get("confidence", "unknown")).casefold()
                bucket = bins.setdefault(label, {"observed": 0, "confirmed": 0})
                bucket["observed"] += 1
                bucket["confirmed"] += int(finding_signature(finding) in expected)
        except (OSError, ValueError, TypeError):
            continue
    for bucket in bins.values():
        bucket["observed_precision"] = round(bucket["confirmed"] / bucket["observed"], 3) if bucket["observed"] else None
        bucket["sample_sufficient"] = bucket["observed"] >= 10
    return {"cases": total, "complete_cases": measured["complete_cases"],
            "precision": metrics["precision"], "recall": metrics["recall"],
            "confidence_bins": bins, "calibrated": measured["complete_cases"] >= 10 and bool(bins) and
            all(item["sample_sufficient"] for item in bins.values()),
            "note": "Observed precision by reported confidence label on adjudicated complete cases. "
                    "Ten complete cases and ten findings per reported bin are required before labeling calibrated; "
                    "selection and finding-identity heuristics can bias these estimates."}


def patch_checklist(folder: Path, comparison: dict) -> dict:
    changed = comparison.get("functions", {}).get("changed", [])
    items = []
    for item in changed[:500]:
        name = item.get("function", item.get("name", item.get("address", str(item)))) if isinstance(item, dict) else str(item)
        items.append({"function": name, "old_entry": item.get("old_entry") if isinstance(item, dict) else None,
                      "new_entry": item.get("new_entry") if isinstance(item, dict) else None,
                      "checks": ["Confirm changed control-flow and bounds checks in pseudocode and disassembly",
                                                    "Re-run static flow and call-path evidence",
                                                    "Exercise authorized regression inputs and compare observations",
                                                    "Re-review related findings and record evidence"]})
    changed_edges = {direction: comparison.get("calls", {}).get(direction, [])[:500]
                     for direction in ("added", "removed")}
    affected_findings = [item for item in comparison.get("patch_impact", {}).get("findings", [])
                         if item.get("relation") in {"cited function changed", "called function changed", "caller changed"}]
    result = {"created_at": datetime.now(timezone.utc).isoformat(), "items": items,
              "changed_call_edges": changed_edges, "affected_findings": affected_findings,
              "flow_checks": ["Validate added call edges and removed validation or sanitizer calls",
                              "Re-run source-to-sink tracking for affected finding call paths",
                              "Compare authorized regression observations with the prior build"],
              "limitation": "Checklist is generated from changed functions, call edges, and finding impact paths; completion requires analyst verification."}
    (Path(folder) / "patch-verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
