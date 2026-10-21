"""Focused tests for flow, lineage, team triage, corpus, and target signing."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from castorpollux_flow import build_data_flow, trace_procedure
from castorpollux_review import finding_key, load_triage, save_triage
from castorpollux_tracking import add_confirmed_case, compare_findings, evaluate_corpus
from castorpollux_integrity import authenticode_status


code = """void test(void) {
 char *buf;
 char *copy;
 recv(sock,buf,128,0);
 copy = buf;
 strcpy(dst,copy);
 copy = safe;
 system(copy);
}"""
row = {"status": "ok", "name": "test", "address": "0x401000", "pseudocode": code}
leads = trace_procedure(row)
assert len(leads) == 1 and leads[0]["source_api"] == "recv" and leads[0]["sink_api"] == "strcpy"
assert leads[0]["variables"] == ["buf", "copy"]

with tempfile.TemporaryDirectory(prefix="castorpollux-v170-") as temp:
    root = Path(temp)
    older, newer = root / "older", root / "newer"
    older.mkdir(); newer.mkdir()
    for folder, digest in ((older, "a" * 64), (newer, "b" * 64)):
        (folder / "manifest.json").write_text(json.dumps({"sha256": digest, "input_name": "sample.exe"}), encoding="utf-8")
    (older / "rea-decompilation.json").write_text(json.dumps({"items": [{"address": "0x401000", "status": "ok",
        "procedure": {"name": "test"}, "pseudocode": code}]}), encoding="utf-8")
    flow = build_data_flow(older)
    assert len(flow["leads"]) == 1 and (older / "data-flow.json").is_file()
    recurring_old = {"title": "Unchecked copy at FUN_00401000", "severity": "high",
                     "evidence": [{"file": "rea-pseudocode.c", "location": "FUN_00401000"}]}
    recurring_new = {"title": "Unchecked copy at FUN_00501000", "severity": "high",
                     "evidence": [{"file": "rea-pseudocode.c", "location": "FUN_00501000"}]}
    resolved = {"title": "Old issue", "severity": "medium", "evidence": []}
    added = {"title": "New issue", "severity": "low", "evidence": []}
    for folder, findings in ((older, [recurring_old, resolved]), (newer, [recurring_new, added])):
        (folder / "security-review-data.json").write_text(json.dumps({"result": {"findings": findings}}), encoding="utf-8")
    tracked = compare_findings(older, newer)
    assert [len(tracked[key]) for key in ("recurring", "resolved", "new")] == [1, 1, 1]
    save_triage(older, recurring_old, "confirmed", "Reviewed evidence", "Alice", "Security")
    save_triage(older, recurring_old, "needs_more_evidence", "Retest", "Bob", "Research")
    assert load_triage(older)[finding_key(recurring_old)]["assignee"] == "Research"
    audit = [json.loads(line) for line in (older / "findings-audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(audit) == 2 and audit[1]["before"]["actor"] == "Alice" and audit[1]["actor"] == "Bob"
    save_triage(older, recurring_old, "confirmed", "Validated", "Alice")
    corpus = root / "corpus.json"
    case = add_confirmed_case(corpus, older, complete=True)
    assert case["complete"] and len(case["expected"]) == 1
    metrics = evaluate_corpus(corpus, [older])["metrics"]
    assert metrics["true_positives"] == 1 and metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 0 and metrics["precision"] == 0.5
    (older / "security-review-data.json").write_text(json.dumps({"result": {"findings": []}}), encoding="utf-8")
    metrics = evaluate_corpus(corpus, [older])["metrics"]
    assert metrics["false_negatives"] == 1 and metrics["recall"] == 0
    assert authenticode_status(root / "missing.exe")["status"] == "not_applicable"

print("Data flow, finding lineage, audit, corpus, and signature checks passed")
