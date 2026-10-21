"""Validate and export agent-suggested, never-automatically-run Python candidates."""

from __future__ import annotations

import ast
import re
from pathlib import Path


def check_candidate(finding: dict) -> dict | None:
    candidate = finding.get("proof_of_concept")
    if candidate is None:
        return None
    if not isinstance(candidate, dict) or candidate.get("status") not in {"candidate", "not_feasible"}:
        raise ValueError("Invalid proof-of-concept status")
    for field in ("python", "setup", "expected_observation", "limitations"):
        if not isinstance(candidate.get(field), str):
            raise ValueError(f"Proof-of-concept {field} must be text")
    if len(candidate["python"]) > 20000:
        raise ValueError("Python candidate exceeds the 20,000-character report limit")
    if candidate["status"] == "not_feasible" and candidate["python"].strip():
        raise ValueError("An infeasible proof of concept must not contain Python code")
    if candidate["status"] == "candidate" and not candidate["python"].strip():
        raise ValueError("A candidate proof of concept must contain Python code")
    if candidate["status"] == "candidate":
        try:
            ast.parse(candidate["python"])
            candidate["syntax_valid"] = True
        except SyntaxError as error:
            candidate["syntax_valid"] = False
            candidate["syntax_error"] = str(error)
    return candidate


def export_candidates(folder: Path, findings: list[dict]) -> list[str]:
    folder = Path(folder)
    names = []
    for number, finding in enumerate(findings, 1):
        candidate = check_candidate(finding)
        if not candidate or candidate["status"] != "candidate" or not candidate["syntax_valid"]:
            continue
        if not names:
            (folder / "proofs-of-concept").mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "-", str(finding.get("title", "finding")).lower()).strip("-")[:48]
        name = f"candidate-{number:02d}-{slug or 'finding'}.py"
        path = folder / "proofs-of-concept" / name
        path.write_text("# Agent-suggested, unverified local validation candidate.\n"
                        "# Inspect before running. CastorPollux never executes this file.\n\n" +
                        candidate["python"].rstrip() + "\n", encoding="utf-8")
        names.append(name)
    if names:
        (folder / "proofs-of-concept" / "README.md").write_text(
            "# Candidate Python proofs of concept\n\n"
            "These scripts were proposed by an agent from reconstructed binary pseudocode. "
            "They have not been run or verified by CastorPollux. Review the code and evidence before "
            "using one against a binary you are authorized to test in an isolated environment. "
            "The investigation's security report contains setup, expected observations, and limitations.\n",
            encoding="utf-8")
    return names
