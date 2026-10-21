"""Static overflow triage with bounded boundary inputs; execution remains analyst controlled."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_review import coverage_rows


ARRAY = re.compile(r"\b(?:char|byte|uchar|uint8_t|undefined1)\s+(\w+)\s*\[\s*(\d{1,6})\s*\]")
COPY = re.compile(r"\b(strcpy|strcat|gets|sprintf|vsprintf|memcpy|memmove|strncpy|snprintf)\s*\((.*)\)", re.I)


def scan_overflows(folder: Path) -> dict:
    folder = Path(folder)
    leads = []
    for procedure in coverage_rows(folder):
        if procedure.get("status") != "ok":
            continue
        code = procedure.get("pseudocode", "")
        arrays = {name: int(size) for name, size in ARRAY.findall(code) if 0 < int(size) <= 65536}
        for line_number, line in enumerate(code.splitlines(), 1):
            match = COPY.search(line)
            if not match:
                continue
            api, args = match.groups()
            destination = args.split(",", 1)[0].strip().lstrip("&*")
            capacity = arrays.get(destination)
            if capacity is None and api.lower() not in {"gets", "strcpy", "strcat", "sprintf", "vsprintf"}:
                continue
            size_argument = args.split(",")[-1].strip() if api.lower() in {"memcpy", "memmove", "strncpy", "snprintf"} else ""
            numeric = int(size_argument, 0) if re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+)", size_argument) else None
            relation = ("constant_copy_exceeds_capacity" if capacity and numeric and numeric > capacity else
                        "unbounded_copy_into_fixed_array" if capacity and api.lower() in {"strcpy", "strcat", "gets", "sprintf", "vsprintf"} else
                        "needs_bounds_review")
            leads.append({"function": procedure.get("name", ""), "function_entry": procedure.get("address", ""),
                          "line": line_number, "api": api, "destination": destination,
                          "observed_capacity": capacity, "size_argument": size_argument,
                          "constant_size": numeric, "relation": relation,
                          "pseudocode": line.strip()[:500], "confidence": "medium" if capacity and numeric else "low",
                          "verification": "static_candidate", "evidence_file": "rea-pseudocode.c"})
            if len(leads) >= 1000:
                break
        if len(leads) >= 1000:
            break
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "leads": leads,
              "count": len(leads), "limitations": ["Decompiler arrays and calls can be inferred incorrectly; no overflow is proven.",
                                                 "A buffer size alone does not establish attacker control or reachable input.",
                                                 "Use isolated runtime validation and crash-to-pseudocode linking before reporting."]}
    (folder / "overflow-leads.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def create_boundary_inputs(folder: Path, lead_index: int) -> dict:
    folder = Path(folder)
    report = json.loads((folder / "overflow-leads.json").read_text(encoding="utf-8"))
    leads = report.get("leads", [])
    if not 0 <= lead_index < len(leads):
        raise ValueError("Select an overflow lead")
    lead = leads[lead_index]
    capacity = lead.get("observed_capacity")
    if not isinstance(capacity, int) or not 1 <= capacity <= 4096:
        raise ValueError("A fixed array capacity of 1–4096 bytes is required for bounded test inputs")
    target = folder / "proofs-of-concept" / f"boundary-{lead_index:04d}"
    target.mkdir(parents=True, exist_ok=True)
    cases = []
    for name, length in (("below", max(0, capacity - 1)), ("at", capacity), ("above", capacity + 1)):
        payload = b"A" * length
        destination = target / f"{name}-{length}.bin"
        destination.write_bytes(payload)
        cases.append({"case": name, "length": length, "file": str(destination.relative_to(folder)),
                      "sha256": hashlib.sha256(payload).hexdigest(), "execution_status": "not_run"})
    result = {"created_at": datetime.now(timezone.utc).isoformat(), "lead": lead,
              "cases": cases, "verified_reproducer": False,
              "instructions": "In an isolated test environment, supply each file through the actual input channel, compare behavior, and save crash logs. These generic bytes may not satisfy the target's input format.",
              "sandbox_status": "UNTESTED", "limitations": ["No target binary was executed.",
                                                           "Boundary inputs are candidates, not proof of a crash or exploit."]}
    (target / "reproduction-plan.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
