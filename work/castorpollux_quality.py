"""Review quality gates, cloud evidence redaction, and independent decompiler checks."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from castorpollux_review import coverage_rows


def coverage_assessment(folder: Path, minimum_percent: int = 80, minimum_chars: int = 1000) -> dict:
    if not 0 <= minimum_percent <= 100:
        raise ValueError("Coverage threshold must be between 0 and 100 percent")
    rows = coverage_rows(folder)
    total = len(rows)
    succeeded = sum(row["status"] == "ok" and row["source_chars"] > 0 for row in rows)
    chars = sum(row["source_chars"] for row in rows if row["status"] == "ok")
    percent = round(100 * succeeded / total, 1) if total else 0.0
    reasons = []
    if percent < minimum_percent:
        reasons.append(f"Only {percent}% of procedures have reconstructed code (threshold {minimum_percent}%).")
    if chars < minimum_chars:
        reasons.append(f"Only {chars} reconstructed source characters are available (minimum {minimum_chars}).")
    return {"status": "warning" if reasons else "passed", "threshold_percent": minimum_percent,
            "minimum_chars": minimum_chars, "total": total, "succeeded": succeeded,
            "source_chars": chars, "coverage_percent": percent, "reasons": reasons}


_SENSITIVE = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b((?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*[\"']?)[^\s\"',;]{5,}"),
     r"\1[REDACTED]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
)


def redact_text(value: str, custom_terms: list[str] | None = None) -> tuple[str, int]:
    count = 0
    for pattern, replacement in _SENSITIVE:
        value, changed = pattern.subn(replacement, value)
        count += changed
    for term in dict.fromkeys(term.strip() for term in custom_terms or [] if term.strip()):
        value, changed = re.subn(re.escape(term), "[REDACTED_CUSTOM]", value, flags=re.IGNORECASE)
        count += changed
    return value, count


def redact_stage(stage: Path, custom_terms: list[str] | None = None) -> dict:
    """Modify staged text only; leave saved evidence untouched."""
    counts = {}
    for path in sorted(stage.iterdir()):
        if path.is_file() and path.suffix.lower() in {".json", ".csv", ".c", ".txt"}:
            original = path.read_text(encoding="utf-8-sig", errors="replace")
            revised, count = redact_text(original, custom_terms)
            if count:
                path.write_text(revised, encoding="utf-8")
                counts[path.name] = count
    return {"enabled": True, "replacements": counts,
            "total_replacements": sum(counts.values()), "custom_term_count": len(custom_terms or [])}


def stage_preview(stage: Path, max_chars: int = 35000) -> str:
    files = sorted(path for path in stage.iterdir() if path.is_file())
    lines = ["CLOUD AGENT EVIDENCE PREVIEW", "", "Files staged:"]
    lines.extend(f"  {path.name}  ({path.stat().st_size:,} bytes)" for path in files)
    lines += ["", "Staged text sample (the agent can read the full files):", ""]
    remaining = max_chars
    for path in files:
        if remaining <= 0:
            break
        if path.suffix.lower() not in {".json", ".csv", ".c", ".txt"}:
            continue
        sample = path.read_text(encoding="utf-8-sig", errors="replace")[:min(remaining, 7000)]
        lines.extend([f"--- {path.name} ---", sample, ""])
        remaining -= len(sample)
    if remaining <= 0:
        lines.append("Preview truncated. Full staged files are available to the selected agent.")
    return "\n".join(lines)


def find_retdec() -> Path | None:
    for name in ("retdec-decompiler.exe", "retdec-decompiler"):
        found = shutil.which(name)
        if found and Path(found).is_file():
            return Path(found)
    return None


def second_decompiler_check(folder: Path, findings: list[dict], executable: Path | None,
                            notify, cancelled, set_process) -> dict:
    """RetDec runs locally once for high findings; matching text is only comparison evidence."""
    high = [finding for finding in findings if finding.get("severity", "").lower() in {"high", "critical"}]
    if not high:
        return {"status": "not_needed", "engine": "RetDec", "findings": []}
    executable = Path(executable) if executable else find_retdec()
    if not executable or not executable.is_file():
        return {"status": "unavailable", "engine": "RetDec", "findings": [],
                "message": "Install RetDec and choose its CLI to compare high-severity findings."}
    binary = next((path for path in Path(folder).glob("source-binary*") if path.is_file() and
                   (path.name == "source-binary" or path.name.startswith("source-binary."))), None)
    if binary is None:
        return {"status": "unavailable", "engine": "RetDec", "findings": [],
                "message": "The saved source binary is unavailable."}
    if binary.stat().st_size > 100 * 1024 * 1024:
        return {"status": "skipped", "engine": "RetDec", "findings": [],
                "message": "Saved binary exceeds the 100 MiB secondary check limit."}
    output = Path(folder) / "retdec-secondary.c"
    log_path = Path(folder) / "retdec-secondary.log"
    notify("RetDec: independently decompiling for high-severity comparison…")
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen([str(executable), str(binary), "-o", str(output), "--cleanup"],
                                   stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        set_process(process)
        try:
            deadline = time.monotonic() + 300
            while process.poll() is None:
                if cancelled() or time.monotonic() >= deadline:
                    process.terminate()
                    raise InterruptedError("Secondary decompilation cancelled or timed out")
                time.sleep(0.25)
        finally:
            set_process(None)
    if process.returncode != 0 or not output.is_file():
        return {"status": "failed", "engine": "RetDec", "findings": [],
                "message": f"RetDec exited with code {process.returncode}; inspect retdec-secondary.log."}
    source = output.read_text(encoding="utf-8", errors="replace")
    comparisons = []
    for finding in high:
        terms = []
        for evidence in finding.get("evidence", []):
            location = str(evidence.get("location", ""))
            terms += re.findall(r"0x[0-9a-fA-F]{6,16}|(?:FUN|sub)_[0-9a-fA-F]{6,16}", location)
        match = next((re.search(re.escape(term), source, re.IGNORECASE) for term in terms
                      if re.search(re.escape(term), source, re.IGNORECASE)), None)
        comparisons.append({"title": finding.get("title", ""), "severity": finding.get("severity", ""),
                            "status": "matching_location_found" if match else "manual_comparison_needed",
                            "matched_term": match.group(0) if match else "",
                            "excerpt": source[max(0, match.start() - 400):match.end() + 800] if match else ""})
    return {"status": "completed", "engine": "RetDec", "output": output.name,
            "message": "A matching location does not confirm a vulnerability; compare both decompilations manually.",
            "findings": comparisons}
