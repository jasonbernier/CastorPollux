"""Persistent application and investigation error events."""

from __future__ import annotations

import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_core import home


def record_error(message: str, folder: Path | None = None, stage: str = "application",
                 detail: str = "") -> dict:
    event = {"time": datetime.now(timezone.utc).isoformat(), "stage": stage,
             "message": str(message), "detail": detail[-12000:]}
    targets = [home() / "Logs" / "castorpollux-errors.jsonl"]
    if folder:
        targets.append(Path(folder) / "errors.jsonl")
    for target in targets:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError:
            pass
    return event


def classify_ghidra_failure(manifest: dict) -> str:
    if manifest.get("ghidra_status") not in {"failed", "partial"}:
        return ""
    reason = str(manifest.get("ghidra_failure_reason", "")).casefold()
    if any(term in reason for term in ("script error", "scriptloadexception", "source bundle", "class could not be found")):
        return "script load"
    if any(term in reason for term in ("java_home", "unsupportedclassversion", "java runtime", "jdk")):
        return "Java runtime"
    if any(term in reason for term in ("outofmemory", "memory limit", "heap space")):
        return "memory"
    if any(term in reason for term in ("timeout", "timed out")):
        return "timeout"
    if any(term in reason for term in ("access denied", "permission denied", "createprocess")):
        return "access"
    if any(term in reason for term in ("unsupported", "not a valid", "failed to import")):
        return "binary import"
    return "unclassified"


def _redact_diagnostic(text: str) -> str:
    text = re.sub(r"(?i)\b(?:[A-Z]:\\|\\\\)[^\s\"']+", "[LOCAL_PATH]", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL]", text)
    text = re.sub(r"(?i)(bearer\s+)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(password|token|api[_-]?key|secret)(\s*[=:]\s*)[^\s,}\]]+",
                  r"\1\2[REDACTED]", text)
    return text


def export_diagnostics(folder: Path, destination: Path) -> Path:
    """Export bounded, redacted diagnostics; never include binary or source evidence."""
    folder, destination = Path(folder).resolve(), Path(destination).resolve()
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if destination.parent == folder or folder in destination.parents:
        raise ValueError("Save the diagnostic ZIP outside the investigation folder")
    names = ("ghidra.log", "rea.log", "rea-decompile.log", "errors.jsonl")
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        snapshot = dict(manifest)
        snapshot.pop("input_path", None)
        snapshot.pop("saved_binary", None)
        archive.writestr("manifest-redacted.json", _redact_diagnostic(json.dumps(snapshot, indent=2)))
        summary = {"ghidra": manifest.get("ghidra_status"),
                   "ghidra_failure_class": classify_ghidra_failure(manifest),
                   "rea": manifest.get("rea_status"), "rea_decompile": manifest.get("rea_decompile_status"),
                   "coverage": manifest.get("rea_decompile_counts", {}),
                   "review_saved": (folder / "security-review-data.json").is_file()}
        archive.writestr("diagnostic-summary.json", json.dumps(summary, indent=2))
        for name in names:
            path = folder / name
            if path.is_file():
                archive.writestr(name, _redact_diagnostic(path.read_text(encoding="utf-8", errors="replace")[-500000:]))
        attempts = folder / "GhidraAttempts"
        if attempts.is_dir():
            for path in sorted(attempts.glob("*.log"))[-20:]:
                archive.writestr("GhidraAttempts/" + path.name,
                                 _redact_diagnostic(path.read_text(encoding="utf-8", errors="replace")[-500000:]))
    return destination
