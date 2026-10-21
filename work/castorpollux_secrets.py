"""Bounded, redacted static secret leads from saved REA evidence."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


PATTERNS = (
    ("AWS access key ID", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Private key header", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("GitHub token", "high", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("Credential assignment", "medium", re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|secret|token)\b\s*[:=]\s*[\"']([^\"'\r\n]{8,})[\"']")),
)


def _lead(label: str, confidence: str, value: str, filename: str, line: int) -> dict:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
    return {"type": label, "confidence": confidence, "file": filename, "line": line,
            "value_sha256": digest, "preview": value[:3] + "…" + value[-3:] if len(value) > 8 else "[REDACTED]",
            "note": "Static evidence only. Verify whether this is an active credential before response."}


def scan_secrets(folder: Path, max_bytes: int = 32 * 1024 * 1024) -> dict:
    folder = Path(folder)
    leads = []
    seen = set()
    for filename in ("rea-pseudocode.c", "strings.csv", "pseudocode.c"):
        path = folder / filename
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
            consumed = 0
            for line_number, line in enumerate(stream, 1):
                consumed += len(line.encode("utf-8", "replace"))
                if consumed > max_bytes or len(leads) >= 500:
                    break
                for label, confidence, pattern in PATTERNS:
                    for match in pattern.finditer(line):
                        value = match.group(1) if match.lastindex else match.group(0)
                        if value.casefold() in {"password", "changeme", "example123", "placeholder"}:
                            continue
                        lead = _lead(label, confidence, value, filename, line_number)
                        key = (lead["value_sha256"], filename)
                        if key not in seen:
                            seen.add(key)
                            leads.append(lead)
    report = {"created_at": datetime.now(timezone.utc).isoformat(), "leads": leads,
              "count": len(leads), "limitations": "Regex leads can include test values and miss encoded or constructed secrets. Values are never written in full to this report."}
    (folder / "secret-evidence.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
