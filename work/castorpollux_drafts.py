"""Bounded, passive autosave for CastorPollux form drafts.

Drafts contain form choices and local paths. They never contain binaries, review
evidence, agent prompts, credentials, or additional cloud redaction literals.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_core import home


MAX_DRAFT_BYTES = 262144
FORMAT_NAMES = ("json", "md", "html", "csv", "pdf", "sarif")
AGENTS = {"none", "codex", "claude", "opencode", "ollama"}
TEXT_FIELDS = {
    "analyze": {"input_path": 4096, "output_path": 4096, "symbol_path": 4096,
                "symbol_server": 2048, "review_agent": 32},
    "review": {"review_folder": 4096, "codex_cli_path": 4096, "local_model": 256,
               "scope_mode": 32, "scope_selection": 8192, "coverage_minimum": 8,
               "retdec_path": 4096},
    "batch": {"batch_agent": 32},
    "settings": {"theme_choice": 64, "font_scale_choice": 8, "layout_choice": 64,
                 "notification_min_seconds": 8, "allowed_servers": 8192,
                 "cache_days": 8, "cache_mb": 8},
}
BOOL_FIELDS = {
    "analyze": {"symbol_server_enabled", "daybreak_blue"},
    "review": {"secondary_decompiler", "redact_cloud"},
    "settings": {"desktop_notifications", "restore_tabs_choice"},
}


def drafts_path() -> Path:
    return home() / "form-drafts.json"


def sanitize_drafts(value: object) -> dict:
    """Keep only recognized, size-bounded passive fields from untrusted JSON."""
    if not isinstance(value, dict):
        return {}
    cleaned = {}
    for section, text_fields in TEXT_FIELDS.items():
        raw = value.get(section)
        if not isinstance(raw, dict):
            continue
        row = {}
        for key, limit in text_fields.items():
            item = raw.get(key)
            if isinstance(item, str) and len(item) <= limit and "\x00" not in item:
                if key in {"review_agent", "batch_agent"} and item not in AGENTS:
                    continue
                if key == "review_agent" and item == "none":
                    continue
                if key == "scope_mode" and item not in {"all", "functions", "modules"}:
                    continue
                row[key] = item
        for key in BOOL_FIELDS.get(section, ()):
            if type(raw.get(key)) is bool:
                row[key] = raw[key]
        if section == "review":
            formats = raw.get("report_formats")
            if isinstance(formats, dict):
                row["report_formats"] = {key: formats[key] for key in FORMAT_NAMES
                                         if type(formats.get(key)) is bool}
        if section == "batch":
            sources = raw.get("sources")
            if isinstance(sources, list) and len(sources) <= 500:
                row["sources"] = list(dict.fromkeys(path for path in sources
                    if isinstance(path, str) and len(path) <= 4096 and "\x00" not in path))
        if section == "settings":
            limits = raw.get("engine_limits")
            if isinstance(limits, dict):
                row["engine_limits"] = {key: limits[key] for key in
                    ("ghidra_timeout_seconds", "rea_timeout_seconds", "ghidra_heap_mb", "rea_heap_mb")
                    if isinstance(limits.get(key), str) and len(limits[key]) <= 8}
            shortcuts = raw.get("shortcuts")
            if isinstance(shortcuts, dict) and len(shortcuts) <= 20:
                from castorpollux_settings import SHORTCUT_ACTIONS
                row["shortcuts"] = {key: shortcuts[key] for key in SHORTCUT_ACTIONS
                                    if isinstance(shortcuts.get(key), str) and len(shortcuts[key]) <= 48}
        if row:
            cleaned[section] = row
    return cleaned


def load_drafts() -> dict:
    path = drafts_path()
    try:
        if path.stat().st_size > MAX_DRAFT_BYTES:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("format_version") != 1:
            return {}
        return sanitize_drafts(payload.get("forms"))
    except (OSError, UnicodeError, ValueError):
        return {}


def save_drafts(forms: dict) -> dict:
    cleaned = sanitize_drafts(forms)
    for section, fields in TEXT_FIELDS.items():
        raw = forms.get(section, {}) if isinstance(forms, dict) else {}
        if not isinstance(raw, dict):
            continue
        for key in fields:
            if key in raw and key not in cleaned.get(section, {}):
                raise ValueError(f"{section}.{key} cannot be autosaved; shorten or correct this field")
    payload = {"format_version": 1, "saved_at": datetime.now(timezone.utc).isoformat(),
               "forms": cleaned}
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_DRAFT_BYTES:
        raise ValueError("Form drafts exceed the local storage limit")
    path = drafts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix="form-drafts-", suffix=".tmp",
                                         dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return cleaned
