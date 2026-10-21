"""Local CastorPollux preferences and symbol-server policy."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from castorpollux_core import home


THEMES = {
    "High Contrast": {"bg": "#000000", "sidebar": "#050505", "card": "#101010", "field": "#191919", "line": "#FFFFFF", "text": "#FFFFFF", "muted": "#E0E0E0", "accent": "#FFFF00", "secondary": "#00FFFF", "danger": "#FF6B6B"},
    "Daylight": {"bg": "#F3F7F8", "sidebar": "#E6EFF1", "card": "#FFFFFF", "field": "#EAF2F3", "line": "#B7CDD1", "text": "#173039", "muted": "#526D75", "accent": "#087F70", "secondary": "#096D9A", "danger": "#B33143"},
    "Midnight": {"bg": "#071017", "sidebar": "#0B171F", "card": "#10212B", "field": "#152B36", "line": "#24414A", "text": "#EDF8F5", "muted": "#91AAA9", "accent": "#83F7BA", "secondary": "#53CFE0", "danger": "#FF7B84"},
    "Obsidian": {"bg": "#101015", "sidebar": "#17171E", "card": "#20212A", "field": "#292B35", "line": "#3D414C", "text": "#F5F5F7", "muted": "#A6A8B2", "accent": "#B8A7FF", "secondary": "#81D3F0", "danger": "#FF8799"},
    "Phosphor": {"bg": "#071008", "sidebar": "#0D1A0F", "card": "#142517", "field": "#1B3020", "line": "#34513A", "text": "#E8FFE9", "muted": "#A0C5A4", "accent": "#92F59C", "secondary": "#B5E889", "danger": "#FF8B80"},
    "Arctic": {"bg": "#0B1624", "sidebar": "#112238", "card": "#182C43", "field": "#213950", "line": "#365873", "text": "#F0F7FF", "muted": "#A9C0D4", "accent": "#8DDCFF", "secondary": "#A4B8FF", "danger": "#FF98A0"},
    "Ember": {"bg": "#18110F", "sidebar": "#251915", "card": "#30211B", "field": "#3D2A22", "line": "#644338", "text": "#FFF4EC", "muted": "#D0B2A3", "accent": "#FFB86B", "secondary": "#F4D28B", "danger": "#FF8B8B"},
    "Slate": {"bg": "#172027", "sidebar": "#1F2A32", "card": "#293741", "field": "#32434D", "line": "#4B626B", "text": "#F4F9FA", "muted": "#BCD0D2", "accent": "#88D8CB", "secondary": "#9FBFE9", "danger": "#FF9B9E"},
}

DEFAULT_LAYOUTS = {"Balanced": 0.36, "Code focus": 0.25, "Results focus": 0.55}
SHORTCUT_ACTIONS = {
    "Command palette": "<Control-k>", "Browse binary": "<Control-o>",
    "Browse output": "<Control-Shift-O>", "Analyze": "<Control-Return>",
    "Analyze and review": "<Control-Shift-Return>", "Batch jobs": "<Control-b>",
    "History": "<Control-h>", "Search activity": "<Control-f>",
    "Context help": "<F1>", "Cancel task": "<Escape>",
}


def shortcut_conflicts(shortcuts: dict) -> dict[str, list[str]]:
    """Return duplicate key sequences, irrespective of spelling or modifier order."""
    groups: dict[str, list[str]] = {}
    for action, sequence in shortcuts.items():
        parts = sequence.strip("<>").casefold().split("-")
        key = parts[-1]
        canonical = "+".join(sorted(parts[:-1]) + [key])
        groups.setdefault(canonical, []).append(action)
    return {key: actions for key, actions in groups.items() if len(actions) > 1}


def validate_shortcuts(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(SHORTCUT_ACTIONS):
        raise ValueError("Shortcut settings must contain every supported action")
    result = {}
    for action, raw in value.items():
        if not isinstance(raw, str) or len(raw) > 48 or not re.fullmatch(
                r"<(?:(?:Control|Shift|Alt)-)*(?:[A-Za-z0-9]|Return|Escape|F(?:[1-9]|1[0-2]))>", raw):
            raise ValueError(f"Invalid shortcut for {action}; use a Tk key sequence such as <Control-k>")
        parts = raw[1:-1].split("-")
        modifiers = [part.casefold() for part in parts[:-1]]
        if len(modifiers) != len(set(modifiers)) or (not modifiers and parts[-1].casefold() not in
                                                    {"escape", *(f"f{number}" for number in range(1, 13))}):
            raise ValueError(f"Shortcut for {action} needs a modifier or a function key")
        result[action] = raw
    conflicts = shortcut_conflicts(result)
    if conflicts:
        raise ValueError("Shortcut conflict: " + "; ".join(
            ", ".join(actions) for actions in conflicts.values()))
    return result

DEFAULT = {"theme": "Midnight", "symbol_servers": ["https://msdl.microsoft.com/download/symbols",
                                                   "https://debuginfod.elfutils.org"],
           "symbol_cache_days": 30, "symbol_cache_mb": 512,
           "ghidra_timeout_seconds": 1800, "rea_timeout_seconds": 1800,
           "ghidra_heap_mb": 2048, "rea_heap_mb": 2048,
           "desktop_notifications": False, "notification_min_seconds": 60,
           "font_scale": 100, "restore_tabs": False, "layout_presets": DEFAULT_LAYOUTS,
           "active_layout": "Balanced", "shortcuts": SHORTCUT_ACTIONS}


def settings_path() -> Path:
    return home() / "settings.json"


def load_settings() -> dict:
    try:
        path = settings_path()
        if path.stat().st_size > 65536:
            raise ValueError("Settings file is too large")
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stored = {}
    result = {**DEFAULT, **(stored if isinstance(stored, dict) else {})}
    try:
        return validate_settings(result)
    except (TypeError, ValueError):
        return validate_settings(DEFAULT)


def validate_settings(data: dict) -> dict:
    if data.get("theme") not in THEMES:
        raise ValueError("Choose one of the available themes")
    servers = data.get("symbol_servers")
    if not isinstance(servers, list) or not servers or len(servers) > 20:
        raise ValueError("Enter one to twenty approved symbol server URLs")
    normalized = []
    for raw in servers:
        if not isinstance(raw, str):
            raise ValueError("Symbol server URLs must be text")
        server = raw.strip().rstrip("/")
        parsed = urlparse(server)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Symbol servers must be HTTPS URLs without credentials or query strings")
        normalized.append(server)
    days, megabytes = int(data.get("symbol_cache_days", 30)), int(data.get("symbol_cache_mb", 512))
    if not 0 <= days <= 365 or not 0 <= megabytes <= 4096:
        raise ValueError("Cache controls require 0–365 days and 0–4096 MiB")
    limits = {}
    for key, low, high in (("ghidra_timeout_seconds", 60, 14400), ("rea_timeout_seconds", 60, 14400),
                           ("ghidra_heap_mb", 512, 16384), ("rea_heap_mb", 512, 16384)):
        value = int(data.get(key, DEFAULT[key]))
        if not low <= value <= high:
            raise ValueError(f"{key} must be {low}–{high}")
        limits[key] = value
    notice_seconds = int(data.get("notification_min_seconds", 60))
    if not 10 <= notice_seconds <= 3600:
        raise ValueError("Notification threshold must be 10–3600 seconds")
    font_scale = int(data.get("font_scale", 100))
    if not 85 <= font_scale <= 150:
        raise ValueError("Text size must be between 85% and 150%")
    raw_presets = data.get("layout_presets", DEFAULT_LAYOUTS)
    if not isinstance(raw_presets, dict) or len(raw_presets) > 20:
        raise ValueError("At most twenty layout presets are supported")
    presets = dict(DEFAULT_LAYOUTS)
    for name, raw_ratio in raw_presets.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,31}", name):
            raise ValueError("Layout names must be 1–32 plain characters")
        ratio = float(raw_ratio)
        if not 0.2 <= ratio <= 0.8:
            raise ValueError("Layout split must be between 20% and 80%")
        presets[name] = round(ratio, 3)
    active_layout = data.get("active_layout", "Balanced")
    if active_layout not in presets:
        active_layout = "Balanced"
    shortcuts = validate_shortcuts(data.get("shortcuts", SHORTCUT_ACTIONS))
    return {"theme": data["theme"], "symbol_servers": list(dict.fromkeys(normalized)),
            "symbol_cache_days": days, "symbol_cache_mb": megabytes, **limits,
            "desktop_notifications": bool(data.get("desktop_notifications", False)),
            "notification_min_seconds": notice_seconds, "font_scale": font_scale,
            "restore_tabs": bool(data.get("restore_tabs", False)),
            "layout_presets": presets, "active_layout": active_layout, "shortcuts": shortcuts}


def save_settings(data: dict) -> dict:
    result = validate_settings(data)
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return result


def approved_server(server: str, settings: dict | None = None) -> str:
    value = server.strip().rstrip("/")
    policy = settings or load_settings()
    if value not in policy["symbol_servers"]:
        raise ValueError("Symbol server is not on the Settings allowlist")
    return value


def workspace_path() -> Path:
    return home() / "workspace.json"


WORKSPACE_TABS = {"analyze": {"Target", "Options", "Activity"},
                  "dashboards": {"Overview", "Performance", "Resources", "Quality"},
                  "settings": {"Appearance", "Symbols", "Engines", "Shortcuts"}}


def load_workspace(pages: set[str], known_folders: set[Path]) -> dict:
    """Restore only passive UI selections; never execute a saved command."""
    try:
        path = workspace_path()
        if path.stat().st_size > 16384:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
    except (OSError, ValueError):
        return {}
    result = {}
    page = data.get("page")
    if isinstance(page, str) and page in pages:
        result["page"] = page
    folder = data.get("current_folder")
    if isinstance(folder, str) and len(folder) <= 4096:
        try:
            resolved = Path(folder).resolve()
            if resolved in known_folders and resolved.is_dir():
                result["current_folder"] = str(resolved)
        except (OSError, RuntimeError, ValueError):
            pass
    for key, file_required in (("input_path", True), ("output_path", False)):
        value = data.get(key)
        if isinstance(value, str) and len(value) <= 4096:
            try:
                candidate = Path(value).resolve()
                exists = candidate.is_file() if file_required else candidate.is_dir()
                if exists:
                    result[key] = str(candidate)
            except (OSError, RuntimeError, ValueError):
                pass
    tabs = data.get("tabs")
    if isinstance(tabs, dict):
        result["tabs"] = {key: value for key, value in tabs.items()
                          if key in WORKSPACE_TABS and isinstance(value, str)
                          and value in WORKSPACE_TABS[key]}
    return result


def save_workspace(data: dict) -> None:
    path = workspace_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {key: str(data.get(key, ""))[:4096] for key in
              ("page", "current_folder", "input_path", "output_path")}
    tabs = data.get("tabs", {})
    record["tabs"] = ({key: value for key, value in tabs.items()
                       if key in WORKSPACE_TABS and isinstance(value, str)
                       and value in WORKSPACE_TABS[key]} if isinstance(tabs, dict) else {})
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
