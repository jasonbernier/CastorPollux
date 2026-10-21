"""Declarative extension points; plugin files never execute code."""

from __future__ import annotations

import json
import re
from pathlib import Path

from castorpollux_core import home

PLUGIN_ID = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
RULE_NAME = re.compile(r"^[A-Za-z_]\w{0,99}$")
SAMPLE = {
    "schema": 1, "id": "example-policy", "version": "1.0", "enabled": False,
    "flow": {"sources": [{"name": "MyInputApi", "output": 0}],
             "sinks": ["MyRiskyApi"],
             "sanitizers": [{"name": "MySanitizer", "output": "return"}]},
    "review_guidance": "Check whether MyRiskyApi receives input without MySanitizer.",
    "report_template": "# {{plugin_id}} review of {{target}}\n\n{{summary}}\n\n{{findings}}\n",
}


def plugin_dir() -> Path:
    return home() / "Plugins"


def validate_plugin(data: dict) -> dict:
    if not isinstance(data, dict) or data.get("schema") != 1 or not PLUGIN_ID.fullmatch(str(data.get("id", ""))):
        raise ValueError("Plugin needs schema 1 and a simple id")
    if not isinstance(data.get("enabled"), bool):
        raise ValueError("Plugin enabled must be true or false")
    flow = data.get("flow", {})
    if not isinstance(flow, dict):
        raise ValueError("Plugin flow must be an object")
    for category in ("sources", "sinks", "sanitizers"):
        items = flow.get(category, [])
        if not isinstance(items, list) or len(items) > 100:
            raise ValueError(f"Plugin {category} must be a list of at most 100 rules")
        for item in items:
            name = item if isinstance(item, str) else item.get("name") if isinstance(item, dict) else None
            if not isinstance(name, str) or not RULE_NAME.fullmatch(name):
                raise ValueError(f"Plugin {category} contains an invalid API name")
            if isinstance(item, dict) and item.get("output", "return") != "return" and \
                    (not isinstance(item.get("output"), int) or not 0 <= item["output"] <= 32):
                raise ValueError("Rule output must be 'return' or a zero-based argument index")
    for field, limit in (("review_guidance", 4000), ("report_template", 20000)):
        if not isinstance(data.get(field, ""), str) or len(data.get(field, "")) > limit:
            raise ValueError(f"Plugin {field} must be text under {limit} characters")
    return data


def load_plugins(directory: Path | None = None) -> list[dict]:
    directory = Path(directory or plugin_dir())
    if not directory.is_dir():
        return []
    plugins = []
    seen = set()
    for path in sorted(directory.glob("*.json")):
        data = validate_plugin(json.loads(path.read_text(encoding="utf-8")))
        if data["id"] in seen:
            raise ValueError(f"Duplicate plugin id: {data['id']}")
        seen.add(data["id"])
        if data["enabled"]:
            plugins.append({**data, "path": str(path)})
    return plugins


def create_sample(directory: Path | None = None) -> Path:
    directory = Path(directory or plugin_dir())
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "example-policy.json"
    if not path.exists():
        path.write_text(json.dumps(SAMPLE, indent=2), encoding="utf-8")
    return path


def plugin_guidance(plugins: list[dict]) -> str:
    sections = [f"{item['id']}: {item['review_guidance'].strip()}" for item in plugins
                if item.get("review_guidance", "").strip()]
    return "\nOrganization review checks (apply only when the saved evidence supports them):\n" + \
           "\n".join(sections) if sections else ""


def render_templates(folder: Path, envelope: dict, plugins: list[dict]) -> list[str]:
    result = envelope["result"]
    findings = "\n".join(f"- **{item.get('severity', '').upper()}** {item.get('title', '')}: "
                         f"{item.get('description', '')}" for item in result["findings"]) or "No findings."
    names = []
    for item in plugins:
        template = item.get("report_template", "")
        if not template:
            continue
        values = {"plugin_id": item["id"], "target": envelope["target"]["input_name"],
                  "sha256": envelope["target"]["sha256"], "summary": result["summary"],
                  "findings": findings, "date": envelope["created_at"]}
        rendered = re.sub(r"\{\{([a-z_]+)\}\}", lambda match: values.get(match.group(1), match.group()), template)
        name = f"security-report-plugin-{item['id']}.md"
        (Path(folder) / name).write_text(rendered, encoding="utf-8")
        names.append(name)
    return names
