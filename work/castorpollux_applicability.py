"""User-authored, evidence-only advisory build-configuration rules."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_binary_profile import _sample
from castorpollux_core import home


SAMPLE = {"schema": 1, "rules": [{"id": "example-disable-before-use", "enabled": False,
    "cve": "CVE-2099-0001", "library": "OpenSSL", "formats": ["PE"],
    "architectures": ["x86_64"], "optimization_levels": ["-O2", "-O3"],
    "required_binary_markers": ["EXAMPLE_FEATURE_ENABLED"],
    "excluded_binary_markers": ["EXAMPLE_FEATURE_DISABLED"],
    "note": "Replace this with an advisory-specific, independently checked build rule."}]}


def rules_path() -> Path:
    return home() / "advisory-applicability-rules.json"


def ensure_rules() -> Path:
    path = rules_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(json.dumps(SAMPLE, indent=2), encoding="utf-8")
    return path


def load_rules(path: Path | None = None) -> list[dict]:
    data = json.loads(Path(path or ensure_rules()).read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("rules"), list):
        raise ValueError("Advisory rules require schema 1 and a rules array")
    seen = set()
    for rule in data["rules"]:
        if not isinstance(rule, dict) or not re.fullmatch(r"[A-Za-z0-9_-]{3,64}", str(rule.get("id", ""))):
            raise ValueError("Each advisory rule needs a short unique id")
        if rule["id"] in seen:
            raise ValueError("Duplicate advisory rule id")
        seen.add(rule["id"])
        if not isinstance(rule.get("enabled"), bool) or not re.fullmatch(r"CVE-\d{4}-\d{4,}|\*", str(rule.get("cve", ""))):
            raise ValueError(f"Invalid enabled/CVE setting in {rule['id']}")
        if not isinstance(rule.get("library"), str):
            raise ValueError(f"Invalid library in {rule['id']}")
        for field in ("formats", "architectures", "optimization_levels", "required_binary_markers",
                      "excluded_binary_markers"):
            values = rule.get(field, [])
            if not isinstance(values, list) or len(values) > 32 or any(not isinstance(value, str) or
                not value or len(value) > 100 for value in values):
                raise ValueError(f"Invalid {field} in {rule['id']}")
        if rule["enabled"] and not any(rule.get(field) for field in
            ("formats", "architectures", "optimization_levels", "required_binary_markers",
             "excluded_binary_markers")):
            raise ValueError(f"Enabled rule {rule['id']} has no build-configuration conditions")
    return [rule for rule in data["rules"] if rule["enabled"]]


def evaluate_applicability(folder: Path, binary: Path, rule_file: Path | None = None) -> dict:
    folder, binary = Path(folder), Path(binary)
    rules = load_rules(rule_file)
    profile = json.loads((folder / "binary-profile.json").read_text(encoding="utf-8"))
    advisories = json.loads((folder / "known-vulnerabilities.json").read_text(encoding="utf-8"))
    observed = [data.lower() for _, data in _sample(binary)]
    rows = []
    for result in advisories.get("results", []):
        for advisory in result.get("advisories", []):
            matching = [rule for rule in rules if rule["cve"] in ("*", advisory["id"]) and
                        rule["library"].casefold() == result["library"].casefold()]
            observations = []
            for rule in matching:
                conflicts, supporting, unknown = [], [], []
                for field, actual in (("formats", profile.get("format")),
                                      ("architectures", profile.get("architecture"))):
                    allowed = rule.get(field, [])
                    if allowed and actual and actual != "unknown":
                        (supporting if actual in allowed else conflicts).append(f"{field}: {actual}")
                    elif allowed:
                        unknown.append(f"{field}: unknown")
                levels = rule.get("optimization_levels", [])
                level = profile.get("optimization", {}).get("level", "unknown")
                if levels:
                    if level in levels:
                        supporting.append(f"optimization flag: {level}")
                    else:
                        unknown.append("optimization flag not evidenced for this rule")
                for marker in rule.get("required_binary_markers", []):
                    if any(marker.encode("utf-8").lower() in data for data in observed):
                        supporting.append(f"required marker present: {marker}")
                    else:
                        unknown.append(f"required marker not observed: {marker}")
                for marker in rule.get("excluded_binary_markers", []):
                    if any(marker.encode("utf-8").lower() in data for data in observed):
                        conflicts.append(f"excluded marker present: {marker}")
                status = "rule_conflict" if conflicts else "configuration_candidate" if supporting and not unknown else "unknown"
                observations.append({"rule_id": rule["id"], "status": status, "supporting": supporting,
                                     "conflicts": conflicts, "unknown": unknown, "note": rule.get("note", "")})
            rows.append({"cve": advisory["id"], "library": result["library"],
                         "status": "no_rule" if not observations else
                                   "configuration_candidate" if any(item["status"] == "configuration_candidate"
                                                                        for item in observations) else
                                   "rule_conflict" if all(item["status"] == "rule_conflict" for item in observations)
                                   else "unknown",
                         "rules": observations,
                         "nvd_platform_constraints": advisory.get("configuration_constraints", []),
                         "limitation": "Local rules and string markers are review aids, not proof of a vulnerable build."})
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "rule_file": str(rule_file or rules_path()),
              "active_rules": len(rules), "results": rows,
              "limitation": "Rule conflicts do not override vendor advisories or establish non-applicability."}
    (folder / "advisory-applicability.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
