"""Offline CycloneDX/SPDX JSON comparison against local library leads."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


ALIASES = {"openssl": "openssl", "libssl": "openssl", "libcrypto": "openssl",
           "zlib": "zlib", "libcurl": "libcurl", "curl": "libcurl",
           "libpng": "libpng", "sqlite": "sqlite", "sqlite3": "sqlite",
           "libxml2": "libxml2", "libxml": "libxml2"}


def _name(value: str) -> str:
    value = str(value).rsplit("/", 1)[-1].casefold().strip()
    value = re.sub(r"(?:\.dll|\.so(?:\.\d+)*|\.dylib)$", "", value)
    return ALIASES.get(value, value)


def _version(value: str | None) -> str:
    return str(value or "").strip().casefold().removeprefix("v")


def _components(data: dict) -> tuple[str, list[dict]]:
    if data.get("bomFormat") == "CycloneDX" and isinstance(data.get("components"), list):
        components = [{"name": item.get("name", ""), "version": item.get("version", ""),
                       "purl": item.get("purl", ""), "reference": item.get("bom-ref", "")}
                      for item in data["components"] if isinstance(item, dict)]
        return "CycloneDX", components
    if isinstance(data.get("spdxVersion"), str) and isinstance(data.get("packages"), list):
        components = []
        for item in data["packages"]:
            if not isinstance(item, dict):
                continue
            purl = next((ref.get("referenceLocator", "") for ref in item.get("externalRefs", [])
                         if isinstance(ref, dict) and ref.get("referenceType", "").casefold() == "purl"), "")
            components.append({"name": item.get("name", ""), "version": item.get("versionInfo", ""),
                               "purl": purl, "reference": item.get("SPDXID", "")})
        return "SPDX", components
    raise ValueError("Choose a CycloneDX or SPDX JSON SBOM with a components/packages array")


def compare_sbom(folder: Path, source: Path | None = None) -> dict:
    folder = Path(folder)
    imported = folder / "SBOM" / "imported.json"
    source = Path(source) if source else imported
    if not source.is_file() or source.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("SBOM must be an existing JSON file of at most 20 MiB")
    raw = source.read_bytes()
    data = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("SBOM root must be a JSON object")
    kind, components = _components(data)
    if len(components) > 10000:
        raise ValueError("SBOM exceeds 10,000 components")
    if source.resolve() != imported.resolve():
        imported.parent.mkdir(parents=True, exist_ok=True)
        temporary = imported.with_suffix(".new")
        shutil.copyfile(source, temporary)
        temporary.replace(imported)
    inventory = json.loads((folder / "embedded-libraries.json").read_text(encoding="utf-8"))
    observed = inventory.get("libraries", [])
    indexed = {}
    for component in components:
        names = {_name(component["name"])}
        if component["purl"].startswith("pkg:"):
            names.add(_name(component["purl"].split("@", 1)[0]))
        for name in names:
            if name:
                indexed.setdefault(name, []).append(component)
    rows = []
    linked = set()
    for lead in observed:
        candidates = indexed.get(_name(lead.get("name", "")), [])
        for candidate in candidates:
            linked.add(id(candidate))
        exact = [item for item in candidates if _version(item["version"]) and
                 _version(item["version"]) == _version(lead.get("version"))]
        if exact:
            status = "name_and_version_match"
        elif candidates and lead.get("version") and any(item["version"] for item in candidates):
            status = "version_conflict"
        elif candidates:
            status = "name_match_version_unknown"
        else:
            status = "detected_only"
        rows.append({"library": lead.get("name"), "detected_version": lead.get("version"),
                     "detected_confidence": lead.get("confidence"), "status": status,
                     "sbom_components": candidates[:20]})
    sbom_only = [{"name": item["name"], "version": item["version"], "reference": item["reference"]}
                 for item in components if id(item) not in linked]
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "format": kind,
              "source_name": source.name, "imported_copy": "SBOM/imported.json",
              "source_sha256": hashlib.sha256(raw).hexdigest(), "component_count": len(components),
              "detected_libraries": rows, "sbom_only_count": len(sbom_only), "sbom_only": sbom_only[:200],
              "limitations": ["SBOM names and versions are supplied declarations; local signatures are unverified library leads.",
                              "A matching name/version does not prove that matching library code is embedded or vulnerable.",
                              "The local fingerprint scanner supports a limited set of libraries and samples bounded binary regions."]}
    (folder / "sbom-comparison.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
