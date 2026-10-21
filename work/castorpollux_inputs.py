"""Validated local VEX, SBOM integrity, and address-based fuzz coverage imports."""

from __future__ import annotations

import csv
import bisect
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_blocks import _block_map, _function_rows
from castorpollux_sbom import _components


def _load_json(source: Path, max_bytes: int = 20 * 1024 * 1024) -> tuple[bytes, dict]:
    source = Path(source)
    if not source.is_file() or source.stat().st_size > max_bytes:
        raise ValueError(f"Choose a JSON file of at most {max_bytes // 1048576} MiB")
    raw = source.read_bytes()
    data = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    return raw, data


def verify_sbom_provenance(folder: Path, expected_sha256: str = "") -> dict:
    """Verify local SBOM bytes against an analyst-pinned digest and record issuer claims separately."""
    folder = Path(folder)
    imported = folder / "SBOM" / "imported.json"
    raw, data = _load_json(imported)
    kind, components = _components(data)
    digest = hashlib.sha256(raw).hexdigest()
    expected = expected_sha256.strip().lower()
    if expected and (len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected)):
        raise ValueError("Expected SBOM SHA-256 must be 64 hexadecimal characters")
    metadata = data.get("metadata", {}) if kind == "CycloneDX" else {}
    declared = {"serial_number": data.get("serialNumber", ""),
                "timestamp": metadata.get("timestamp", "") if isinstance(metadata, dict) else data.get("creationInfo", {}),
                "supplier": metadata.get("supplier", {}) if isinstance(metadata, dict) else {},
                "tool": metadata.get("tools", {}) if isinstance(metadata, dict) else {}}
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "format": kind,
              "sbom_sha256": digest, "expected_sha256": expected,
              "integrity": "match" if expected == digest else "mismatch" if expected else "not_pinned",
              "origin_authentication": "not_verified", "component_count": len(components),
              "declared_metadata": declared,
              "limitations": ["A pinned digest proves byte identity against the analyst's trusted reference only.",
                              "Supplier/tool fields are claims inside the SBOM; no producer signature is verified."]}
    (folder / "sbom-provenance.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def import_vex(folder: Path, source: Path) -> dict:
    folder, source = Path(folder), Path(source)
    raw, data = _load_json(source)
    sbom = folder / "SBOM" / "imported.json"
    _, inventory = _load_json(sbom)
    _, components = _components(inventory)
    identifiers = {component.get(key, "") for component in components for key in ("reference", "purl")}
    identifiers.discard("")
    statements = []
    if isinstance(data.get("statements"), list) and (data.get("@context") or data.get("author")):
        kind = "OpenVEX"
        for item in data["statements"][:10_000]:
            if not isinstance(item, dict):
                continue
            vuln = item.get("vulnerability", {})
            identifier = vuln.get("name", "") if isinstance(vuln, dict) else ""
            for product in item.get("products", []):
                ref = product.get("@id", "") if isinstance(product, dict) else ""
                statements.append({"vulnerability": identifier, "component_ref": ref,
                                   "status": item.get("status", ""), "justification": item.get("justification", ""),
                                   "impact_statement": item.get("impact_statement", "")})
    elif data.get("bomFormat") == "CycloneDX" and isinstance(data.get("vulnerabilities"), list):
        kind = "CycloneDX VEX"
        for item in data["vulnerabilities"][:10_000]:
            if not isinstance(item, dict):
                continue
            for affected in item.get("affects", []):
                if isinstance(affected, dict):
                    analysis = item.get("analysis", {})
                    statements.append({"vulnerability": item.get("id", ""),
                                       "component_ref": affected.get("ref", ""),
                                       "status": analysis.get("state", ""),
                                       "justification": analysis.get("justification", ""),
                                       "impact_statement": analysis.get("detail", "")})
    else:
        raise ValueError("Choose OpenVEX or CycloneDX VEX JSON")
    if len(statements) > 20_000:
        raise ValueError("VEX has too many product statements")
    for item in statements:
        item["match"] = "exact_sbom_reference" if item["component_ref"] in identifiers else "unmatched"
        if item["status"] == "not_affected" and not (item["justification"] or item["impact_statement"]):
            item["quality"] = "missing_justification"
        else:
            item["quality"] = "declared_unverified"
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "format": kind,
              "source_name": source.name, "source_sha256": hashlib.sha256(raw).hexdigest(),
              "statements": statements, "matched": sum(item["match"] == "exact_sbom_reference" for item in statements),
              "unmatched": sum(item["match"] == "unmatched" for item in statements),
              "limitations": ["VEX assertions are supplier declarations, not local proof of exploitability or safety.",
                              "Only exact SBOM reference or package URL matches are accepted; unmatched statements have no effect.",
                              "Imported VEX never suppresses a CastorPollux finding automatically."]}
    destination = folder / "VEX"
    destination.mkdir(exist_ok=True)
    (destination / "imported.json").write_bytes(raw)
    (folder / "vex-import.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def import_fuzz_coverage(folder: Path, source: Path) -> dict:
    """Overlay address-based fuzz hits; AFL edge IDs need an external address mapping first."""
    folder = Path(folder)
    raw, data = _load_json(Path(source))
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    binary_hash = manifest.get("sha256", "").lower()
    if data.get("binary_sha256", "").lower() != binary_hash:
        raise ValueError("Coverage binary SHA-256 must match the investigation target")
    hits = data.get("hits", [])
    if not isinstance(hits, list) or len(hits) > 500_000:
        raise ValueError("Coverage hits must be an array of at most 500,000 addresses")
    addresses = {}
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        try:
            address = int(str(hit.get("address", "")), 16)
            count = int(hit.get("count", 0))
        except ValueError:
            continue
        if 0 <= count <= 1_000_000_000:
            addresses[address] = addresses.get(address, 0) + count
    functions = _function_rows(folder)
    blocks = _block_map(folder, {format(entry, "x") for entry, _ in functions[:20_000]})
    sorted_hits = sorted(addresses.items())
    hit_addresses = [address for address, _ in sorted_hits]
    prefix = [0]
    for _, count in sorted_hits:
        prefix.append(prefix[-1] + count)
    overlays = []
    hit_blocks = 0
    for entry, row in functions:
        for block in blocks.get(format(entry, "x"), []):
            start, end = int(block["entry"], 16), int(block["end"], 16)
            count = prefix[bisect.bisect_right(hit_addresses, end)] - prefix[bisect.bisect_left(hit_addresses, start)]
            hit_blocks += count > 0
            overlays.append({"function": row.get("name", ""), "function_entry": row.get("entry", ""),
                             "block_entry": block["entry"], "block_end": block["end"],
                             "hits": count, "status": "hit" if count else "unobserved"})
    intervals = sorted((int(item["block_entry"], 16), int(item["block_end"], 16)) for item in overlays)
    starts = [start for start, _ in intervals]
    unmapped = []
    for address in hit_addresses:
        index = bisect.bisect_right(starts, address) - 1
        if index < 0 or address > intervals[index][1]:
            unmapped.append(format(address, "x"))
            if len(unmapped) >= 100:
                break
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "binary_sha256": binary_hash,
              "source_sha256": hashlib.sha256(raw).hexdigest(), "source_name": Path(source).name,
              "blocks": overlays, "hit_blocks": hit_blocks, "total_blocks": len(overlays),
              "unmapped_addresses": unmapped,
              "limitations": ["Only address/count JSON is accepted; raw AFL++ edge IDs do not identify binary addresses.",
                              "Unobserved means the imported corpus missed a block, not that the block is unreachable.",
                              "Basic-block boundaries are approximate and address mapping may shift across builds."]}
    destination = folder / "Fuzz"
    destination.mkdir(exist_ok=True)
    (destination / "imported.json").write_bytes(raw)
    (folder / "fuzz-coverage.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
