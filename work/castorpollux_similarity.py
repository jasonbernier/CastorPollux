"""Approximate REA procedure search across saved investigations."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


def _tokens(code: str) -> list[str]:
    code = re.sub(r"/\*.*?\*/|//[^\n]*", " ", code, flags=re.S)
    code = re.sub(r"\b(?:0x[0-9a-f]+|FUN_[0-9a-f]+|DAT_[0-9a-f]+|[0-9a-f]{8,16})\b", "ADDR", code, flags=re.I)
    return re.findall(r"[a-z_][a-z_0-9]*|[+*/%<>=!&|^-]+", code.casefold())


def fingerprint(code: str) -> set[str]:
    tokens = _tokens(code)
    if len(tokens) < 8:
        return set()
    return {hashlib.sha256(" ".join(tokens[i:i + 5]).encode()).hexdigest()[:16]
            for i in range(len(tokens) - 4)}


def procedures(folder: Path) -> list[dict]:
    try:
        items = json.loads((Path(folder) / "rea-decompilation.json").read_text(encoding="utf-8"))["items"]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    return [{"address": str(item.get("address", "")),
             "name": str((item.get("procedure") or {}).get("name", "")),
             "pseudocode": item["pseudocode"]}
            for item in items if item.get("status") == "ok" and isinstance(item.get("pseudocode"), str)]


def similar_functions(folder: Path, selector: str, investigations: list[Path],
                      minimum: float = 0.45, limit: int = 50) -> list[dict]:
    if not 0 <= minimum <= 1:
        raise ValueError("Similarity threshold must be from 0 to 1")
    query = selector.strip().casefold().removeprefix("0x")
    source = next((row for row in procedures(folder)
                   if row["address"].casefold().removeprefix("0x") == query or
                   row["name"].casefold() == query), None)
    if source is None:
        raise ValueError("Choose a saved REA procedure name or address")
    source_fp = fingerprint(source["pseudocode"])
    if not source_fp:
        raise ValueError("Procedure has too little reconstructed code for similarity search")
    results = []
    for other in investigations:
        if Path(other).resolve() == Path(folder).resolve():
            continue
        for row in procedures(other):
            candidate = fingerprint(row["pseudocode"])
            if not candidate:
                continue
            score = len(source_fp & candidate) / len(source_fp | candidate)
            if score >= minimum:
                results.append({"folder": str(Path(other).resolve()), "address": row["address"],
                                "name": row["name"], "similarity": round(score, 4),
                                "shared_shingles": len(source_fp & candidate),
                                "source_shingles": len(source_fp), "candidate_shingles": len(candidate)})
    return sorted(results, key=lambda row: (-row["similarity"], row["folder"], row["address"]))[:limit]
