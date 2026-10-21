"""Conservative code-based matching for anonymous functions across investigations."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from castorpollux_review import coverage_rows


ANONYMOUS = re.compile(r"(?i)^(?:FUN|sub|fcn|func)_[0-9a-f]+$")
HEADER = re.compile(r"^/\* ===== .+ @ ([0-9A-Fa-f]+) ===== \*/$")
TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|0x[0-9a-fA-F]+|\d+|==|!=|<=|>=|&&|\|\||[-+*/%<>&|^~=!?:;{}()\[\]]")


def _address(value: str) -> str:
    try:
        return format(int(str(value), 16), "x")
    except (ValueError, TypeError):
        return ""


def _code_by_address(folder: Path) -> dict[str, str]:
    rows = coverage_rows(folder)
    code = {_address(row["address"]): row["pseudocode"] for row in rows if row.get("pseudocode")}
    path = Path(folder) / "pseudocode.c"
    if not path.is_file():
        return code
    current = ""
    parts = defaultdict(list)
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            marker = HEADER.match(line.strip())
            if marker:
                current = _address(marker.group(1))
            elif current:
                parts[current].append(line)
    fallback = {key: "".join(value) for key, value in parts.items()}
    fallback.update(code)
    return fallback


def _signature(code: str) -> dict | None:
    code = re.sub(r"/\*.*?\*/|//[^\n]*", " ", code, flags=re.S)
    code = re.sub(r"\b(?:FUN|sub|fcn|func)_[0-9a-fA-F]+\b", "FUNCTION", code)
    code = re.sub(r"\b(?:[a-zA-Z]Var\d+|param_\d+|local_[0-9a-fA-F]+)\b", "LOCAL", code)
    code = re.sub(r"0x[0-9a-fA-F]{6,}", "ADDRESS", code)
    tokens = TOKEN.findall(code.casefold())
    if len(tokens) < 18:
        return None
    shingles = {tuple(tokens[index:index + 3]) for index in range(len(tokens) - 2)}
    if len(shingles) < 10:
        return None
    return {"hash": hashlib.sha256("\0".join(tokens).encode("utf-8")).hexdigest(),
            "tokens": len(tokens), "shingles": shingles}


def match_anonymous_functions(left: Path, right: Path, left_rows: list[dict], right_rows: list[dict],
                              left_unmatched: set[str], right_unmatched: set[str]) -> list[dict]:
    """Mutual-best, unique matching; ambiguous or tiny bodies are left unmatched."""
    old_code, new_code = _code_by_address(left), _code_by_address(right)
    def candidates(rows, allowed, code):
        result = {}
        for row in rows:
            address = _address(row.get("entry", ""))
            if address in allowed and ANONYMOUS.fullmatch(row.get("name", "")):
                signature = _signature(code.get(address, ""))
                if signature:
                    result[address] = (row, signature)
        return result
    old = candidates(left_rows, left_unmatched, old_code)
    new = candidates(right_rows, right_unmatched, new_code)
    by_hash_old, by_hash_new = defaultdict(list), defaultdict(list)
    for address, (_, signature) in old.items():
        by_hash_old[signature["hash"]].append(address)
    for address, (_, signature) in new.items():
        by_hash_new[signature["hash"]].append(address)
    matches = []
    used_old, used_new = set(), set()
    for digest in sorted(by_hash_old.keys() & by_hash_new.keys()):
        if len(by_hash_old[digest]) == len(by_hash_new[digest]) == 1:
            a, b = by_hash_old[digest][0], by_hash_new[digest][0]
            matches.append({"old_entry": old[a][0]["entry"], "new_entry": new[b][0]["entry"],
                            "old_name": old[a][0]["name"], "new_name": new[b][0]["name"],
                            "similarity": 1.0, "method": "unique normalized code", "confidence": "high"})
            used_old.add(a); used_new.add(b)
    # Fuzzy comparison is bounded and requires a unique mutual best with a clear margin.
    remaining_old = [(a, item) for a, item in old.items() if a not in used_old][:500]
    remaining_new = [(b, item) for b, item in new.items() if b not in used_new][:500]
    scored = {}
    for a, (_, left_sig) in remaining_old:
        choices = []
        for b, (_, right_sig) in remaining_new:
            ratio = min(left_sig["tokens"], right_sig["tokens"]) / max(left_sig["tokens"], right_sig["tokens"])
            if ratio < .7:
                continue
            common = len(left_sig["shingles"] & right_sig["shingles"])
            union = len(left_sig["shingles"] | right_sig["shingles"])
            score = common / union if union else 0.0
            if score >= .88:
                choices.append((score, b))
        scored[a] = sorted(choices, reverse=True)
    reverse = defaultdict(list)
    for a, choices in scored.items():
        for score, b in choices:
            reverse[b].append((score, a))
    for a, choices in scored.items():
        if not choices or len(choices) > 1 and choices[0][0] - choices[1][0] < .08:
            continue
        score, b = choices[0]
        contenders = sorted(reverse[b], reverse=True)
        if contenders[0][1] != a or len(contenders) > 1 and contenders[0][0] - contenders[1][0] < .08:
            continue
        matches.append({"old_entry": old[a][0]["entry"], "new_entry": new[b][0]["entry"],
                        "old_name": old[a][0]["name"], "new_name": new[b][0]["name"],
                        "similarity": round(score, 4), "method": "mutual normalized-code similarity",
                        "confidence": "candidate"})
    return sorted(matches, key=lambda item: item["old_entry"])
