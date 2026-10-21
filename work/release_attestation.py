"""Reproducible local release provenance (unsigned unless publisher signs it)."""

from __future__ import annotations

import json
import hashlib
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_core import APP_VERSION, sha256


def build_time() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(int(epoch), timezone.utc).isoformat()


def generate(root: Path) -> Path:
    root = Path(root)
    materials = sorted(path for path in (root / "work").glob("*.py") if not path.name.startswith("test_"))
    materials += sorted((root / "work/scripts").glob("*"))
    materials += sorted((root / "work/assets").glob("*"))
    materials += [root / "work/CastorPollux.spec", root / "work/content/about.html", root / "work/content/help.html"]
    materials = [path for path in materials if path.is_file()]
    archives = sorted((root / "work/archives").glob("*.zip"))
    materials += archives + [root / "work/runtime/node.exe",
                             root / "work/runtime/node_modules/rea-agents/scripts/rea.mjs"]
    materials += [root / "outputs" / name for name in
                  ("CastorPollux-README.md", "CastorPollux-CREDITS.md", "CastorPollux-Codex-Prompt.txt",
                   "CastorPollux-Batch-Example.json", "CastorPollux-CI-Example.ps1",
                   "CastorPollux-Commercial-License-Audit.md", "CastorPollux-Software-Inventory.json",
                   "CastorPollux-License-Inventory.json", "CastorPollux-SHA256.txt",
                   "CastorPollux-Flow-Rules-Example.json", "CastorPollux-Plugin-Example.json",
                   "CastorPollux-Advisory-Rules-Example.json")]
    trees = []
    for directory in (root / "work/runtime/node_modules", root / "work/runtime/pnpm",
                      root / "outputs/CastorPollux-Licenses"):
        digest = hashlib.sha256()
        count = 0
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            digest.update(path.relative_to(directory).as_posix().encode("utf-8") + b"\0")
            digest.update(sha256(path).encode("ascii") + b"\n")
            count += 1
        trees.append((directory, digest.hexdigest(), count))
    try:
        pyinstaller = subprocess.check_output([sys.executable, "-m", "PyInstaller", "--version"], text=True).strip()
    except Exception:
        pyinstaller = "unknown"
    data = {"schema": 1, "type": "local-build-attestation", "application_version": APP_VERSION,
            "build_time": build_time(), "source_date_epoch": int(os.environ["SOURCE_DATE_EPOCH"]),
            "builder": {"python": platform.python_version(), "pyinstaller": pyinstaller,
                        "platform": platform.platform()},
            "recipe": ["python -m PyInstaller --noconfirm work/CastorPollux.spec",
                       "python work/build_release.py"],
            "materials": [{"path": path.relative_to(root).as_posix(), "sha256": sha256(path)} for path in materials]
                         + [{"path": directory.relative_to(root).as_posix(), "tree_sha256": digest,
                             "file_count": count} for directory, digest, count in trees],
            "subjects": [{"name": "CastorPollux.exe", "sha256": sha256(root / "outputs/CastorPollux.exe")}],
            "signature": "unsigned",
            "note": "This records exact inputs and output. It is not a third-party or cryptographically signed provenance claim."}
    target = root / "outputs/CastorPollux-Release-Attestation.json"
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return target
