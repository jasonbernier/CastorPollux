"""Generate a release inventory for files actually bundled in CastorPollux.exe."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from castorpollux_core import APP_VERSION, PINNED, sha256
from castorpollux_integrity import LICENSES, authenticode_status
from release_attestation import build_time


def generate(root: Path) -> Path:
    root = Path(root).resolve()
    files = {
        "ghidra": root / "work/archives/ghidra_12.1.4_PUBLIC_20260921.zip",
        "jdk": root / "work/archives/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip",
        "node": root / "work/runtime/node.exe",
        "rea": root / "work/runtime/node_modules/rea-agents/scripts/rea.mjs",
    }
    executable = root / "outputs/CastorPollux.exe"
    data = {"application": "CastorPollux", "version": APP_VERSION,
            "generated_at": build_time(),
            "application_sha256": sha256(executable),
            "application_signature": authenticode_status(executable),
            "components": [{"name": name, "version": PINNED[name], "license": LICENSES[name],
                            "bundled_file": path.name, "sha256": sha256(path),
                            "authenticode": authenticode_status(path)}
                           for name, path in files.items()],
            "update_policy": "Components are fetched from upstream HTTPS sources and verified against published SHA-256 or package integrity. A publisher signature is required before a release can be described as signed.",
            "notices": "See CastorPollux-CREDITS.md and CastorPollux-Licenses/."}
    target = root / "outputs/CastorPollux-Software-Inventory.json"
    target.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return target


if __name__ == "__main__":
    print(generate(Path(__file__).resolve().parent.parent))
