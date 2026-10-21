"""Reproducible CastorPollux build, optional publisher signing, and package inventory."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from castorpollux_core import sha256
from castorpollux_integrity import authenticode_status
from release_inventory import generate
from release_license_inventory import generate as generate_license_inventory
from release_sign import sign
from castorpollux_flow import DEFAULT_RULES
from castorpollux_applicability import SAMPLE as ADVISORY_RULE_SAMPLE
from castorpollux_plugins import SAMPLE
from release_attestation import generate as generate_attestation
from build_github_archive import build as build_github_archive


def build(root: Path, skip_build: bool = False, require_signature: bool = False) -> None:
    root = Path(root).resolve()
    os.environ.setdefault("SOURCE_DATE_EPOCH", str(int(max(path.stat().st_mtime for path in
        (root / "work").glob("*.py") if path.is_file()))))
    os.environ.setdefault("PYTHONHASHSEED", "0")
    if not skip_build:
        subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", str(root / "work/CastorPollux.spec")],
                       cwd=root, check=True)
    source = root / "dist/CastorPollux.exe"
    target = root / "outputs/CastorPollux.exe"
    shutil.copy2(source, target)
    if os.environ.get("CASTORPOLLUX_SIGNING_THUMBPRINT"):
        sign(target)
    status = authenticode_status(target)
    if require_signature and status.get("status") != "Valid":
        raise RuntimeError("Release requires a valid Authenticode signature; current status is " +
                           str(status.get("status")))
    (root / "outputs/CastorPollux-SHA256.txt").write_text(sha256(target) + "  CastorPollux.exe\n", encoding="ascii")
    (root / "outputs/CastorPollux-Flow-Rules-Example.json").write_text(
        json.dumps(DEFAULT_RULES, indent=2), encoding="utf-8")
    (root / "outputs/CastorPollux-Advisory-Rules-Example.json").write_text(
        json.dumps(ADVISORY_RULE_SAMPLE, indent=2), encoding="utf-8")
    (root / "outputs/CastorPollux-Plugin-Example.json").write_text(
        json.dumps(SAMPLE, indent=2), encoding="utf-8")
    generate(root)
    generate_license_inventory(root)
    generate_attestation(root)
    subprocess.run([sys.executable, str(root / "work/package_v130.py")], cwd=root, check=True)
    github_source = root / "github" / "CastorPollux"
    if github_source.is_dir():
        for name in ("CastorPollux-Software-Inventory.json", "CastorPollux-License-Inventory.json",
                     "CastorPollux-Release-Attestation.json"):
            shutil.copy2(root / "outputs" / name, github_source / "outputs" / name)
        shutil.copy2(root / "outputs/CastorPollux-License-Inventory.json",
                     github_source / "third_party/License-Inventory.json")
        build_github_archive(root)
    print(f"Release built; Authenticode status: {status.get('status')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--require-signature", action="store_true")
    options = parser.parse_args()
    build(Path(__file__).resolve().parent.parent, options.skip_build, options.require_signature)
