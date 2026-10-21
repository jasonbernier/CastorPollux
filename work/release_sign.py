"""Publisher release step: Authenticode-sign EXE with a configured certificate."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


def find_signtool() -> str | None:
    configured = os.environ.get("SIGNTOOL_PATH") or shutil.which("signtool.exe")
    if configured:
        return str(configured)
    kits = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10" / "bin"
    candidates = sorted(kits.glob("*/x64/signtool.exe"), reverse=True) if kits.is_dir() else []
    return str(candidates[0]) if candidates else None


def sign(executable: Path) -> None:
    executable = Path(executable).resolve()
    if not executable.is_file() or executable.suffix.lower() != ".exe":
        raise ValueError("Choose an existing Windows EXE")
    thumbprint = os.environ.get("CASTORPOLLUX_SIGNING_THUMBPRINT", "").replace(" ", "")
    timestamp = os.environ.get("CASTORPOLLUX_TIMESTAMP_URL", "")
    signtool = find_signtool()
    if not thumbprint or not timestamp or not signtool:
        raise RuntimeError("Signing requires a code-signing certificate thumbprint, timestamp URL, and Windows SignTool")
    if len(thumbprint) != 40 or any(letter not in "0123456789abcdefABCDEF" for letter in thumbprint):
        raise ValueError("Signing certificate thumbprint must be 40 hexadecimal characters")
    result = subprocess.run([signtool, "sign", "/sha1", thumbprint, "/fd", "SHA256",
                             "/tr", timestamp, "/td", "SHA256", str(executable)],
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("Authenticode signing failed: " + (result.stderr or result.stdout)[-500:])
    verify = subprocess.run([signtool, "verify", "/pa", str(executable)],
                            capture_output=True, text=True, timeout=60)
    if verify.returncode:
        raise RuntimeError("Signed EXE failed Authenticode verification: " + (verify.stderr or verify.stdout)[-500:])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sign and verify a CastorPollux release EXE")
    parser.add_argument("executable", type=Path)
    options = parser.parse_args()
    sign(options.executable)
    print("Authenticode signature verified:", options.executable)
