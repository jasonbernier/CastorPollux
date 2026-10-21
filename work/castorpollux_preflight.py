"""Local, bounded engine and review-agent compatibility checks."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_core import PINNED, compatible_update


def _version(args: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=20,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-300:] or f"exit {result.returncode}")
    return (result.stdout or result.stderr).strip().splitlines()[0][:200]


def engine_compatibility(store, paths: tuple[Path, Path, Path, Path]) -> dict:
    ghidra, jdk, node, rea = paths
    checks = []
    for name, path in (("Ghidra", ghidra / "support" / "analyzeHeadless.bat"),
                       ("JDK", jdk / "bin" / "java.exe"), ("Node", node), ("REA", rea)):
        checks.append({"engine": name, "path": str(path), "present": path.is_file()})
    errors = [item["engine"] + " executable is missing" for item in checks if not item["present"]]
    if not errors:
        try:
            java = _version([str(jdk / "bin" / "java.exe"), "-version"])
            checks[1]["version_output"] = java
            if not re.search(r'\b21(?:\.|\b)', java):
                errors.append("Ghidra 12.1 requires the supported JDK 21 line")
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            errors.append("JDK launch failed: " + str(error))
        try:
            node_version = _version([str(node), "--version"])
            checks[2]["version_output"] = node_version
            if int(re.search(r"\d+", node_version).group()) < 20:
                errors.append("REA requires Node 20 or newer")
        except (OSError, RuntimeError, subprocess.TimeoutExpired, AttributeError) as error:
            errors.append("Node launch failed: " + str(error))
        rea_package = rea.parent.parent / "package.json"
        if rea_package.is_file():
            try:
                version = json.loads(rea_package.read_text(encoding="utf-8"))["version"]
                checks[3]["version_output"] = version
            except (OSError, ValueError, KeyError):
                errors.append("REA package metadata is invalid")
        if not compatible_update("ghidra", store.current_version("ghidra")):
            errors.append("Active Ghidra version is outside REA's supported 12.1 line")
    return {"checked_at": datetime.now(timezone.utc).isoformat(), "status": "compatible" if not errors else "blocked",
            "checks": checks, "errors": errors, "pinned": PINNED}


def agent_capabilities(agent: str, executable: Path, stage: Path) -> dict:
    """Check CLI flags and local read access without invoking a model."""
    marker = stage / ".castorpollux-capability-probe"
    marker.write_text("CastorPollux read probe", encoding="ascii")
    try:
        help_args = [str(executable)] + (["exec"] if agent == "codex" else ["run"] if agent == "opencode" else []) + ["--help"]
        output = _version(help_args, stage)
        result = subprocess.run(help_args, cwd=stage, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=20,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        help_text = result.stdout + result.stderr
        required = {"codex": ("--sandbox", "--output-schema"),
                    "claude": ("--print", "--output-format", "--json-schema"),
                    "opencode": ("--model",)}[agent]
        missing = [flag for flag in required if flag not in help_text]
        status = "ready" if not missing and marker.read_text(encoding="ascii") == "CastorPollux read probe" else "blocked"
        return {"agent": agent, "status": status, "missing": missing, "version_help": output,
                "stage_readable": marker.is_file(), "note": "Host-side capability probe; agent sandbox access is verified during review."}
    finally:
        marker.unlink(missing_ok=True)
