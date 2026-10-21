"""Software inventory and Windows Authenticode inspection."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from castorpollux_core import APP_VERSION, PINNED, ComponentStore, bundled_component, sha256


LICENSES = {"ghidra": "Apache-2.0 and bundled module notices",
            "jdk": "GPL-2.0 with Classpath Exception and bundled notices",
            "node": "Node.js license and bundled component notices",
            "rea": "MIT and REA third-party notices"}


def authenticode_status(path: Path) -> dict:
    if not Path(path).is_file() or Path(path).suffix.lower() not in {".exe", ".dll", ".sys", ".ocx"}:
        return {"status": "not_applicable"}
    environment = os.environ.copy()
    environment["CASTORPOLLUX_SIGNATURE_TARGET"] = str(Path(path).resolve())
    system_modules = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"
    environment["PSModulePath"] = str(system_modules)
    command = ("$s = Get-AuthenticodeSignature -LiteralPath $env:CASTORPOLLUX_SIGNATURE_TARGET; "
               "@{status=[string]$s.Status; subject=[string]$s.SignerCertificate.Subject; "
               "issuer=[string]$s.SignerCertificate.Issuer; "
               "thumbprint=[string]$s.SignerCertificate.Thumbprint; "
               "valid_until=[string]$s.SignerCertificate.NotAfter} | ConvertTo-Json -Compress")
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, text=True, encoding="utf-8", errors="replace",
                                env=environment, timeout=30,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode == 0 and not result.stderr.strip():
            parsed = json.loads(result.stdout)
            if parsed.get("status"):
                return parsed
        return {"status": "verification_error", "detail": result.stderr.strip()[:300]}
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        return {"status": "verification_error", "detail": str(error)}


def software_inventory(store: ComponentStore | None = None, app_path: Path | None = None) -> dict:
    store = store or ComponentStore()
    app = Path(app_path or (sys.executable if getattr(sys, "frozen", False) else __file__)).resolve()
    components = []
    for name in ("ghidra", "jdk", "node", "rea"):
        active = store.active_path(name)
        bundled = bundled_component(name)
        path = active or (bundled[1] if bundled else None)
        executable = path
        if name == "ghidra" and path:
            executable = path / "support" / "analyzeHeadless.bat"
        elif name == "jdk" and path:
            executable = path / "bin" / "java.exe"
        record = {"name": name, "version": store.current_version(name), "license": LICENSES[name],
                  "source": "updated" if active else "bundled", "path": str(path) if path else None}
        if executable and executable.is_file():
            record["file"] = str(executable)
            record["sha256"] = sha256(executable)
            record["authenticode"] = authenticode_status(executable)
        components.append(record)
    return {"application": "CastorPollux", "version": APP_VERSION,
            "generated_at": datetime.now().astimezone().isoformat(),
            "application_file": str(app), "application_sha256": sha256(app),
            "application_signature": authenticode_status(app),
            "components": components,
            "notice": "SHA-256 checks verify downloaded bytes. Authenticode status is reported separately; an unsigned component is not represented as signed."}


def write_inventory(destination: Path, store: ComponentStore | None = None,
                    app_path: Path | None = None) -> Path:
    destination = Path(destination)
    if not destination.parent.is_dir():
        raise ValueError("Inventory destination directory does not exist")
    destination.write_text(json.dumps(software_inventory(store, app_path), indent=2), encoding="utf-8")
    return destination
