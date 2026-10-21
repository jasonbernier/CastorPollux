"""CastorPollux analysis and verified component updates."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from packaging.version import Version

from rea_binary_studio import safe_delete, safe_name, sha256, unpack_tool, write_report


APP_NAME = "CastorPollux"
APP_VERSION = "1.0.0"
PINNED = {"ghidra": "12.1.4", "jdk": "21.0.12.1+1", "rea": "6.5.0", "node": "24.19.0"}
GHIDRA_ARCHIVE = "ghidra_12.1.4_PUBLIC_20260921.zip"
JDK_ARCHIVE = "OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip"
GHIDRA_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
JDK_SHA256 = "f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e"


def optional_symbols_not_found(error: Exception) -> bool:
    """A missing optional symbol file is a normal lookup result, not an analysis failure."""
    return isinstance(error, HTTPError) and error.code == 404


def symbol_lookup_failure_class(error: Exception) -> str:
    lowered = str(error).casefold()
    return "identity_mismatch" if "age differs" in lowered or "identity mismatch" in lowered else "lookup_failed"


def resource(*parts: str) -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).parent)).joinpath(*parts)


def home() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    current = base / APP_NAME
    # Preserve investigations and component downloads when upgrading the old brand.
    legacy = base / "HexVigil"
    if legacy.is_dir() and not legacy.is_symlink() and legacy.resolve().parent == base.resolve():
        if not current.exists():
            try:
                legacy.rename(current)
                return current
            except OSError:
                pass
        marker = current / ".legacy-migration-complete"
        if not marker.exists():
            # Another process may hold the old folder open, or a new folder may
            # already exist. Preserve existing new state and copy missing data.
            current.mkdir(parents=True, exist_ok=True)
            for name in ("settings.json", "workspace.json", "form-drafts.json",
                         "investigations.json", "investigation-jobs.json"):
                source = legacy / name
                if (source.is_file() and not source.is_symlink() and
                        source.stat().st_size <= 16 * 1024 * 1024 and not (current / name).exists()):
                    shutil.copy2(source, current / name)
            content = legacy / "Content"
            if content.is_dir() and not content.is_symlink():
                (current / "Content").mkdir(exist_ok=True)
                for source in content.iterdir():
                    if (source.is_file() and not source.is_symlink() and
                            source.stat().st_size <= 16 * 1024 * 1024 and
                            not (current / "Content" / source.name).exists()):
                        shutil.copy2(source, current / "Content" / source.name)
            marker.write_text("Migrated available user state from the previous application folder.\n",
                              encoding="utf-8")
    return current


def fetch_bytes(url: str, hosts: set[str], timeout: int = 30) -> bytes:
    if urlparse(url).scheme != "https" or urlparse(url).hostname not in hosts:
        raise RuntimeError("Unexpected update URL")
    request = Request(url, headers={"User-Agent": "CastorPollux/1.0 (+local updater)", "Accept": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_json(url: str, hosts: set[str]) -> dict | list:
    return json.loads(fetch_bytes(url, hosts).decode("utf-8"))


def newer(latest: str, current: str) -> bool:
    return Version(latest) > Version(current)


def compatible_update(component: str, version: str) -> bool:
    # REA's Windows Ghidra provider currently admits the 12.1.x release line.
    return component != "ghidra" or Version(version).release[:2] == (12, 1)


def download(url: str, destination: Path, expected_sha256: str, notify, cancelled) -> Path:
    if urlparse(url).scheme != "https" or urlparse(url).hostname not in {
        "github.com", "nodejs.org", "registry.npmjs.org"
    }:
        raise RuntimeError("Download URL is not an expected official host")
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".partial")
    digest = hashlib.sha256()
    request = Request(url, headers={"User-Agent": "CastorPollux/1.0 (+local updater)"})
    received = 0
    last_report = 0
    try:
        with urlopen(request, timeout=120) as response, partial.open("wb") as output:
            total = int(response.headers.get("Content-Length", "0"))
            while True:
                if cancelled():
                    raise InterruptedError("Update cancelled")
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
                digest.update(chunk)
                received += len(chunk)
                if received - last_report >= 25 * 1024 * 1024:
                    notify(f"Downloaded {received / 1048576:.0f} MiB" +
                           (f" of {total / 1048576:.0f} MiB" if total else ""))
                    last_report = received
        actual = digest.hexdigest()
        if actual.lower() != expected_sha256.lower():
            raise RuntimeError(f"SHA-256 mismatch for {destination.name}")
        os.replace(partial, destination)
        return destination
    finally:
        partial.unlink(missing_ok=True)


def bundled_component(component: str) -> tuple[str, Path] | None:
    paths = {
        "ghidra": home() / "Tools" / "ghidra_12.1.4_PUBLIC",
        "jdk": home() / "Tools" / "jdk-21.0.12.1+1",
        "node": resource("runtime", "node.exe"),
        "rea": resource("runtime", "node_modules", "rea-agents", "scripts", "rea.mjs"),
    }
    path = paths[component]
    return (PINNED[component], path) if path.exists() else None


def check_component(component: str, path: Path, version: str, store: "ComponentStore") -> str:
    """Exercise the active executable or validate the installed Ghidra metadata."""
    if component == "ghidra":
        launcher = path / "support" / "analyzeHeadless.bat"
        properties = path / "Ghidra" / "application.properties"
        if not launcher.is_file() or not properties.is_file():
            raise RuntimeError("Ghidra launcher or application metadata is missing")
        values = dict(line.split("=", 1) for line in properties.read_text(encoding="utf-8").splitlines()
                      if "=" in line and not line.startswith("#"))
        actual = values.get("application.version", "")
        if actual != version:
            raise RuntimeError(f"Ghidra reports {actual or 'no version'}, expected {version}")
        jdk = store.active_path("jdk") or (bundled_component("jdk") or ("", Path("")))[1]
        if not (jdk / "bin" / "java.exe").is_file():
            tools = store.root / "Tools"
            tools.mkdir(parents=True, exist_ok=True)
            jdk = unpack_tool(resource("archives", JDK_ARCHIVE), JDK_SHA256,
                              "jdk-21.0.12.1+1", tools / "jdk-21.0.12.1+1",
                              tools, lambda _: None, lambda: False)
        env = os.environ.copy()
        env.update({"JAVA_HOME": str(jdk), "GHIDRA_INSTALL_DIR": str(path)})
        env["PATH"] = str(jdk / "bin") + os.pathsep + env.get("PATH", "")
        result = subprocess.run([str(launcher), "-help"], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", env=env,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=45)
        if "Headless Analyzer Usage" not in (result.stdout + result.stderr):
            raise RuntimeError("Ghidra headless launcher did not start")
        return f"Ghidra {actual}: headless launcher healthy"
    if component == "jdk":
        executable = path / "bin" / "java.exe"
        if not executable.is_file() or not (path / "bin" / "javac.exe").is_file():
            raise RuntimeError("Java runtime or compiler is missing")
        args = [str(executable), "-version"]
    elif component == "node":
        if not path.is_file():
            raise RuntimeError("Node executable is missing")
        args = [str(path), "--version"]
    elif component == "rea":
        if not path.is_file():
            raise RuntimeError("REA CLI is missing")
        node = store.active_path("node") or resource("runtime", "node.exe")
        args = [str(node), str(path), "--version"]
    else:
        raise ValueError(f"Unknown component: {component}")
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=30)
    output = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError(f"{component.upper()} health check failed: {output[:300]}")
    if component == "jdk":
        if f'"{version.split("+")[0]}' not in output:
            raise RuntimeError(f"Java reports an unexpected version: {output[:150]}")
    elif component == "node" and result.stdout.strip() != "v" + version:
        raise RuntimeError(f"Node reports {result.stdout.strip()}, expected v{version}")
    elif component == "rea" and result.stdout.strip() != version:
        raise RuntimeError(f"REA reports {result.stdout.strip()}, expected {version}")
    return f"{component.upper()} {version}: healthy"


class ComponentStore:
    def __init__(self):
        self.root = home()
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "active-components.json"
        try:
            self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.state = {}
        self.history_path = self.root / "component-history.json"
        try:
            self.history = json.loads(self.history_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.history = {}

    def current_version(self, component: str) -> str:
        entry = self.state.get(component, {})
        if isinstance(entry, dict) and Path(entry.get("path", "")).exists():
            return entry.get("version", PINNED[component])
        return PINNED[component]

    def active_path(self, component: str) -> Path | None:
        entry = self.state.get(component, {})
        if isinstance(entry, dict) and entry.get("path"):
            path = Path(entry["path"])
            if path.exists():
                return path
        return None

    def activate(self, component: str, version: str, path: Path):
        previous = self.state.get(component)
        if isinstance(previous, dict) and previous.get("path") and previous.get("path") != str(path.resolve()):
            entries = self.history.setdefault(component, [])
            if not entries or entries[-1].get("path") != previous["path"]:
                entries.append(previous)
            self.history[component] = entries[-10:]
        self.state[component] = {"version": version, "path": str(path.resolve()),
                                 "activated_at": datetime.now().astimezone().isoformat()}
        self._save()

    def _save(self):
        for path, data in ((self.state_path, self.state), (self.history_path, self.history)):
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(temporary, path)

    def rollback_targets(self, component: str) -> list[dict]:
        targets = [item for item in reversed(self.history.get(component, []))
                   if isinstance(item, dict) and item.get("path") and Path(item["path"]).exists()]
        bundled = bundled_component(component)
        if bundled and self.active_path(component) is not None and self.active_path(component) != bundled[1]:
            targets.append({"version": bundled[0], "path": str(bundled[1]), "bundled": True})
        return targets

    def rollback(self, component: str, notify):
        targets = self.rollback_targets(component)
        if not targets:
            raise RuntimeError(f"No previous {component.upper()} version is available")
        target = targets[0]
        check_component(component, Path(target["path"]), target["version"], self)
        current = self.state.get(component)
        if isinstance(current, dict) and current.get("path"):
            self.history.setdefault(component, []).append(current)
        self.history[component] = [item for item in self.history.get(component, [])
                                   if item.get("path") != target["path"]][-10:]
        self.state[component] = {"version": target["version"], "path": target["path"],
                                 "activated_at": datetime.now().astimezone().isoformat()}
        self._save()
        notify(f"Rolled back {component.upper()} to {target['version']}.")

    def analysis_paths(self, notify, cancelled) -> tuple[Path, Path, Path, Path]:
        tools = self.root / "Tools"
        tools.mkdir(parents=True, exist_ok=True)
        ghidra = self.active_path("ghidra")
        if ghidra is None:
            ghidra = unpack_tool(resource("archives", GHIDRA_ARCHIVE), GHIDRA_SHA256,
                                 "ghidra_12.1.4_PUBLIC", tools / "ghidra_12.1.4_PUBLIC",
                                 tools, notify, cancelled)
        jdk = self.active_path("jdk")
        if jdk is None:
            jdk = unpack_tool(resource("archives", JDK_ARCHIVE), JDK_SHA256,
                              "jdk-21.0.12.1+1", tools / "jdk-21.0.12.1+1",
                              tools, notify, cancelled)
        node = self.active_path("node") or resource("runtime", "node.exe")
        rea = self.active_path("rea") or resource("runtime", "node_modules", "rea-agents", "scripts", "rea.mjs")
        required = [ghidra / "support" / "analyzeHeadless.bat", jdk / "bin" / "java.exe", node, rea]
        if not all(path.is_file() for path in required):
            raise RuntimeError("An active analysis component is missing")
        return ghidra, jdk, node, rea


class UpdateManager:
    def __init__(self, store: ComponentStore):
        self.store = store

    def check(self) -> dict[str, dict]:
        findings: dict[str, dict] = {}
        errors: dict[str, str] = {}
        try:
            release = fetch_json("https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest", {"api.github.com"})
            version = re.search(r"Ghidra_(\d+\.\d+\.\d+)_build", release["tag_name"]).group(1)
            asset = next(a for a in release["assets"] if re.fullmatch(r"ghidra_.*_PUBLIC_\d+\.zip", a["name"]))
            checksum = re.search(r"SHA-256:\s*`([a-fA-F0-9]{64})`", release["body"]).group(1)
            findings["ghidra"] = {"version": version, "url": asset["browser_download_url"],
                                  "sha256": checksum, "archive": asset["name"], "source": release["html_url"]}
        except Exception as error:
            errors["ghidra"] = str(error)
        try:
            records = fetch_json("https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse", {"api.adoptium.net"})
            record = records[0]
            package = record["binary"]["package"]
            version = package["name"].split("_hotspot_")[1].removesuffix(".zip").replace("_", "+", 1)
            findings["jdk"] = {"version": version, "url": package["link"],
                               "sha256": package["checksum"], "archive": package["name"],
                               "source": "https://adoptium.net/temurin/releases/"}
        except Exception as error:
            errors["jdk"] = str(error)
        try:
            record = fetch_json("https://registry.npmjs.org/rea-agents/latest", {"registry.npmjs.org"})
            findings["rea"] = {"version": record["version"], "url": record["dist"]["tarball"],
                               "integrity": record["dist"].get("integrity", ""),
                               "source": "https://www.npmjs.com/package/rea-agents"}
        except Exception as error:
            errors["rea"] = str(error)
        try:
            releases = fetch_json("https://nodejs.org/dist/index.json", {"nodejs.org"})
            latest = next(item for item in releases if item["version"].startswith("v24."))
            version = latest["version"].removeprefix("v")
            base = f"https://nodejs.org/dist/v{version}/"
            archive = f"node-v{version}-win-x64.zip"
            sums = fetch_bytes(base + "SHASUMS256.txt", {"nodejs.org"}).decode("utf-8")
            checksum = next(line.split()[0] for line in sums.splitlines() if line.endswith("  " + archive))
            findings["node"] = {"version": version, "url": base + archive,
                                "sha256": checksum, "archive": archive, "source": "https://nodejs.org/en/download"}
        except Exception as error:
            errors["node"] = str(error)
        return {"components": findings, "errors": errors}

    def update(self, component: str, info: dict, notify, cancelled, set_process):
        version = info["version"]
        if not compatible_update(component, version):
            raise RuntimeError(f"Ghidra {version} is outside REA's supported Windows 12.1.x line")
        if not newer(version, self.store.current_version(component)):
            notify(f"{component.upper()} is already current ({self.store.current_version(component)}).")
            return
        tools = self.store.root / "Tools"
        downloads = self.store.root / "Downloads"
        tools.mkdir(parents=True, exist_ok=True)
        if component in {"ghidra", "jdk", "node"}:
            archive = download(info["url"], downloads / info["archive"], info["sha256"], notify, cancelled)
            with zipfile.ZipFile(archive) as zipped:
                root_name = zipped.infolist()[0].filename.split("/")[0]
            destination = tools / root_name
            path = unpack_tool(archive, info["sha256"], root_name, destination, tools, notify, cancelled)
            if component == "ghidra" and not (path / "support" / "analyzeHeadless.bat").is_file():
                raise RuntimeError("Downloaded Ghidra archive lacks analyzeHeadless.bat")
            if component == "jdk" and not (path / "bin" / "javac.exe").is_file():
                raise RuntimeError("Downloaded JDK archive lacks javac.exe")
            if component == "node":
                path = path / "node.exe"
                if not path.is_file():
                    raise RuntimeError("Downloaded Node archive lacks node.exe")
                completed = subprocess.run([str(path), "--version"], capture_output=True, text=True,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=20)
                if completed.returncode != 0 or completed.stdout.strip() != "v" + version:
                    raise RuntimeError("Downloaded Node runtime did not report the expected version")
            check_component(component, path, version, self.store)
            self.store.activate(component, version, path)
            notify(f"Activated {component.upper()} {version}.")
            return
        if component == "rea":
            node = self.store.active_path("node") or resource("runtime", "node.exe")
            pnpm = resource("runtime", "pnpm", "bin", "pnpm.cjs")
            if not pnpm.is_file():
                raise RuntimeError("Bundled package manager is missing")
            components = self.store.root / "Components"
            components.mkdir(parents=True, exist_ok=True)
            stage = components / ("rea-stage-" + uuid.uuid4().hex)
            stage.mkdir()
            try:
                args = [str(node), str(pnpm), "add", f"rea-agents@{version}", "--dir", str(stage),
                        "--config.node-linker=hoisted", "--ignore-scripts"]
                notify(f"Installing REA {version} and its dependencies…")
                process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, encoding="utf-8", errors="replace",
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                set_process(process)
                try:
                    for line in process.stdout:
                        if cancelled():
                            process.terminate()
                            raise InterruptedError("Update cancelled")
                        if line.strip() and ("Progress" not in line or "done" in line):
                            notify(line.strip())
                    if process.wait() != 0:
                        raise RuntimeError("REA package installation failed")
                finally:
                    set_process(None)
                cli = stage / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"
                if not cli.is_file():
                    raise RuntimeError("Installed REA CLI is missing")
                verify = subprocess.run([str(node), str(cli), "--version"], capture_output=True, text=True,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=30)
                if verify.returncode != 0 or verify.stdout.strip() != version:
                    raise RuntimeError("Installed REA did not report the expected version")
                destination = components / ("rea-" + version)
                if destination.exists():
                    safe_delete(destination, components)
                stage.rename(destination)
                installed = destination / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"
                check_component("rea", installed, version, self.store)
                self.store.activate("rea", version, installed)
                notify(f"Activated REA {version}.")
            finally:
                if stage.exists():
                    safe_delete(stage, components)


class AnalysisRunner:
    def __init__(self, store: ComponentStore, notify, cancelled, set_process):
        self.store = store
        self.notify = notify
        self.cancelled = cancelled
        self._external_set_process = set_process
        self._metrics = None
        self.set_process = self._track_process

    def _track_process(self, process):
        if self._metrics is not None:
            self._metrics.process(process)
        self._external_set_process(process)

    def _check(self):
        if self.cancelled():
            raise InterruptedError("Analysis cancelled")

    @staticmethod
    def _record_job(output: Path) -> None:
        index = home() / "investigation-jobs.json"
        try:
            paths = json.loads(index.read_text(encoding="utf-8"))
            if not isinstance(paths, list):
                paths = []
        except (OSError, ValueError):
            paths = []
        paths = [str(output.resolve())] + [path for path in paths if path != str(output.resolve())]
        temporary = index.with_suffix(".tmp")
        temporary.write_text(json.dumps(paths[:500], indent=2), encoding="utf-8")
        os.replace(temporary, index)

    def _run(self, args: list[str], log_path: Path, env: dict[str, str], output: Path | None = None,
             cwd: Path | None = None, timeout: int | None = None) -> int:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        expired = threading.Event()
        def watchdog(process):
            expired.set()
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   capture_output=True, creationflags=flags)
                if process.poll() is None:
                    process.kill()
        with log_path.open("w", encoding="utf-8", errors="replace") as log:
            if output is None:
                process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, encoding="utf-8", errors="replace", env=env,
                                           creationflags=flags, cwd=cwd)
                self.set_process(process)
                timer = threading.Timer(timeout, watchdog, args=(process,)) if timeout else None
                if timer: timer.start()
                try:
                    for line in process.stdout:
                        log.write(line)
                        if "CASTORPOLLUX_PROGRESS" in line or "REA_BINARY_STUDIO_PROGRESS" in line or "REA_BINARY_STUDIO_COMPLETE" in line:
                            self.notify(line.strip().split("> ")[-1])
                    code = process.wait()
                    if expired.is_set():
                        log.write(f"\nCastorPollux engine time limit exceeded: {timeout} seconds\n")
                        return 124
                    return code
                finally:
                    if timer: timer.cancel()
                    self.set_process(None)
            with output.open("wb") as result:
                process = subprocess.Popen(args, stdout=result, stderr=log, env=env, creationflags=flags, cwd=cwd)
                self.set_process(process)
                timer = threading.Timer(timeout, watchdog, args=(process,)) if timeout else None
                if timer: timer.start()
                try:
                    code = process.wait()
                    if expired.is_set():
                        log.write(f"\nCastorPollux engine time limit exceeded: {timeout} seconds\n")
                        return 124
                    return code
                finally:
                    if timer: timer.cancel()
                    self.set_process(None)

    def run(self, source: Path, destination: Path, resume_folder: Path | None = None,
            symbols: Path | None = None, symbol_server: str | None = None) -> Path:
        source = Path(source).resolve()
        destination = Path(destination).resolve()
        if symbols and symbol_server:
            raise ValueError("Choose either a local symbol file or an online server")
        if symbols:
            from castorpollux_symbols import verify_symbols
            verify_symbols(source, symbols)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        output = Path(resume_folder).resolve() if resume_folder else destination / (safe_name(source.stem) + "-" + stamp)
        output.mkdir(parents=True, exist_ok=bool(resume_folder))
        from castorpollux_metrics import ScanMetrics
        metrics = ScanMetrics(output, stamp)
        self._metrics = metrics
        warnings: list[str] = []
        manifest = {
            "application": APP_NAME, "application_version": APP_VERSION,
            "input_name": source.name, "input_path": str(source), "input_bytes": source.stat().st_size,
            "sha256": "", "started_at": datetime.now().astimezone().isoformat(), "finished_at": "",
            "versions": {key: self.store.current_version(key) for key in PINNED},
            "warnings": warnings, "ghidra_status": "pending", "rea_status": "pending",
            "rea_decompile_status": "pending",
            "scan_metrics": "scan-metrics.json",
        }
        if resume_folder:
            manifest_path = output / "manifest.json"
            if not manifest_path.is_file():
                raise ValueError("The selected folder has no investigation manifest")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.setdefault("scan_metrics", "scan-metrics.json")
            warnings = manifest.setdefault("warnings", [])
            retryable_warnings = ("Data-flow lead generation failed", "Cross-function flow scan failed",
                                  "Secret evidence scan failed", "Third-party fingerprint scan failed",
                                  "DLL signature inventory failed", "Indirect-call scan failed",
                                  "Assembly cross-check failed", "Advanced graph scan failed",
                                  "Overflow triage failed")
            warnings[:] = [warning for warning in warnings if not str(warning).startswith(retryable_warnings)]
            manifest["resumed_at"] = datetime.now().astimezone().isoformat()
            saved = output / manifest.get("saved_binary", "")
            if not saved.is_file() or sha256(saved) != manifest.get("sha256"):
                raise ValueError("Cannot resume: the saved binary is missing or its checksum changed")
            source = saved
        if not manifest.get("sha256"):
            manifest["sha256"] = sha256(source)
        def stage(percent: int, label: str) -> None:
            metrics.stage(label, percent)
            manifest["progress"] = {"percent": percent, "stage": label}
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self.notify(f"CASTORPOLLUX_STAGE {percent} {label}")

        stage(2, "Preparing engines")
        self._record_job(output)
        jobs = self.store.root / "Jobs"
        job = jobs / ("job-" + uuid.uuid4().hex)
        metrics_status = "failed"
        try:
            self.notify("Preparing analysis engines…")
            ghidra, jdk, node, rea = self.store.analysis_paths(self.notify, self.cancelled)
            from castorpollux_preflight import engine_compatibility
            from castorpollux_settings import load_settings
            limits = load_settings()
            compatibility = engine_compatibility(self.store, (ghidra, jdk, node, rea))
            manifest["engine_compatibility"] = compatibility
            (output / "engine-compatibility.json").write_text(json.dumps(compatibility, indent=2), encoding="utf-8")
            if compatibility["status"] != "compatible":
                raise RuntimeError("Engine compatibility check blocked scanning: " + "; ".join(compatibility["errors"]))
            self._check()
            stage(8, "Verifying binary")
            manifest["sha256"] = sha256(source)
            job.mkdir(parents=True)
            staged = source if resume_folder else output / ("source-binary" + source.suffix.lower()[:10])
            if not resume_folder:
                self.notify("Copying and verifying target bytes…")
                shutil.copyfile(source, staged)
                if sha256(staged) != manifest["sha256"]:
                    raise RuntimeError("Target changed while being copied")
            manifest["saved_binary"] = staged.name
            stage(14, "Checking symbols")
            if symbol_server and not resume_folder:
                from castorpollux_symbols import lookup_symbols
                from castorpollux_settings import approved_server, load_settings
                self.notify("Looking up symbols online (explicit opt-in)…")
                try:
                    policy = load_settings()
                    server = approved_server(symbol_server, policy)
                    symbols, provenance = lookup_symbols(staged, output / "Symbols", server,
                        home() / "SymbolCache", policy["symbol_cache_days"], policy["symbol_cache_mb"])
                    manifest["symbol_download"] = provenance
                    self.notify("Verified symbols from local cache." if provenance.get("cache_hit") else
                                "Downloaded symbol identity verified against the binary.")
                except Exception as error:
                    if optional_symbols_not_found(error):
                        manifest["symbol_download"] = {"status": "not_found", "server": symbol_server,
                                                       "http_status": 404,
                                                       "message": "No matching symbol file was found on the configured server."}
                        self.notify("No matching symbols were found on the configured server; continuing without symbols.")
                    else:
                        from castorpollux_diagnostics import record_error
                        mismatch = symbol_lookup_failure_class(error) == "identity_mismatch"
                        if not mismatch:
                            record_error(str(error), output, "optional symbol lookup")
                        manifest["symbol_download"] = {"status": "identity_mismatch" if mismatch else "failed",
                                                       "server": symbol_server, "error": str(error),
                                                       "failure_class": "identity_mismatch" if mismatch else "lookup_failed"}
                        if mismatch:
                            warnings.append("Online symbols rejected: " + str(error))
                            self.notify("Online symbols did not match this exact build (PDB GUID/age or ELF build ID). "
                                        "They were rejected; scan continues without symbols. Choose symbols from the "
                                        "exact build or disable optional lookup. Details saved in manifest.json.")
                        else:
                            warnings.append("Optional online symbol lookup failed: " + str(error))
                            self.notify(f"Optional symbol lookup failed: {error}. Continuing without symbols; details saved in manifest.json.")
            if symbols:
                symbol_source = Path(symbols).resolve()
                if not symbol_source.is_file():
                    raise ValueError("The selected symbol file is missing")
                from castorpollux_symbols import verify_symbols
                self.notify("Verifying symbol identity against the target…")
                verification = verify_symbols(staged, symbol_source)
                kind = verification["kind"]
                symbols_dir = output / "Symbols"
                symbols_dir.mkdir(exist_ok=True)
                copied = symbols_dir / symbol_source.name
                if symbol_source != copied.resolve():
                    shutil.copy2(symbol_source, copied)
                manifest["symbols"] = {"kind": kind, "file": str(copied.relative_to(output)),
                                       "sha256": sha256(copied), "status": "identity_verified",
                                       "identity": verification["identity"]}
            symbol_info = manifest.get("symbols") or {}
            symbol_file = output / symbol_info["file"] if symbol_info.get("file") else None
            if symbol_file and (not symbol_file.is_file() or sha256(symbol_file) != symbol_info.get("sha256")):
                raise ValueError("The saved symbol file is missing or its checksum changed")
            if symbol_file:
                from castorpollux_symbols import verify_symbols
                verified = verify_symbols(staged, symbol_file)
                if symbol_info.get("identity") and verified["identity"] != symbol_info["identity"]:
                    raise ValueError("Saved symbol identity changed")
            if "target_signature" not in manifest:
                from castorpollux_integrity import authenticode_status
                self.notify("Checking target code signature…")
                manifest["target_signature"] = authenticode_status(staged)
            from castorpollux_binary_profile import detect_binary_profile
            if "binary_profile" not in manifest:
                manifest["binary_profile"] = detect_binary_profile(staged)
                (output / "binary-profile.json").write_text(json.dumps(manifest["binary_profile"], indent=2),
                                                              encoding="utf-8")
                self.notify(f"Target: {manifest['binary_profile']['format']} / "
                            f"{manifest['binary_profile']['architecture']}; compiler "
                            f"{manifest['binary_profile']['compiler']['name']}.")
            stage(20, "Running Ghidra")
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self._record_job(output)
            project = job / "project"
            exports = job / "exports"
            # A stopped headless run can leave either directory behind. Reuse the
            # project for resume and keep only exports made by the new attempt.
            project.mkdir(exist_ok=True)
            exports.mkdir(exist_ok=True)
            env = os.environ.copy()
            env.update({"JAVA_HOME": str(jdk), "GHIDRA_INSTALL_DIR": str(ghidra),
                        "GHIDRA_HEADLESS_MAXMEM": str(limits["ghidra_heap_mb"]) + "M",
                        "NODE_OPTIONS": "--max-old-space-size=" + str(limits["rea_heap_mb"])})
            manifest["engine_limits"] = {key: limits[key] for key in
                ("ghidra_timeout_seconds", "rea_timeout_seconds", "ghidra_heap_mb", "rea_heap_mb")}
            env["PATH"] = str(jdk / "bin") + os.pathsep + env.get("PATH", "")
            self._check()
            ghidra_done = (manifest.get("ghidra_status") == "complete" and
                           (output / "pseudocode.c").is_file() and
                           (output / "functions.csv").is_file())
            if ghidra_done:
                self.notify("Ghidra: reusing completed exports…")
            else:
                manifest["ghidra_status"] = "running"
                (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                self.notify("Ghidra: importing and analyzing binary…")
                previous_log = output / "ghidra.log"
                attempts_dir = output / "GhidraAttempts"
                if previous_log.is_file():
                    attempts_dir.mkdir(exist_ok=True)
                    old_name = f"ghidra-{stamp}.log"
                    shutil.move(str(previous_log), str(attempts_dir / old_name))
                    manifest.setdefault("ghidra_attempts", []).append({"preserved_log": "GhidraAttempts/" + old_name})
                for name in ("ghidra-summary.json", "functions.csv", "pseudocode.c"):
                    old_export = output / name
                    if old_export.is_file():
                        attempts_dir.mkdir(exist_ok=True)
                        shutil.move(str(old_export), str(attempts_dir / f"{stamp}-{name}"))
                    (exports / name).unlink(missing_ok=True)
                script_dir = resource("scripts")
                staged_scripts = job / "scripts"
                staged_scripts.mkdir()
                for name in ("ExportBinaryStudio.java", "CastorPolluxSymbols.java"):
                    script = script_dir / name
                    if not script.is_file():
                        raise RuntimeError(f"Bundled Ghidra script is missing: {script}")
                    shutil.copy2(script, staged_scripts / name)
                command = [str(ghidra / "support" / "analyzeHeadless.bat"), str(project), "Analysis",
                           "-import", str(staged), "-scriptPath", str(staged_scripts)]
                if symbol_file:
                    self.notify(f"Ghidra: loading local {symbol_info['kind'].upper()} symbols…")
                    command += ["-preScript", "CastorPolluxSymbols.java", symbol_info["kind"], str(symbol_file)]
                command += ["-analysisTimeoutPerFile", str(limits["ghidra_timeout_seconds"]),
                            "-postScript", "ExportBinaryStudio.java", str(exports)]
                code = self._run(command, output / "ghidra.log", env, cwd=job,
                                 timeout=limits["ghidra_timeout_seconds"] + 60)
                for item in exports.iterdir():
                    shutil.copy2(item, output / item.name)
                if any(project.iterdir()):
                    project_output = output / "GhidraProject"
                    if project_output.exists():
                        safe_delete(project_output, output)
                    shutil.move(str(project), str(project_output))
                manifest["ghidra_exit_code"] = code
                expected_exports = ("ghidra-summary.json", "functions.csv", "pseudocode.c")
                manifest["ghidra_exports"] = {name: (output / name).is_file() for name in expected_exports}
                if code == 0 and all(manifest["ghidra_exports"].values()):
                    manifest["ghidra_status"] = "complete"
                    manifest.pop("ghidra_failure_reason", None)
                    warnings[:] = [warning for warning in warnings
                                   if not str(warning).startswith(("Ghidra failed", "Ghidra partial"))]
                    if symbol_file:
                        log_text = (output / "ghidra.log").read_text(encoding="utf-8", errors="replace")
                        configured = "CASTORPOLLUX_SYMBOLS " + symbol_info["kind"].upper() + " configured" in log_text
                        manifest["symbols"]["status"] = "configured" if configured else "failed"
                        manifest["symbols"]["note"] = "Check ghidra.log and exported function names to confirm symbol application."
                        if not configured:
                            warnings.append("The optional symbol pre-script did not confirm configuration; inspect ghidra.log.")
                else:
                    has_source = (output / "pseudocode.c").is_file() and (output / "functions.csv").is_file()
                    manifest["ghidra_status"] = "partial" if has_source else "failed"
                    try:
                        lines = (output / "ghidra.log").read_text(encoding="utf-8", errors="replace").splitlines()
                        errors = [line.strip() for line in lines if re.search(r"\b(ERROR|Exception|FATAL)\b", line, re.I)]
                        reason = (errors[-1] if errors else next((line.strip() for line in reversed(lines) if line.strip()),
                                                                  "No diagnostic line was emitted"))[:500]
                    except OSError:
                        reason = "ghidra.log was not written"
                    manifest["ghidra_failure_reason"] = reason
                    from castorpollux_diagnostics import record_error
                    record_error(f"Ghidra {manifest['ghidra_status']} (exit {code}): {reason}", output, "ghidra")
                    if symbol_file:
                        manifest["symbols"]["status"] = "failed"
                    warnings.append(f"Ghidra {manifest['ghidra_status']} (exit {code}): {reason}. Inspect ghidra.log.")
                    self.notify(warnings[-1])
                (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self._check()
            stage(48, "Collecting REA evidence")
            rea_done = manifest.get("rea_status") == "complete" and (output / "rea-evidence.json").is_file()
            if rea_done:
                try:
                    json.loads((output / "rea-evidence.json").read_text(encoding="utf-8-sig"))
                except (OSError, ValueError):
                    rea_done = False
            if rea_done:
                self.notify("REA: reusing completed evidence…")
            else:
                manifest["rea_status"] = "running"
                (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                self.notify("REA: generating evidence JSON…")
                code = self._run([str(node), str(rea), "analyze", str(staged), "--provider", "ghidra", "--format", "json",
                                  "--snapshot", str(output / "rea-snapshot.json")],
                                 output / "rea.log", env, output / "rea-evidence.json",
                                 timeout=limits["rea_timeout_seconds"])
                if code != 0 and (output / "rea-snapshot.json").is_file():
                    try:
                        error = json.loads((output / "rea-evidence.json").read_text(encoding="utf-8-sig"))
                    except (OSError, ValueError):
                        error = {}
                    if error.get("code") == "evidence_integrity_mismatch":
                        archive = output / ("rea-snapshot-invalid-" + stamp + ".json")
                        shutil.move(str(output / "rea-snapshot.json"), str(archive))
                        self.notify("REA snapshot did not match; archived it and retrying fresh analysis…")
                        code = self._run([str(node), str(rea), "analyze", str(staged), "--provider", "ghidra", "--format", "json",
                                          "--snapshot", str(output / "rea-snapshot.json")],
                                         output / "rea.log", env, output / "rea-evidence.json",
                                         timeout=limits["rea_timeout_seconds"])
                if code == 0:
                    try:
                        json.loads((output / "rea-evidence.json").read_text(encoding="utf-8-sig"))
                        manifest["rea_status"] = "complete"
                        warnings[:] = [warning for warning in warnings if not str(warning).startswith(
                            ("REA evidence was unavailable", "REA returned invalid JSON"))]
                    except (OSError, ValueError):
                        manifest["rea_status"] = "invalid_output"
                        warnings.append("REA returned invalid JSON; inspect rea.log.")
                else:
                    manifest["rea_status"] = "failed"
                    from castorpollux_diagnostics import record_error
                    record_error(f"REA evidence failed (exit {code}); inspect rea.log", output, "rea evidence")
                    warnings.append("REA evidence was unavailable for this binary; inspect rea.log.")
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            stage(64, "Decompiling with REA")
            rea_source_done = (manifest.get("rea_decompile_status") == "complete" and
                               (output / "rea-pseudocode.c").is_file() and
                               (output / "rea-decompilation.json").is_file())
            if rea_source_done:
                self.notify("REA: reusing completed reconstructed source…")
            elif manifest["rea_status"] == "complete":
                from castorpollux_rea import decompile_with_rea
                manifest["rea_decompile_status"] = "running"
                (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                try:
                    def decompile_progress(message: str) -> None:
                        self.notify(message)
                        match = re.search(r"REA decompilation: (\d+)/(\d+) processed", message)
                        if match:
                            fraction = int(match.group(1)) / max(1, int(match.group(2)))
                            stage(64 + int(30 * fraction), "Decompiling with REA")
                    counts = decompile_with_rea(staged, output, node, rea, jdk, ghidra,
                                                manifest["sha256"], decompile_progress, self.cancelled,
                                                self.set_process, limits["rea_timeout_seconds"],
                                                limits["rea_heap_mb"])
                    manifest["rea_decompile_status"] = "complete" if counts["failed"] == 0 else "partial"
                    manifest["rea_decompile_counts"] = counts
                    if not counts["failed"]:
                        warnings[:] = [warning for warning in warnings if not str(warning).startswith(
                            ("REA decompilation failed", "REA could not reconstruct", "REA decompilation was blocked"))]
                    if counts["failed"]:
                        warnings.append(f"REA could not reconstruct {counts['failed']} of {counts['total']} procedures.")
                except InterruptedError:
                    raise
                except Exception as error:
                    manifest["rea_decompile_status"] = "failed"
                    from castorpollux_diagnostics import record_error
                    record_error(str(error), output, "rea decompilation")
                    warnings.append(f"REA decompilation failed: {error}")
                    self.notify(f"REA decompilation failed: {error}")
            else:
                manifest["rea_decompile_status"] = "blocked"
                warnings.append("REA decompilation was blocked because REA analysis did not complete.")
            if manifest["rea_decompile_status"] in ("complete", "partial"):
                stage(95, "Scanning security evidence")
                try:
                    from castorpollux_flow import build_data_flow
                    self.notify("Tracing candidate input-to-sink data flows…")
                    flow = build_data_flow(output)
                    manifest["data_flow_leads"] = len(flow["leads"])
                except Exception as error:
                    from castorpollux_diagnostics import record_error
                    record_error(str(error), output, "data flow")
                    warnings.append(f"Data-flow lead generation failed: {error}")
                try:
                    from castorpollux_interflow import build_cross_function_flow
                    interflow = build_cross_function_flow(output)
                    manifest["cross_function_flow_leads"] = len(interflow["leads"])
                    self.notify(f"Cross-function data flow: {len(interflow['leads'])} candidate(s).")
                except Exception as error:
                    from castorpollux_diagnostics import record_error
                    record_error(str(error), output, "cross-function data flow")
                    warnings.append(f"Cross-function flow scan failed: {error}")
                try:
                    from castorpollux_secrets import scan_secrets
                    self.notify("Scanning saved evidence for possible credentials…")
                    secrets = scan_secrets(output)
                    manifest["secret_leads"] = secrets["count"]
                except Exception as error:
                    from castorpollux_diagnostics import record_error
                    record_error(str(error), output, "secret scan")
                    warnings.append(f"Secret evidence scan failed: {error}")
            try:
                summary = json.loads((output / "ghidra-summary.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                summary = None
            if summary:
                manifest["binary_profile"] = detect_binary_profile(staged, summary)
                (output / "binary-profile.json").write_text(json.dumps(manifest["binary_profile"], indent=2),
                                                              encoding="utf-8")
            try:
                from castorpollux_binary_profile import scan_embedded_libraries
                libraries = scan_embedded_libraries(staged, output)
                manifest["embedded_library_candidates"] = len(libraries["libraries"])
                self.notify(f"Third-party fingerprint scan: {len(libraries['libraries'])} candidate(s).")
                if (output / "SBOM" / "imported.json").is_file():
                    from castorpollux_sbom import compare_sbom
                    compare_sbom(output)
            except Exception as error:
                from castorpollux_diagnostics import record_error
                record_error(str(error), output, "third-party fingerprint")
                warnings.append(f"Third-party fingerprint scan failed: {error}")
            try:
                from castorpollux_evidence_tools import dll_signature_inventory
                original = Path(manifest.get("input_path", ""))
                inventory = dll_signature_inventory(output, original if original.is_file() and
                                                   sha256(original) == manifest.get("sha256") else staged)
                self.notify(f"DLL signature inventory: {len(inventory['dlls'])} imported name(s).")
            except Exception as error:
                from castorpollux_diagnostics import record_error
                record_error(str(error), output, "DLL signature inventory")
                warnings.append(f"DLL signature inventory failed: {error}")
            try:
                from castorpollux_indirect import resolve_indirect_calls
                indirect = resolve_indirect_calls(output)
                manifest["indirect_call_candidates"] = len(indirect["resolved"])
                self.notify(f"Indirect-call candidates: {len(indirect['resolved'])} resolved, "
                            f"{len(indirect['unresolved'])} unresolved.")
            except Exception as error:
                from castorpollux_diagnostics import record_error
                record_error(str(error), output, "indirect calls")
                warnings.append(f"Indirect-call scan failed: {error}")
            try:
                from castorpollux_consistency import check_consistency
                consistency = check_consistency(output)
                manifest["consistency_counts"] = consistency["summary"]
                self.notify(f"Assembly cross-check: {consistency['summary']['review']} review lead(s).")
            except Exception as error:
                from castorpollux_diagnostics import record_error
                record_error(str(error), output, "assembly cross-check")
                warnings.append(f"Assembly cross-check failed: {error}")
            try:
                from castorpollux_advanced import build_advanced_graph, check_call_edges
                advanced = build_advanced_graph(output)
                edges = check_call_edges(output)
                manifest["ssa_ops"] = advanced["ssa_ops"]
                manifest["ssa_source_sink_leads"] = advanced["ssa_source_sink_count"]
                manifest["virtual_dispatch_leads"] = advanced["virtual_dispatch_leads"]
                manifest["jump_tables"] = advanced["jump_tables"]
                manifest["disputed_call_edges"] = edges["disputed"]
                self.notify(f"Advanced graph: {advanced['ssa_ops']} SSA ops, "
                            f"{advanced['virtual_dispatch_leads']} virtual-call leads, "
                            f"{advanced['jump_tables']} jump tables.")
            except Exception as error:
                from castorpollux_diagnostics import record_error
                record_error(str(error), output, "advanced graph")
                warnings.append(f"Advanced graph scan failed: {error}")
            if manifest.get("rea_decompile_status") in ("complete", "partial"):
                try:
                    from castorpollux_overflow import scan_overflows
                    overflow = scan_overflows(output)
                    manifest["overflow_leads"] = overflow["count"]
                    self.notify(f"Buffer-boundary review: {overflow['count']} candidate(s).")
                except Exception as error:
                    from castorpollux_diagnostics import record_error
                    record_error(str(error), output, "overflow triage")
                    warnings.append(f"Overflow triage failed: {error}")
            manifest["finished_at"] = datetime.now().astimezone().isoformat()
            stage(99, "Writing investigation summary")
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            write_report(output, manifest, summary)
            stage(100, "Analysis complete")
            self.notify(f"Analysis complete: {output}")
            metrics_status = "complete" if all(manifest.get(key) == "complete" for key in
                ("ghidra_status", "rea_status", "rea_decompile_status")) else "incomplete"
            return output
        except Exception as error:
            metrics_status = "cancelled" if isinstance(error, InterruptedError) else "failed"
            from castorpollux_diagnostics import record_error
            record_error(str(error), output, "analysis")
            manifest["finished_at"] = datetime.now().astimezone().isoformat()
            warnings.append(str(error))
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self.notify(f"Analysis stopped: {error}. Partial output: {output}")
            return output
        finally:
            try:
                metrics.finish(metrics_status, manifest)
            except Exception as error:
                from castorpollux_diagnostics import record_error
                record_error(str(error), output, "scan metrics")
            self._metrics = None
            if job.exists():
                safe_delete(job, jobs)
