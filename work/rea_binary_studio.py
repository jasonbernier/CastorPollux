"""Portable Windows GUI for complete local REA and Ghidra binary exports."""

from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import uuid
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
import tkinter as tk
from tkinter import filedialog, messagebox


APP = "REA Binary Studio"
GHIDRA_VERSION = "12.1.4"
JDK_VERSION = "21.0.12.1+1"
REA_VERSION = "6.5.0"
GHIDRA_ARCHIVE = "ghidra_12.1.4_PUBLIC_20260921.zip"
JDK_ARCHIVE = "OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip"
GHIDRA_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
JDK_SHA256 = "f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e"

BG = "#0e1725"
PANEL = "#18283c"
FIELD = "#263c55"
FG = "#e9f1fa"
MUTED = "#abc0d2"
ACCENT = "#63d0be"


def bundled_path(*parts: str) -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).parent)).joinpath(*parts)


def app_data() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / APP


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_delete(path: Path, root: Path) -> None:
    # Windows app virtualization can resolve a child under LocalCache while its
    # parent still resolves to LOCALAPPDATA. Validate the direct parent and
    # reject reparse points before removing an application-created directory.
    if path.parent.resolve() != root.resolve() or path.is_symlink() or path.is_junction():
        raise ValueError("Refusing to remove a path outside the application cache")
    if path.exists():
        shutil.rmtree(path)


def unpack_tool(archive: Path, digest: str, root_name: str, destination: Path,
                cache: Path, report, cancelled) -> Path:
    marker = destination / ".rea-binary-studio-ready"
    if marker.is_file() and marker.read_text(encoding="utf-8").strip() == digest:
        return destination
    if cancelled():
        raise InterruptedError("Cancelled")
    report(f"Verifying {archive.name}…")
    if sha256(archive) != digest:
        raise RuntimeError(f"Bundled archive failed its SHA-256 check: {archive.name}")
    stage = cache / ("unpack-" + uuid.uuid4().hex)
    stage.mkdir(parents=True)
    try:
        report(f"Unpacking {root_name}. First use may take a minute…")
        with zipfile.ZipFile(archive) as zipped:
            for index, item in enumerate(zipped.infolist()):
                name = PurePosixPath(item.filename)
                if name.is_absolute() or ".." in name.parts or name.parts[0] != root_name:
                    raise RuntimeError("Unexpected path in bundled archive")
                if cancelled():
                    raise InterruptedError("Cancelled")
                zipped.extract(item, stage)
                if index and index % 2500 == 0:
                    report(f"Unpacking {root_name}: {index:,} files…")
        source = stage / root_name
        if not source.is_dir():
            raise RuntimeError(f"Missing {root_name} after unpacking")
        if destination.exists():
            safe_delete(destination, cache)
        source.rename(destination)
        marker.write_text(digest, encoding="utf-8")
        return destination
    finally:
        safe_delete(stage, cache)


def safe_name(name: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_-]", "_", name)[:40]
    return result or "binary"


def read_csv_preview(path: Path, limit: int = 100) -> list[list[str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        return [row for _, row in zip(range(limit + 1), reader)]


def write_report(folder: Path, manifest: dict, summary: dict | None) -> None:
    counts = (summary or {}).get("counts", {})
    files = [
        ("Saved input binary", manifest.get("saved_binary", "")),
        ("Ghidra project", "GhidraProject/Analysis.gpr"),
        ("Decompiled pseudocode", "pseudocode.c"),
        ("Disassembly", "disassembly.txt"),
        ("Functions", "functions.csv"),
        ("Calls", "calls.csv"),
        ("Cross-references", "xrefs.csv"),
        ("Strings", "strings.csv"),
        ("Symbols", "symbols.csv"),
        ("Imports", "imports.csv"),
        ("Sections", "sections.csv"),
        ("REA evidence", "rea-evidence.json"),
        ("REA snapshot", "rea-snapshot.json"),
        ("Ghidra summary", "ghidra-summary.json"),
        ("Run manifest", "manifest.json"),
        ("Ghidra log", "ghidra.log"),
        ("REA log", "rea.log"),
    ]
    links = "\n".join(
        f'<li><a href="{html.escape(path, quote=True)}">{html.escape(label)}</a></li>'
        for label, path in files if path and (folder / path).exists()
    )
    metrics = "\n".join(
        f"<tr><th>{html.escape(key.replace('_', ' ').title())}</th><td>{value:,}</td></tr>"
        for key, value in counts.items() if isinstance(value, int)
    )
    functions = read_csv_preview(folder / "functions.csv", 100)
    function_rows = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(cell)}</td>" for cell in row[:3]) + "</tr>"
        for row in functions[1:]
    )
    warnings = "\n".join(f"<li>{html.escape(w)}</li>" for w in manifest.get("warnings", []))
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Binary analysis: {html.escape(manifest['input_name'])}</title>
<style>body{{font:15px/1.55 Segoe UI,Arial,sans-serif;background:#0e1725;color:#e9f1fa;margin:0 auto;max-width:1100px;padding:32px}}
h1,h2{{color:#63d0be}} a{{color:#8bd9fb}} table{{border-collapse:collapse;width:100%}} th,td{{border-bottom:1px solid #34445a;padding:8px;text-align:left;vertical-align:top}}
.card{{background:#18283c;border-radius:12px;padding:20px;margin:18px 0}} code{{overflow-wrap:anywhere}} ul{{columns:2}}</style></head><body>
<h1>Binary analysis</h1><p><strong>{html.escape(manifest['input_name'])}</strong></p>
<div class="card"><p>Original path: <code>{html.escape(manifest['input_path'])}</code><br>
SHA-256: <code>{html.escape(manifest['sha256'])}</code><br>
Size: {manifest['input_bytes']:,} bytes<br>Analyzed: {html.escape(manifest['finished_at'])}</p></div>
<div class="card"><h2>Results</h2><table>{metrics}</table></div>
<div class="card"><h2>Files</h2><ul>{links}</ul></div>
<div class="card"><h2>Functions (first 100)</h2><table><tr><th>Entry</th><th>Name</th><th>Signature</th></tr>{function_rows}</table></div>
<div class="card"><h2>Notes</h2><ul>{warnings}</ul><p>Pseudocode is Ghidra's reconstruction, not the original source code. Unsupported functions and analysis limits are recorded in the output files.</p></div>
</body></html>"""
    (folder / "report.html").write_text(page, encoding="utf-8")


class BinaryStudio:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(APP)
        root.geometry("930x680")
        root.minsize(730, 520)
        root.configure(bg=BG)
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar(value=str(Path.home() / "Documents" / "REA Analyses"))
        self.status = tk.StringVar(value="Ready to analyze a binary")
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.stop_requested = threading.Event()
        self.process: subprocess.Popen | None = None
        self.running = False
        self.last_output: Path | None = None
        self._ui()
        root.after(100, self._poll)
        root.protocol("WM_DELETE_WINDOW", self._close)

    def _label(self, parent, text: str, color=MUTED, size=10, bold=False):
        return tk.Label(parent, text=text, bg=parent["bg"], fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), anchor="w")

    def _button(self, parent, text: str, command, primary=False):
        return tk.Button(parent, text=text, command=command, relief="flat", padx=16, pady=8,
                         bg=ACCENT if primary else FIELD, fg="#08242c" if primary else FG,
                         activebackground="#8fe8db", font=("Segoe UI", 10, "bold" if primary else "normal"),
                         cursor="hand2")

    def _path_row(self, parent, title, variable, button_text, command):
        self._label(parent, title, size=10, bold=True).pack(fill="x", pady=(0, 6))
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill="x", pady=(0, 18))
        tk.Entry(row, textvariable=variable, relief="flat", bg=FIELD, fg=FG,
                 insertbackground=FG, font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True, ipady=8)
        self._button(row, button_text, command).pack(side="left", padx=(10, 0))

    def _ui(self):
        shell = tk.Frame(self.root, bg=BG, padx=28, pady=24)
        shell.pack(fill="both", expand=True)
        self._label(shell, "REA Binary Studio", FG, 22, True).pack(fill="x")
        self._label(shell, "One binary in. A complete local analysis folder out.", MUTED, 10).pack(fill="x", pady=(4, 20))
        card = tk.Frame(shell, bg=PANEL, padx=20, pady=18)
        card.pack(fill="x")
        self._path_row(card, "Binary to analyze", self.input_path, "Choose binary…", self._choose_input)
        self._path_row(card, "Save results under", self.output_path, "Choose folder…", self._choose_output)
        self._label(card, "Includes Ghidra 12.1.4, Temurin JDK 21, and REA 6.5.0. First analysis unpacks the tools locally.",
                    MUTED, 9).pack(fill="x")

        actions = tk.Frame(shell, bg=BG)
        actions.pack(fill="x", pady=(18, 10))
        self.run_button = self._button(actions, "Analyze binary", self._start, True)
        self.run_button.pack(side="left")
        self.cancel_button = self._button(actions, "Cancel", self._cancel)
        self.cancel_button.pack(side="left", padx=(10, 0))
        self.cancel_button.configure(state="disabled")
        self._button(actions, "Open last output", self._open_output).pack(side="right")
        self._label(shell, "Output: Ghidra project, pseudocode, disassembly, inventories, report, JSON evidence, and logs.",
                    MUTED, 9).pack(fill="x", pady=(0, 8))
        self._label(shell, "Status", MUTED, 10, True).pack(fill="x")
        tk.Label(shell, textvariable=self.status, bg=BG, fg=ACCENT, anchor="w",
                 font=("Segoe UI", 10)).pack(fill="x", pady=(3, 8))
        log_frame = tk.Frame(shell, bg=PANEL, padx=10, pady=10)
        log_frame.pack(fill="both", expand=True)
        self.log = tk.Text(log_frame, bg="#0a1320", fg=FG, borderwidth=0, wrap="word",
                           padx=12, pady=10, font=("Consolas", 9), state="disabled")
        scroll = tk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._append("Choose a binary and an output folder, then click Analyze binary.\n")

    def _append(self, message: str):
        self.log.configure(state="normal")
        self.log.insert("end", message + ("" if message.endswith("\n") else "\n"))
        self.log.see("end")
        self.log.configure(state="disabled")

    def _choose_input(self):
        path = filedialog.askopenfilename(title="Choose a binary to analyze")
        if path:
            self.input_path.set(path)

    def _choose_output(self):
        path = filedialog.askdirectory(title="Choose where results will be saved")
        if path:
            self.output_path.set(path)

    def _post(self, kind: str, message: str):
        self.events.put((kind, message))

    def _poll(self):
        try:
            while True:
                kind, message = self.events.get_nowait()
                if kind == "status":
                    self.status.set(message)
                    self._append(message)
                elif kind == "log":
                    self._append(message)
                elif kind == "done":
                    self.running = False
                    self.run_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    self.status.set(message)
                    self._append(message)
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(100, self._poll)

    def _start(self):
        if self.running:
            return
        source = Path(self.input_path.get().strip().strip('"')).expanduser()
        destination = Path(self.output_path.get().strip().strip('"')).expanduser()
        if not source.is_file():
            messagebox.showerror(APP, "Choose an existing binary file.")
            return
        if not self.output_path.get().strip():
            messagebox.showerror(APP, "Choose an output folder.")
            return
        try:
            destination.mkdir(parents=True, exist_ok=True)
            if not destination.is_dir():
                raise OSError("Output path is not a folder")
        except OSError as error:
            messagebox.showerror(APP, str(error))
            return
        self.stop_requested.clear()
        self.running = True
        self.run_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        threading.Thread(target=self._worker, args=(source.resolve(), destination.resolve()), daemon=True).start()

    def _check_cancel(self):
        if self.stop_requested.is_set():
            raise InterruptedError("Analysis cancelled")

    def _run_command(self, args: list[str], log_path: Path, env: dict[str, str], output: Path | None = None) -> int:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with log_path.open("w", encoding="utf-8", errors="replace") as log:
            if output is None:
                self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                text=True, encoding="utf-8", errors="replace", env=env,
                                                creationflags=flags)
                assert self.process.stdout is not None
                for line in self.process.stdout:
                    log.write(line)
                    if "REA_BINARY_STUDIO_PROGRESS" in line or "REA_BINARY_STUDIO_COMPLETE" in line:
                        self._post("status", line.strip().split("REA_BINARY_STUDIO_")[-1])
                code = self.process.wait()
            else:
                with output.open("wb") as result:
                    self.process = subprocess.Popen(args, stdout=result, stderr=log, env=env,
                                                    creationflags=flags)
                    code = self.process.wait()
        self.process = None
        return code

    def _worker(self, source: Path, destination: Path):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        output = destination / (safe_name(source.stem) + "-" + stamp)
        output.mkdir()
        self.last_output = output
        warnings: list[str] = []
        manifest = {
            "input_name": source.name,
            "input_path": str(source),
            "input_bytes": source.stat().st_size,
            "sha256": "",
            "started_at": datetime.now().astimezone().isoformat(),
            "finished_at": "",
            "versions": {"ghidra": GHIDRA_VERSION, "jdk": JDK_VERSION, "rea": REA_VERSION},
            "warnings": warnings,
            "ghidra_status": "pending",
            "rea_status": "pending",
        }
        job_root = app_data() / "Jobs"
        job = job_root / ("job-" + uuid.uuid4().hex)
        try:
            cache = app_data() / "Tools"
            cache.mkdir(parents=True, exist_ok=True)
            self._post("status", "Preparing bundled Ghidra and Java…")
            ghidra = unpack_tool(bundled_path("archives", GHIDRA_ARCHIVE), GHIDRA_SHA256,
                                 "ghidra_12.1.4_PUBLIC", cache / "ghidra_12.1.4_PUBLIC",
                                 cache, lambda m: self._post("status", m), self.stop_requested.is_set)
            jdk = unpack_tool(bundled_path("archives", JDK_ARCHIVE), JDK_SHA256,
                              "jdk-21.0.12.1+1", cache / "jdk-21.0.12.1+1",
                              cache, lambda m: self._post("status", m), self.stop_requested.is_set)
            node = bundled_path("runtime", "node.exe")
            rea = bundled_path("runtime", "node_modules", "rea-agents", "scripts", "rea.mjs")
            script_dir = bundled_path("scripts")
            if not all(path.exists() for path in [node, rea, script_dir / "ExportBinaryStudio.java"]):
                raise RuntimeError("Bundled REA files are missing")
            self._check_cancel()
            manifest["sha256"] = sha256(source)
            job.mkdir(parents=True)
            staged = job / ("input" + source.suffix.lower()[:10])
            self._post("status", "Copying binary into a private analysis workspace…")
            shutil.copyfile(source, staged)
            if sha256(staged) != manifest["sha256"]:
                raise RuntimeError("The binary changed while being copied; retry with a stable file")
            project = job / "project"
            exports = job / "exports"
            project.mkdir()
            exports.mkdir()
            env = os.environ.copy()
            env["JAVA_HOME"] = str(jdk)
            env["GHIDRA_INSTALL_DIR"] = str(ghidra)
            env["PATH"] = str(jdk / "bin") + os.pathsep + env.get("PATH", "")
            env["GHIDRA_HEADLESS_MAXMEM"] = "2G"

            self._check_cancel()
            self._post("status", "Ghidra is analyzing and exporting the binary…")
            command = [str(ghidra / "support" / "analyzeHeadless.bat"), str(project), "Analysis",
                       "-import", str(staged), "-scriptPath", str(script_dir),
                       "-postScript", "ExportBinaryStudio.java", str(exports),
                       "-analysisTimeoutPerFile", "900"]
            ghidra_code = self._run_command(command, output / "ghidra.log", env)
            if ghidra_code != 0 or not (exports / "ghidra-summary.json").is_file():
                manifest["ghidra_status"] = "failed"
                warnings.append("Ghidra export failed; see ghidra.log. Available partial files are retained.")
            else:
                manifest["ghidra_status"] = "complete"
            for item in exports.iterdir():
                shutil.move(str(item), str(output / item.name))
            if any(project.iterdir()):
                shutil.move(str(project), str(output / "GhidraProject"))

            self._check_cancel()
            self._post("status", "REA is generating its evidence JSON…")
            rea_command = [str(node), str(rea), "analyze", str(staged), "--provider", "ghidra", "--format", "json"]
            rea_code = self._run_command(rea_command, output / "rea.log", env, output / "rea-evidence.json")
            if rea_code == 0:
                try:
                    json.loads((output / "rea-evidence.json").read_text(encoding="utf-8-sig"))
                    manifest["rea_status"] = "complete"
                except (OSError, ValueError):
                    manifest["rea_status"] = "invalid_output"
                    warnings.append("REA returned invalid JSON; see rea.log.")
            else:
                manifest["rea_status"] = "failed"
                warnings.append("REA evidence could not be generated for this binary; see rea.log. Ghidra exports remain available.")

            summary = None
            try:
                summary = json.loads((output / "ghidra-summary.json").read_text(encoding="utf-8"))
                if summary.get("cancelled"):
                    warnings.append("Ghidra export was cancelled before all functions completed.")
            except (OSError, ValueError):
                pass
            manifest["finished_at"] = datetime.now().astimezone().isoformat()
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            write_report(output, manifest, summary)
            self._post("done", f"Complete. Results saved to {output}")
        except InterruptedError:
            manifest["finished_at"] = datetime.now().astimezone().isoformat()
            warnings.append("Analysis cancelled. Partial files may be present.")
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self._post("done", f"Cancelled. Partial results: {output}")
        except Exception as error:
            manifest["finished_at"] = datetime.now().astimezone().isoformat()
            warnings.append(str(error))
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self._post("done", f"Analysis stopped: {error}. Details: {output}")
        finally:
            if job.exists():
                try:
                    safe_delete(job, job_root)
                except OSError:
                    pass

    def _cancel(self):
        self.stop_requested.set()
        if self.process and self.process.poll() is None:
            subprocess.run(["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.status.set("Cancelling…")

    def _open_output(self):
        if self.last_output and self.last_output.exists():
            os.startfile(self.last_output)
        else:
            messagebox.showinfo(APP, "Run an analysis first.")

    def _close(self):
        if self.running:
            if not messagebox.askyesno(APP, "An analysis is running. Cancel it and exit?"):
                return
            self._cancel()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    BinaryStudio(root)
    root.mainloop()
