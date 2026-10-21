"""Small Windows desktop front end for the REA command-line package."""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_NAME = "REA Desktop"
REA_VERSION = "6.5.0"
BG = "#101827"
PANEL = "#19263a"
TEXT = "#e5edf8"
MUTED = "#a4b3c7"
ACCENT = "#5cc8bd"


def bundle_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).parent))


def runtime_paths() -> tuple[Path, Path]:
    base = bundle_root() / "runtime"
    return base / "node.exe", base / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"


def default_results_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "REA Desktop" / "Results"


def is_managed_pe(path: Path) -> bool:
    """Check whether a PE has a nonempty CLI header data directory."""
    try:
        with path.open("rb") as stream:
            header = stream.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                return False
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            if pe_offset > 16_777_216:
                return False
            stream.seek(pe_offset)
            pe_header = stream.read(160)
            if len(pe_header) < 160 or pe_header[:4] != b"PE\0\0":
                return False
            optional_offset = 24
            magic = struct.unpack_from("<H", pe_header, optional_offset)[0]
            directory_offset = {0x10B: 96, 0x20B: 112}.get(magic)
            if directory_offset is None:
                return False
            cli_offset = optional_offset + directory_offset + 14 * 8
            if len(pe_header) < cli_offset + 8:
                stream.seek(pe_offset + cli_offset)
                cli = stream.read(8)
            else:
                cli = pe_header[cli_offset:cli_offset + 8]
            return len(cli) == 8 and all(struct.unpack("<II", cli))
    except OSError:
        return False


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} - REA {REA_VERSION}")
        self.root.geometry("1000x740")
        self.root.minsize(780, 560)
        self.root.configure(bg=BG)
        self.target = tk.StringVar()
        self.mode = tk.StringVar(value="Auto overview")
        self.ghidra = tk.StringVar()
        self.java = tk.StringVar()
        self.results_dir = tk.StringVar(value=str(default_results_dir()))
        self.status = tk.StringVar(value="Ready")
        self.process: subprocess.Popen | None = None
        self.running = False
        self.last_result: Path | None = None
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TCombobox", fieldbackground="#26364d", background="#26364d", foreground=TEXT)
        style.map("TCombobox", fieldbackground=[("readonly", "#26364d")], foreground=[("readonly", TEXT)])

        main = tk.Frame(self.root, bg=BG, padx=26, pady=22)
        main.pack(fill="both", expand=True)
        tk.Label(main, text="REA Desktop", bg=BG, fg=TEXT, font=("Segoe UI", 21, "bold")).pack(anchor="w")
        tk.Label(main, text="Inspect local files with REA. Results stay on this PC.", bg=BG, fg=MUTED,
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 18))

        card = tk.Frame(main, bg=PANEL, padx=18, pady=16)
        card.pack(fill="x")
        self._label(card, "Target file or folder")
        row = tk.Frame(card, bg=PANEL)
        row.pack(fill="x", pady=(4, 12))
        self._entry(row, self.target).pack(side="left", fill="x", expand=True)
        self._button(row, "File…", self._pick_file).pack(side="left", padx=(8, 0))
        self._button(row, "Folder…", self._pick_folder).pack(side="left", padx=(6, 0))

        mode_row = tk.Frame(card, bg=PANEL)
        mode_row.pack(fill="x", pady=(0, 12))
        self._label(mode_row, "Analysis", pack=False).pack(side="left", padx=(0, 12))
        modes = ["Auto overview", "JavaScript / Electron", ".NET assembly", "Native binary (Ghidra)"]
        ttk.Combobox(mode_row, textvariable=self.mode, values=modes, state="readonly", width=28).pack(side="left")

        self._path_row(card, "Ghidra folder (native analysis)", self.ghidra, self._pick_ghidra)
        self._path_row(card, "JDK folder (native analysis)", self.java, self._pick_java)
        self._path_row(card, "Results folder", self.results_dir, self._pick_results)

        actions = tk.Frame(main, bg=BG)
        actions.pack(fill="x", pady=(16, 12))
        self.run_button = self._button(actions, "Analyze", self._run, primary=True)
        self.run_button.pack(side="left")
        self.cancel_button = self._button(actions, "Cancel", self._cancel)
        self.cancel_button.pack(side="left", padx=(8, 0))
        self.cancel_button.configure(state="disabled")
        self._button(actions, "Open results folder", self._open_results).pack(side="right")
        self._button(actions, "Open last result", self._open_last).pack(side="right", padx=(0, 8))

        tk.Label(main, textvariable=self.status, bg=BG, fg=ACCENT, anchor="w",
                 font=("Segoe UI", 10)).pack(fill="x", pady=(0, 10))
        preview = tk.Frame(main, bg=PANEL, padx=12, pady=12)
        preview.pack(fill="both", expand=True)
        tk.Label(preview, text="Result preview", bg=PANEL, fg=TEXT, anchor="w",
                 font=("Segoe UI", 11, "bold")).pack(fill="x", pady=(0, 8))
        text_row = tk.Frame(preview, bg=PANEL)
        text_row.pack(fill="both", expand=True)
        self.text = tk.Text(text_row, bg="#0c1421", fg=TEXT, insertbackground=TEXT,
                            selectbackground="#33536a", borderwidth=0, padx=12, pady=10,
                            wrap="none", font=("Consolas", 9))
        yscroll = tk.Scrollbar(text_row, command=self.text.yview)
        xscroll = tk.Scrollbar(preview, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        xscroll.pack(fill="x")
        self._show("Select a file or folder, choose an analysis, and click Analyze.\n\n"
                   "JavaScript/Electron and .NET inspection work with the bundled REA runtime.\n"
                   "Native decompilation needs an installed Ghidra 12.1.x and compatible JDK.")

    def _label(self, parent, text, pack=True):
        widget = tk.Label(parent, text=text, bg=PANEL, fg=MUTED, font=("Segoe UI", 9))
        if pack:
            widget.pack(anchor="w")
        return widget

    def _entry(self, parent, variable):
        return tk.Entry(parent, textvariable=variable, bg="#26364d", fg=TEXT,
                        insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))

    def _button(self, parent, text, command, primary=False):
        return tk.Button(parent, text=text, command=command, bg=ACCENT if primary else "#293b52",
                         fg="#09252d" if primary else TEXT, activebackground="#7bdad0",
                         activeforeground="#09252d", relief="flat", padx=13, pady=6,
                         font=("Segoe UI", 9, "bold" if primary else "normal"), cursor="hand2")

    def _path_row(self, parent, label, variable, picker):
        self._label(parent, label)
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill="x", pady=(3, 10))
        self._entry(row, variable).pack(side="left", fill="x", expand=True)
        self._button(row, "Browse…", picker).pack(side="left", padx=(8, 0))

    def _pick_file(self):
        path = filedialog.askopenfilename(title="Choose a file to inspect")
        if path:
            self.target.set(path)

    def _pick_folder(self):
        path = filedialog.askdirectory(title="Choose an application folder")
        if path:
            self.target.set(path)

    def _pick_ghidra(self):
        path = filedialog.askdirectory(title="Choose the Ghidra installation folder")
        if path:
            self.ghidra.set(path)

    def _pick_java(self):
        path = filedialog.askdirectory(title="Choose the JDK folder")
        if path:
            self.java.set(path)

    def _pick_results(self):
        path = filedialog.askdirectory(title="Choose a results folder")
        if path:
            self.results_dir.set(path)

    def _show(self, value: str):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", value)
        self.text.configure(state="disabled")

    def _command(self, target: Path) -> list[str]:
        node, rea = runtime_paths()
        if not node.is_file() or not rea.is_file():
            raise RuntimeError("Bundled REA runtime is missing. Re-download the application.")
        mode = self.mode.get()
        if mode == "JavaScript / Electron":
            if not target.is_dir() and target.suffix.lower() != ".asar":
                raise ValueError("Choose an extracted JavaScript/Electron folder or an ASAR file.")
            command = "analyze-javascript-application"
        elif mode == ".NET assembly":
            if not target.is_file():
                raise ValueError("Choose a .NET assembly file.")
            command = "inspect-managed-artifact"
        elif mode == "Native binary (Ghidra)":
            if not target.is_file():
                raise ValueError("Choose a native binary file.")
            command = "analyze"
        else:
            if target.is_dir() or target.suffix.lower() == ".asar":
                command = "analyze-javascript-application"
            elif target.is_file() and is_managed_pe(target):
                command = "inspect-managed-artifact"
            else:
                command = "analyze"
        args = [str(node), str(rea), command, str(target)]
        if mode == "Native binary (Ghidra)":
            args.extend(["--provider", "ghidra"])
        args.extend(["--format", "json"])
        return args

    def _run(self):
        if self.running:
            return
        target = Path(self.target.get().strip().strip('"')).expanduser()
        if not target.exists():
            messagebox.showerror(APP_NAME, "Choose an existing file or folder.")
            return
        if not target.is_file() and not target.is_dir():
            messagebox.showerror(APP_NAME, "The target must be a regular file or folder.")
            return
        try:
            args = self._command(target)
            out_dir = Path(self.results_dir.get().strip().strip('"')).expanduser()
            out_dir.mkdir(parents=True, exist_ok=True)
            if not out_dir.is_dir():
                raise ValueError("Results path is not a folder")
        except (OSError, ValueError, RuntimeError) as error:
            messagebox.showerror(APP_NAME, str(error))
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in target.stem)[:50] or "target"
        output = out_dir / f"{safe_name}-{stamp}.json"
        error_file = out_dir / f"{safe_name}-{stamp}.log"
        env = os.environ.copy()
        if self.ghidra.get().strip():
            env["GHIDRA_INSTALL_DIR"] = self.ghidra.get().strip().strip('"')
        if self.java.get().strip():
            env["JAVA_HOME"] = self.java.get().strip().strip('"')
        self.running = True
        self.status.set(f"Analyzing {target.name}…")
        self._show("REA is working. Large applications may take several minutes.\n")
        self.run_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        threading.Thread(target=self._worker, args=(args, output, error_file, env), daemon=True).start()

    def _worker(self, args: list[str], output: Path, error_file: Path, env: dict[str, str]):
        try:
            with output.open("wb") as stdout, error_file.open("wb") as stderr:
                self.process = subprocess.Popen(args, stdout=stdout, stderr=stderr, env=env,
                                                cwd=str(output.parent), creationflags=subprocess.CREATE_NO_WINDOW)
                code = self.process.wait()
            self.root.after(0, self._finished, code, output, error_file)
        except Exception as error:
            self.root.after(0, self._failed, str(error))
        finally:
            self.process = None

    def _finished(self, code: int, output: Path, error_file: Path):
        self.running = False
        self.run_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        error_text = error_file.read_text(encoding="utf-8", errors="replace")[:12000] if error_file.exists() else ""
        if code == 0 and output.stat().st_size:
            self.last_result = output
            self.status.set(f"Complete · {output.name}")
            try:
                if output.stat().st_size <= 25_000_000:
                    value = json.loads(output.read_text(encoding="utf-8-sig"))
                    preview = json.dumps(value, indent=2, ensure_ascii=False)[:150_000]
                else:
                    preview = (f"Large result ({output.stat().st_size / 1_000_000:.1f} MB) saved to:\n"
                               f"{output}\n\nOpen the saved JSON to view the complete Evidence.")
                self._show(preview)
            except Exception as error:
                self._show(f"Saved result to {output}\n\nCould not preview JSON: {error}")
        else:
            self.status.set(f"Analysis failed (exit {code})")
            message = error_text or "REA did not return a result."
            if output.exists() and output.stat().st_size:
                message += "\n\nPartial output saved to:\n" + str(output)
            self._show(message)
        if not error_text and error_file.exists():
            error_file.unlink(missing_ok=True)

    def _failed(self, message: str):
        self.running = False
        self.run_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self.status.set("Could not start REA")
        self._show(message)

    def _cancel(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.status.set("Cancelling…")

    def _open_results(self):
        folder = Path(self.results_dir.get().strip()).expanduser()
        folder.mkdir(parents=True, exist_ok=True)
        os.startfile(folder)

    def _open_last(self):
        if self.last_result and self.last_result.exists():
            os.startfile(self.last_result)
        else:
            messagebox.showinfo(APP_NAME, "Run an analysis first.")

    def _close(self):
        if self.running and not messagebox.askyesno(APP_NAME, "An analysis is running. Cancel it and exit?"):
            return
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self.root.destroy()


if __name__ == "__main__":
    window = tk.Tk()
    App(window)
    window.mainloop()
