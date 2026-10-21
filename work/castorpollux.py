"""CastorPollux desktop interface."""

from __future__ import annotations

import os
import json
import queue
import re
import shutil
import subprocess
import sys
import tkinter as tk
import threading
import time
import traceback
import uuid
import ctypes
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
from tkinter import font as tkfont

import customtkinter as ctk
from PIL import Image

from castorpollux_core import APP_VERSION, AnalysisRunner, ComponentStore, UpdateManager, home, newer, compatible_update, resource, sha256
from castorpollux_core import check_component, bundled_component
from castorpollux_workspace import (CATEGORIES, REPORT_FORMATS, CodexReview, InvestigationLibrary,
                                build_review_prompt, cloud_evidence_preview, compare_investigations, find_agent_cli, function_links, pseudocode_for,
                                read_manifest, review_readiness, run_rea_command, run_rea_query,
                                review_is_stale, search_pseudocode, search_rows)
from castorpollux_quality import find_retdec
from castorpollux_integrity import authenticode_status, write_inventory
from castorpollux_review import (coverage_rows, evidence_jump, export_coverage_csv, finding_key,
                             load_triage, ollama_models, resolve_scope, save_triage)
from castorpollux_flow import (build_data_flow, create_default_rules, load_rules, rules_path,
                           evaluate_rule_change, activate_rule_change)
from castorpollux_interflow import build_cross_function_flow
from castorpollux_tracking import add_confirmed_case, evaluate_corpus, set_flow_answers
from castorpollux_bundle import export_bundle, verify_bundle, import_bundle
from castorpollux_plugins import create_sample, load_plugins, plugin_dir
from castorpollux_runtime import prepare_trace, launch_trace, correlate_trace, sandbox_executable
from castorpollux_unpack import unpack_binary
from castorpollux_similarity import procedures, similar_functions
from castorpollux_findings import active_suppression, set_suppression, clear_suppression
from castorpollux_sarif import write_sarif
from castorpollux_report_evidence import (confirmation_steps, export_source_map, load_confirmation_state,
                                          save_confirmation_state)
from castorpollux_settings import (THEMES, SHORTCUT_ACTIONS, shortcut_conflicts, validate_shortcuts,
                               load_settings, save_settings, approved_server, load_workspace, save_workspace)
from castorpollux_ui_state import begin_session, end_session, load_palette, save_palette
from castorpollux_secrets import scan_secrets
from castorpollux_diagnostics import export_diagnostics, record_error
from castorpollux_recovery import (attempt_agent_recovery, engine_failures, diagnostic_preview,
                               recovery_comparison, recovery_stages, recovery_log_preview)
from castorpollux_usage import read_codex_usage, read_other_usage, usage_label
from castorpollux_intelligence import (build_source_index, search_index, line_address, disagreement_heatmap,
                                   review_priority, evidence_freshness, confidence_calibration, patch_checklist)
from castorpollux_binary_profile import check_known_vulnerabilities, detect_binary_profile, scan_embedded_libraries
from castorpollux_applicability import ensure_rules as ensure_advisory_rules, evaluate_applicability
from castorpollux_callpaths import explore_paths, load_graph
from castorpollux_indirect import resolve_indirect_calls
from castorpollux_sbom import compare_sbom
from castorpollux_consistency import check_consistency
from castorpollux_advanced import build_advanced_graph, check_call_edges
from castorpollux_inputs import import_vex, import_fuzz_coverage, verify_sbom_provenance
from castorpollux_overflow import scan_overflows, create_boundary_inputs
from castorpollux_metrics import load_metrics, trend, export_metrics_csv
from castorpollux_dashboard_export import export_dashboard_html
from castorpollux_drop import WindowsFileDrop, first_regular_file
from castorpollux_drafts import load_drafts, save_drafts
from castorpollux_ui_support import (activity_kind, filter_activity, format_duration,
                                 historical_stage_seconds, notify_windows, stage_estimate)
from castorpollux_evidence_tools import (cve_reachability, dll_signature_inventory, minimize_candidate_input,
                                     link_crash_log, disclosure_packet)
from castorpollux_html import help_sections, plain_text, render_html


BG = "#071017"
SIDEBAR = "#0B171F"
CARD = "#10212B"
FIELD = "#152B36"
LINE = "#24414A"
TEXT = "#EDF8F5"
MUTED = "#91AAA9"
GREEN = "#83F7BA"
CYAN = "#53CFE0"
RED = "#FF7B84"

CREDIT_LICENSE_FILES = {
    "REA": ("REA-LICENSE.txt", "REA-THIRD-PARTY-NOTICES.md"),
    "GHIDRA": ("Ghidra-LICENSE.txt", "Ghidra-NOTICE.txt", "Ghidra-DISCLAIMER.txt"),
    "TEMURIN JDK": ("Temurin-LICENSE.txt", "Temurin-NOTICE.txt"),
    "NODE.JS": ("Node-LICENSE.txt",), "CUSTOMTKINTER": ("CustomTkinter-LICENSE.txt",),
    "PNPM": ("pnpm-LICENSE.txt",), "PYTHON": ("Python-LICENSE.txt",),
    "PYINSTALLER": ("PyInstaller-COPYING.txt",), "REPORTLAB": ("ReportLab-LICENSE.txt",),
    "PILLOW": ("Pillow-LICENSE.txt",), "CHARSET-NORMALIZER": ("charset-normalizer-LICENSE.txt",),
    "DARKDETECT": ("darkdetect-LICENSE.txt",),
    "PACKAGING": ("packaging-LICENSE.txt", "packaging-LICENSE.APACHE.txt", "packaging-LICENSE.BSD.txt"),
}

HELP_FOR_PAGE = {
    "analyze": "Analyze a binary", "batch": "Start here", "history": "History and recovery",
    "dashboards": "Browse evidence", "codex": "Agent review", "reports": "Compare and report",
    "investigations": "Browse evidence", "coverage": "Analyze a binary", "flow": "Browse evidence",
    "compare": "Compare and report", "callpaths": "Browse evidence", "libraries": "Browse evidence",
    "advanced": "Browse evidence", "lab": "Browse evidence", "queries": "REA actions and console",
    "console": "REA actions and console", "settings": "Components and settings",
    "credits": "Components and settings", "plugins": "Plugins",
}


def apply_palette(name: str) -> None:
    global BG, SIDEBAR, CARD, FIELD, LINE, TEXT, MUTED, GREEN, CYAN, RED
    palette = THEMES[name]
    BG, SIDEBAR, CARD, FIELD, LINE = (palette[key] for key in ("bg", "sidebar", "card", "field", "line"))
    TEXT, MUTED, GREEN, CYAN, RED = (palette[key] for key in ("text", "muted", "accent", "secondary", "danger"))
    ctk.set_appearance_mode("light" if name == "Daylight" else "dark")
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


class CastorPollux(ctk.CTk):
    def destroy(self):
        if hasattr(self, "nav_group"):
            self._save_drafts_now()
        # Cancel queued Tcl timers without deleting their commands ahead of
        # CustomTkinter's normal child-widget teardown.
        try:
            for timer in self.tk.call("after", "info"):
                self.tk.call("after", "cancel", timer)
        except tk.TclError:
            pass
        try:
            self.unbind_all("<FocusIn>")
            if getattr(self, "focus_ring", None) is not None:
                widget, width, color = self.focus_ring
                if widget.winfo_exists():
                    tk.Frame.configure(widget, highlightthickness=width,
                                       highlightbackground=color, highlightcolor=color)
                self.focus_ring = None
        except tk.TclError:
            pass
        if getattr(self, "file_drop", None) is not None:
            self.file_drop.close()
        if hasattr(self, "nav_group"):
            self._save_workspace()
        super().destroy()
        end_session(getattr(self, "session_marker", None))

    def report_callback_exception(self, exception_type, exception, traceback_object):
        detail = "".join(traceback.format_exception(exception_type, exception, traceback_object))
        record_error(str(exception), self.current_folder, "interface", detail)
        self.status_text.set("INTERFACE ERROR — SEE HISTORY LOGS")
        try:
            messagebox.showerror("CastorPollux", str(exception))
        except Exception:
            pass

    def __init__(self):
        self.settings = load_settings()
        self.form_drafts = load_drafts()
        self.draft_timer = None
        self.font_scale = self.settings["font_scale"] / 100
        apply_palette(self.settings["theme"])
        super().__init__(fg_color=BG)
        try:
            self.iconbitmap(str(resource("assets", "CastorPollux.ico")))
        except (OSError, tk.TclError):
            pass
        try:
            self.session_marker, self.interrupted_session = begin_session()
        except OSError:
            self.session_marker, self.interrupted_session = None, False
        self.title("CastorPollux  |  Binary Intelligence")
        self.geometry("1280x850")
        self.minsize(940, 640)
        installed_fonts = set(tkfont.families(self))
        self.ui_font = "Segoe UI Variable" if "Segoe UI Variable" in installed_fonts else "Segoe UI"
        self.code_font = "Cascadia Code" if "Cascadia Code" in installed_fonts else "Consolas"
        ctk.ThemeManager.theme["CTkFont"]["family"] = self.ui_font
        ctk.ThemeManager.theme["CTkFont"]["size"] = round(13 * self.font_scale)
        self.store = ComponentStore()
        self.updater = UpdateManager(self.store)
        self.library = InvestigationLibrary()
        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.process = None
        self.busy = False
        self.active_task_kind = "idle"
        self.scan_finished = False
        self.task_started = 0.0
        self.stage_started = 0.0
        self.stage_name = ""
        self.stage_percent = 0
        self.stage_history = historical_stage_seconds([Path(item["path"]) for item in self.library.details()[:20]])
        self.scan_timing_text = ctk.StringVar(value="Elapsed 0s  •  Stage not started")
        self.activity_search = ctk.StringVar(value="")
        self.activity_filter = ctk.StringVar(value="All")
        self.log_records = []
        self.log_visible_records = []
        self.bookmark_path = home() / "activity-bookmarks.json"
        self.bookmarks = self._load_bookmarks()
        self.log_records.extend({**row, "kind": activity_kind(row.get("text", "")), "bookmarked": True}
                                for row in self.bookmarks)
        self.desktop_notifications = ctk.BooleanVar(value=bool(self.settings["desktop_notifications"]))
        self.notification_min_seconds = ctk.StringVar(value=str(self.settings["notification_min_seconds"]))
        self.findings = {}
        self.last_output = None
        recent = self.library.list()
        self.current_folder = Path(recent[0]["path"]) if recent else None
        self.search_category = "functions"
        self.search_serial = 0
        self.search_text = ctk.StringVar(value="")
        self.lab_query = ctk.StringVar(value="")
        self.lab_line = ctk.StringVar(value="")
        self.lab_function = ctk.StringVar(value="")
        self.compare_left = ctk.StringVar(value="")
        self.compare_right = ctk.StringVar(value="")
        self.call_source = ctk.StringVar(value="")
        self.compare_destination = None
        self.call_target = ctk.StringVar(value="")
        self.call_path_index = 0
        self.active_call_report = None
        self.review_agent = ctk.StringVar(value="codex")
        self.review_folder = ctk.StringVar(value=str(self.current_folder or ""))
        self.batch_agent = ctk.StringVar(value="none")
        self.codex_cli_path = ctk.StringVar(value=str(find_agent_cli("codex") or ""))
        self.local_model = ctk.StringVar(value="")
        self.scope_mode = ctk.StringVar(value="all")
        self.scope_selection = ctk.StringVar(value="")
        self.coverage_search = ctk.StringVar(value="")
        self.coverage_filter = ctk.StringVar(value="all")
        self.triage_actor = ctk.StringVar(value=os.environ.get("USERNAME", "local analyst"))
        self.triage_assignee = ctk.StringVar(value="")
        self.corpus_path = ctk.StringVar(value=str(home() / "known-answer-corpus.json"))
        self.corpus_complete = ctk.BooleanVar(value=False)
        self.coverage_page_index = 0
        self.daybreak_blue = ctk.BooleanVar(value=False)
        self.coverage_minimum = ctk.StringVar(value="80")
        self.redact_cloud = ctk.BooleanVar(value=True)
        self.redaction_terms = ctk.StringVar(value="")
        self.secondary_decompiler = ctk.BooleanVar(value=True)
        self.retdec_path = ctk.StringVar(value=str(find_retdec() or ""))
        self.report_formats = {name: ctk.BooleanVar(value=True) for name in REPORT_FORMATS}
        self.rea_console_args = ctk.StringVar(value='["capabilities", "--json"]')
        self.rea_query_type = ctk.StringVar(value="inspect")
        self.rea_query_text = ctk.StringVar(value="")
        self.input_path = ctk.StringVar(value="")
        self.symbol_path = ctk.StringVar(value="")
        self.symbol_server_enabled = ctk.BooleanVar(value=False)
        self.symbol_server = ctk.StringVar(value="https://msdl.microsoft.com/download/symbols")
        self.similarity_selector = ctk.StringVar(value="")
        self.similarity_minimum = ctk.StringVar(value="0.45")
        self.history_search = ctk.StringVar(value="")
        self.history_filter = ctk.StringVar(value="all")
        self.history_limit = 40
        self.dashboard_selection = ctk.StringVar(value="")
        self.help_search = ctk.StringVar(value="")
        self.credits_search = ctk.StringVar(value="")
        self.theme_choice = ctk.StringVar(value=self.settings["theme"])
        self.font_scale_choice = ctk.StringVar(value=str(self.settings["font_scale"]))
        self.layout_choice = ctk.StringVar(value=self.settings["active_layout"])
        self.layout_name = ctk.StringVar(value="")
        self.last_split_ratio = self.settings["layout_presets"][self.settings["active_layout"]]
        self.allowed_servers = ctk.StringVar(value="\n".join(self.settings["symbol_servers"]))
        self.restore_tabs_choice = ctk.BooleanVar(value=self.settings["restore_tabs"])
        self.shortcut_vars = {action: ctk.StringVar(value=sequence)
                              for action, sequence in self.settings["shortcuts"].items()}
        self.dirty_pages = set()
        self.cache_days = ctk.StringVar(value=str(self.settings["symbol_cache_days"]))
        self.cache_mb = ctk.StringVar(value=str(self.settings["symbol_cache_mb"]))
        self.engine_limit_vars = {key: ctk.StringVar(value=str(self.settings[key])) for key in
            ("ghidra_timeout_seconds", "rea_timeout_seconds", "ghidra_heap_mb", "rea_heap_mb")}
        self.trace_arguments = ctk.StringVar(value="[]")
        self.trace_timeout = ctk.StringVar(value="60")
        self.rule_candidate = ctk.StringVar(value="")
        self.rule_trial_sha256 = ""
        self.unpack_source = ctk.StringVar(value="")
        self.unpack_output = ctk.StringVar(value="")
        self.bundle_path = ctk.StringVar(value="")
        self.sbom_pin = ctk.StringVar(value="")
        self.advanced_view = ctk.StringVar(value="SSA flow")
        self.overflow_lead_index = ctk.StringVar(value="0")
        self.output_path = ctk.StringVar(value=str(Path.home() / "Desktop"))
        self.batch_sources = []
        self.status_text = ctk.StringVar(value="SYSTEM READY")
        self.progress_text = ctk.StringVar(value="READY")
        self.scan_state_text = ctk.StringVar(value="READY TO SCAN")
        self.scan_stage_text = ctk.StringVar(value="Choose a binary or drop one into this window.")
        self.scan_percent_text = ctk.StringVar(value="0%")
        self.agent_usage_text = ctk.StringVar(value="Codex usage: checked after each scan")
        self.draft_status_text = ctk.StringVar(value="DRAFT RESTORED" if self.form_drafts else "")
        self.page_name = "analyze"
        self.saved_tabs = {}
        self.focus_ring = None
        self._layout()
        known = {Path(item["path"]).resolve() for item in self.library.list()}
        restored = load_workspace(set(self.nav_group), known)
        if restored.get("current_folder"):
            self.current_folder = Path(restored["current_folder"])
        for key, variable in (("input_path", self.input_path), ("output_path", self.output_path)):
            if key in restored:
                variable.set(restored[key])
        if not (self.form_drafts.get("review") or {}).get("review_folder"):
            self.review_folder.set(str(self.current_folder or ""))
        self._restore_form_drafts()
        if self.settings["restore_tabs"]:
            self.saved_tabs = restored.get("tabs", {})
        self.show_page("analyze" if self.interrupted_session else restored.get("page", "analyze"))
        self.after(250, self._install_file_drop)
        self.after(300, self._poll_drop_hover)
        self.after(1000, self._tick_scan_clock)
        self._bind_shortcuts()
        self._watch_settings_edits()
        self._watch_form_drafts()
        self._refresh_settings_dirty()
        self.bind_all("<FocusIn>", self._highlight_focus, add="+")
        try:
            self.state("zoomed")
        except Exception:
            pass
        self.after(100, self._drain)
        if self.interrupted_session:
            self.after(650, self._recovery_prompt)

    def _font(self, size=14, weight="normal", mono=False):
        return ctk.CTkFont(family=self.code_font if mono else self.ui_font,
                           size=max(9, round(size * self.font_scale)), weight=weight)

    def _tk_font(self, size=11, mono=False, bold=False):
        return (self.code_font if mono else self.ui_font,
                max(9, round(size * self.font_scale)), "bold" if bold else "normal")

    def _label(self, parent, text, size=14, color=TEXT, weight="normal", mono=False, **kw):
        return ctk.CTkLabel(parent, text=text, text_color=color,
                            font=self._font(size, weight, mono), **kw)

    def _button(self, parent, text, command, width=130, accent=False):
        button = ctk.CTkButton(parent, text=text, command=command, width=width, height=39,
                               corner_radius=8, fg_color=GREEN if accent else FIELD,
                               hover_color=CYAN if accent else LINE,
                               text_color=BG if accent else TEXT, font=self._font(13, "bold"))
        self._keyboard_button(button)
        return button

    @staticmethod
    def _keyboard_button(button):
        tk.Frame.configure(button, takefocus=1)
        button.bind("<Return>", lambda _event=None: button.invoke())
        button.bind("<space>", lambda _event=None: button.invoke())

    def _layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        sidebar = ctk.CTkFrame(self, width=224, corner_radius=0, fg_color=SIDEBAR,
                               border_width=1, border_color=LINE)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=15, pady=(18, 0))
        self.brand_mark = ctk.CTkImage(Image.open(resource("assets", "castorpollux-gemini.png")), size=(52, 52))
        ctk.CTkLabel(brand, text="", image=self.brand_mark, width=52, height=52).pack(side="left")
        self._label(brand, "CastorPollux", 17, GREEN, "bold").pack(side="left", padx=(6, 0))
        self._label(sidebar, "BINARY INTELLIGENCE", 10, MUTED, mono=True).pack(anchor="w", padx=25, pady=(0, 15))
        groups = {
            "Start": ["analyze", "batch", "history", "dashboards", "codex", "reports"],
            "Explore": ["investigations", "coverage", "flow", "compare", "callpaths", "libraries",
                        "secrets", "similar", "advanced", "lab"],
            "Tools": ["queries", "console", "runtime", "bundles", "unpack", "corpus", "plugins"],
            "System": ["updates", "settings", "about", "help", "credits"],
        }
        self.nav_group = {page: group for group, pages in groups.items() for page in pages}
        self.nav_tabs = ctk.CTkTabview(sidebar, fg_color=SIDEBAR, segmented_button_fg_color=FIELD,
                                       segmented_button_selected_color=GREEN,
                                       segmented_button_selected_hover_color=CYAN,
                                       segmented_button_unselected_color=FIELD, text_color=TEXT,
                                       width=216)
        self.nav_tabs.pack(fill="both", expand=True, padx=4, pady=(0, 8))
        nav_panels = {}
        for group in groups:
            self.nav_tabs.add(group)
            panel = ctk.CTkScrollableFrame(self.nav_tabs.tab(group), fg_color="transparent",
                                            scrollbar_button_color=FIELD, width=200)
            panel.pack(fill="both", expand=True)
            nav_panels[group] = panel
        self.nav = {}
        for key, title in [("analyze", "  ◉  ANALYZE"), ("dashboards", "  ▥  DASHBOARDS"),
                           ("batch", "  ▦  BATCH JOBS"),
                           ("history", "  ◷  HISTORY"),
                           ("investigations", "  ▤  INVESTIGATIONS"), ("coverage", "  ◫  COVERAGE"),
                           ("flow", "  ⇢  DATA FLOW"), ("corpus", "  ◩  TEST CORPUS"),
                           ("runtime", "  ◌  RUNTIME TRACE"), ("bundles", "  ▣  BUNDLES"),
                           ("unpack", "  ▤  UNPACK"), ("similar", "  ≈  SIMILAR FUNCTIONS"),
                           ("plugins", "  ⛭  PLUGINS"),
                           ("queries", "  ⌕  REA ACTIONS"), ("libraries", "  ◈  LIBRARIES & CVEs"),
                           ("console", "  >_ REA CONSOLE"),
                           ("compare", "  ◇  COMPARE"), ("callpaths", "  ⇢  CALL PATHS"),
                           ("advanced", "  ◈  GRAPH LAB"), ("lab", "  ◫  EVIDENCE LAB"),
                           ("codex", "  ✦  AGENT REVIEW"),
                           ("reports", "  ◈  FINDINGS"), ("secrets", "  ◉  SECRET LEADS"),
                           ("updates", "  ↻  COMPONENTS"), ("settings", "  ⚙  SETTINGS"), ("about", "  ⓘ  ABOUT"),
                           ("help", "  ?  HELP"), ("credits", "  ◎  CREDITS")]:
            button = ctk.CTkButton(nav_panels[self.nav_group[key]], text=title, command=lambda k=key: self.show_page(k),
                                   height=40, corner_radius=8, anchor="w", fg_color="transparent",
                                   hover_color=FIELD, text_color=MUTED, font=self._font(13, "bold"))
            self._keyboard_button(button)
            button.pack(fill="x", padx=4, pady=2)
            self.nav[key] = button
        main = ctk.CTkFrame(self, corner_radius=0, fg_color=BG)
        self.main = main
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=26, pady=(16, 6))
        self.heading = self._label(header, "", 26, TEXT, "bold")
        self.heading.pack(side="left")
        self.dirty_badge = self._label(header, "", 10, CYAN, "bold")
        self.dirty_badge.pack(side="left", padx=(13, 0))
        self._update_dirty_badge()
        self._label(header, "", 10, MUTED, "bold", textvariable=self.draft_status_text).pack(
            side="left", padx=(10, 0))
        self._label(header, "●", 18, GREEN).pack(side="right", padx=(5, 0))
        self._label(header, "WORKSPACE READY", 11, GREEN, mono=True).pack(side="right")
        self.mode_button = self._button(header, "☀ DAY" if self.settings["theme"] != "Daylight" else "☾ NIGHT",
                                        self._toggle_day_mode, 96)
        self.mode_button.pack(side="right", padx=(0, 14))
        self._button(header, "? HELP HERE", self._context_help, 116).pack(side="right", padx=(0, 8))
        self.body = ctk.CTkScrollableFrame(main, corner_radius=0, fg_color="transparent",
                                            scrollbar_button_color=FIELD)
        self.body.grid(row=1, column=0, sticky="nsew", padx=20, pady=(2, 5))
        self.body.grid_columnconfigure(0, weight=1)
        footer = ctk.CTkFrame(main, height=57, corner_radius=0, fg_color=SIDEBAR)
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_columnconfigure(1, weight=1)
        self.progress_bar = ctk.CTkProgressBar(footer, height=4, corner_radius=0,
                                                progress_color=GREEN, fg_color=LINE)
        self.progress_bar.grid(row=1, column=0, columnspan=3, sticky="ew")
        self.progress_bar.set(0)
        self._label(footer, "CASTORPOLLUX", 10, MUTED, "bold").grid(row=0, column=0, padx=(16, 10), pady=10)
        self.status = self._label(footer, "", 11, GREEN, "bold", textvariable=self.status_text,
                                  anchor="w", wraplength=700, justify="left")
        self.status.grid(row=0, column=1, sticky="ew", padx=8)
        self._label(footer, "", 11, CYAN, "bold", textvariable=self.progress_text).grid(
            row=0, column=2, padx=(10, 20))
        self._label(footer, "", 10, MUTED, textvariable=self.agent_usage_text,
                    anchor="w").grid(row=2, column=0, columnspan=3, sticky="ew", padx=16, pady=(3, 5))
        footer.bind("<Configure>", lambda event: self.status.configure(wraplength=max(220, event.width - 280)))

    def _clear(self, page):
        self.body.destroy()
        if page in {"about", "help", "credits", "updates", "queries", "console", "plugins"}:
            self.body = ctk.CTkFrame(self.main, corner_radius=0, fg_color="transparent")
        else:
            self.body = ctk.CTkScrollableFrame(self.main, corner_radius=0, fg_color="transparent",
                                                scrollbar_button_color=FIELD)
        self.body.grid(row=1, column=0, sticky="nsew", padx=20, pady=(2, 5))
        self.body.grid_columnconfigure(0, weight=1)

    def _toggle_day_mode(self):
        self._remember_page_tab()
        target = "Midnight" if self.settings["theme"] == "Daylight" else "Daylight"
        self.settings = save_settings({**self.settings, "theme": target})
        self.theme_choice.set(target)
        apply_palette(target)
        self.configure(fg_color=BG)
        for child in self.winfo_children():
            child.destroy()
        self._layout()
        self.show_page(self.page_name)

    def _bind_shortcuts(self):
        actions = {
            "Command palette": self._command_palette, "Browse binary": self._browse_input,
            "Browse output": self._browse_output, "Analyze": lambda: self._shortcut_analyze(False),
            "Analyze and review": lambda: self._shortcut_analyze(True),
            "Batch jobs": lambda: self.show_page("batch"), "History": lambda: self.show_page("history"),
            "Search activity": self._focus_activity_search, "Context help": self._context_help,
            "Cancel task": lambda: self._cancel() if self.busy else None,
        }
        for sequence in getattr(self, "bound_shortcuts", {}).values():
            self.unbind_all(sequence)
        self.bound_shortcuts = dict(self.settings["shortcuts"])
        for action, sequence in self.bound_shortcuts.items():
            callback = actions[action]
            self.bind_all(sequence, lambda _event=None, run=callback: (run(), "break")[1])

    def _set_dirty(self, page, dirty=True):
        (self.dirty_pages.add if dirty else self.dirty_pages.discard)(page)
        self._update_dirty_badge()

    def _update_dirty_badge(self):
        if getattr(self, "dirty_badge", None) is not None and self.dirty_badge.winfo_exists():
            self.dirty_badge.configure(text="● UNSAVED: " + ", ".join(sorted(self.dirty_pages))
                                       if self.dirty_pages else "")

    def _watch_settings_edits(self):
        variables = [self.theme_choice, self.font_scale_choice, self.layout_choice,
                     self.desktop_notifications, self.restore_tabs_choice, self.notification_min_seconds,
                     self.cache_days, self.cache_mb, *self.engine_limit_vars.values(),
                     *self.shortcut_vars.values()]
        for variable in variables:
            variable.trace_add("write", lambda *_: self._refresh_settings_dirty())

    def _watch_form_drafts(self):
        names = ("input_path", "output_path", "symbol_path", "symbol_server_enabled",
                 "symbol_server", "review_agent", "daybreak_blue", "review_folder",
                 "codex_cli_path", "local_model", "scope_mode", "scope_selection",
                 "coverage_minimum", "redact_cloud", "secondary_decompiler", "retdec_path",
                 "batch_agent", "theme_choice", "font_scale_choice", "layout_choice",
                 "desktop_notifications", "restore_tabs_choice", "notification_min_seconds",
                 "allowed_servers", "cache_days", "cache_mb")
        variables = [getattr(self, name) for name in names]
        variables.extend(self.report_formats.values())
        variables.extend(self.engine_limit_vars.values())
        variables.extend(self.shortcut_vars.values())
        for variable in variables:
            variable.trace_add("write", lambda *_: self._schedule_draft_save())

    def _restore_form_drafts(self):
        sections = {
            "analyze": ("input_path", "output_path", "symbol_path", "symbol_server_enabled",
                        "symbol_server", "review_agent", "daybreak_blue"),
            "review": ("review_folder", "codex_cli_path", "local_model", "scope_mode",
                       "scope_selection", "coverage_minimum", "redact_cloud",
                       "secondary_decompiler", "retdec_path"),
            "batch": ("batch_agent",),
            "settings": ("theme_choice", "font_scale_choice", "layout_choice",
                         "desktop_notifications", "restore_tabs_choice", "notification_min_seconds",
                         "allowed_servers", "cache_days", "cache_mb"),
        }
        for section, names in sections.items():
            saved = self.form_drafts.get(section, {})
            for name in names:
                if name in saved:
                    getattr(self, name).set(saved[name])
        review = self.form_drafts.get("review", {})
        for name, selected in review.get("report_formats", {}).items():
            if name in self.report_formats:
                self.report_formats[name].set(selected)
        batch = self.form_drafts.get("batch", {})
        self.batch_sources = list(batch.get("sources", []))
        settings = self.form_drafts.get("settings", {})
        for name, value in settings.get("engine_limits", {}).items():
            if name in self.engine_limit_vars:
                self.engine_limit_vars[name].set(value)
        for name, value in settings.get("shortcuts", {}).items():
            if name in self.shortcut_vars:
                self.shortcut_vars[name].set(value)

    def _collect_form_drafts(self):
        forms = {
            "analyze": {name: getattr(self, name).get() for name in
                ("input_path", "output_path", "symbol_path", "symbol_server_enabled",
                 "symbol_server", "review_agent", "daybreak_blue")},
            "review": {name: getattr(self, name).get() for name in
                ("review_folder", "codex_cli_path", "local_model", "scope_mode",
                 "scope_selection", "coverage_minimum", "redact_cloud",
                 "secondary_decompiler", "retdec_path")},
            "batch": {"batch_agent": self.batch_agent.get(), "sources": list(self.batch_sources)},
        }
        forms["review"]["report_formats"] = {name: variable.get()
                                                for name, variable in self.report_formats.items()}
        if "Settings" in self.dirty_pages:
            forms["settings"] = {name: getattr(self, name).get() for name in
                ("theme_choice", "font_scale_choice", "layout_choice", "desktop_notifications",
                 "restore_tabs_choice", "notification_min_seconds", "allowed_servers",
                 "cache_days", "cache_mb")}
            forms["settings"]["engine_limits"] = {name: variable.get()
                                                      for name, variable in self.engine_limit_vars.items()}
            forms["settings"]["shortcuts"] = {name: variable.get()
                                                  for name, variable in self.shortcut_vars.items()}
        return forms

    def _schedule_draft_save(self):
        try:
            if self.draft_timer is not None:
                self.after_cancel(self.draft_timer)
            self.draft_status_text.set("DRAFT PENDING")
            self.draft_timer = self.after(650, self._save_drafts_now)
        except tk.TclError:
            pass

    def _save_drafts_now(self):
        if not hasattr(self, "draft_status_text"):
            return
        self.draft_timer = None
        try:
            self.form_drafts = save_drafts(self._collect_form_drafts())
            self.draft_status_text.set("DRAFT AUTOSAVED")
        except (OSError, ValueError) as error:
            self.draft_status_text.set("DRAFT SAVE FAILED")
            record_error(str(error), self.current_folder, "form draft")

    def _refresh_settings_dirty(self):
        if getattr(self, "allowed_servers_box", None) is not None:
            try:
                if self.allowed_servers_box.winfo_exists():
                    self.allowed_servers.set(self.allowed_servers_box.get("1.0", "end-1c"))
            except tk.TclError:
                pass
        current = {
            "theme": self.theme_choice.get(), "font_scale": self.font_scale_choice.get(),
            "active_layout": self.layout_choice.get(),
            "desktop_notifications": self.desktop_notifications.get(),
            "restore_tabs": self.restore_tabs_choice.get(),
            "notification_min_seconds": self.notification_min_seconds.get(),
            "symbol_cache_days": self.cache_days.get(), "symbol_cache_mb": self.cache_mb.get(),
            "shortcuts": {name: variable.get() for name, variable in self.shortcut_vars.items()},
            "symbol_servers": [line.strip() for line in self.allowed_servers.get().splitlines() if line.strip()],
            **{key: variable.get() for key, variable in self.engine_limit_vars.items()},
        }
        dirty = any(str(current[key]) != str(self.settings[key]) for key in current)
        self._set_dirty("Settings", dirty)

    def _highlight_focus(self, event):
        """Draw a visible keyboard focus ring without changing command behavior."""
        target = event.widget
        while target is not None and target is not self:
            if isinstance(target, (ctk.CTkButton, ctk.CTkEntry, ctk.CTkTextbox,
                                   ctk.CTkCheckBox, ctk.CTkOptionMenu)):
                break
            target = getattr(target, "master", None)
        if target is self or target is None:
            target = None
        if self.focus_ring is not None and self.focus_ring[0] is not target:
            previous, width, color = self.focus_ring
            try:
                if previous.winfo_exists():
                    tk.Frame.configure(previous, highlightthickness=width,
                                       highlightbackground=color, highlightcolor=color)
            except (tk.TclError, ValueError):
                pass
            self.focus_ring = None
        if target is not None and self.focus_ring is None:
            try:
                width = tk.Frame.cget(target, "highlightthickness")
                color = tk.Frame.cget(target, "highlightbackground")
                tk.Frame.configure(target, highlightthickness=3, highlightbackground=GREEN,
                                   highlightcolor=GREEN)
                self.focus_ring = (target, width, color)
            except (tk.TclError, ValueError, TypeError, AttributeError):
                pass

    def _remember_page_tab(self):
        key = getattr(self, "page_name", "")
        attr = {"analyze": "analyze_tabs", "dashboards": "dashboard_tabs",
                "settings": "settings_tabs"}.get(key)
        tabs = getattr(self, attr, None) if attr else None
        try:
            if tabs is not None and tabs.winfo_exists():
                self.saved_tabs[key] = tabs.get()
        except tk.TclError:
            pass

    def _restore_page_tab(self, key, tabs):
        if tabs is not None and tabs.winfo_exists() and self.settings["restore_tabs"] and self.saved_tabs.get(key):
            try:
                tabs.set(self.saved_tabs[key])
            except (tk.TclError, ValueError):
                pass

    def _recovery_prompt(self):
        if not self.winfo_exists():
            return
        window = ctk.CTkToplevel(self)
        self.recovery_window = window
        window.title("CastorPollux | Recover interrupted session")
        window.geometry("800x610")
        window.transient(self)
        window.grab_set()
        self._label(window, "A previous CastorPollux session ended unexpectedly", 18, TEXT, "bold").pack(
            anchor="w", padx=20, pady=(20, 8))
        self._label(window, "Select an incomplete stage to inspect its saved log. Resume reuses completed stages and verifies the saved binary.",
                    12, MUTED, wraplength=750, justify="left").pack(anchor="w", padx=20)
        incomplete = next((item for item in self.library.details()
                           if item.get("resumable") and (item.get("ghidra") != "complete" or
                           item.get("rea") != "complete" or item.get("decompile") != "complete")), None)
        if incomplete:
            folder = Path(incomplete["path"])
            self._label(window, f"Latest unfinished: {folder.name}", 12, CYAN, "bold").pack(
                anchor="w", padx=20, pady=(15, 3))
            try:
                rows = recovery_stages(read_manifest(folder))
            except (OSError, ValueError, TypeError) as error:
                rows = []
                self._label(window, f"Manifest could not be read: {error}", 11, RED).pack(anchor="w", padx=20)
            if rows:
                labels = {f"{row['label']}  •  {row['status'].upper()}": row for row in rows}
                selected = ctk.StringVar(value=next((label for label, row in labels.items()
                                                      if row["can_resume"]), next(iter(labels))))
                top = ctk.CTkFrame(window, fg_color="transparent")
                top.pack(fill="x", padx=20, pady=(12, 5))
                self._label(top, "STAGE", 11, TEXT, "bold").pack(side="left", padx=(0, 10))
                ctk.CTkOptionMenu(top, variable=selected, values=list(labels), width=340,
                                  fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(side="left")
                stage_hint = self._label(window, "", 11, MUTED, wraplength=740, justify="left")
                stage_hint.pack(anchor="w", padx=20, pady=(2, 8))
                log_box = ctk.CTkTextbox(window, height=260, fg_color=SIDEBAR, text_color=TEXT,
                                          font=self._font(11, mono=True))
                log_box.pack(fill="both", expand=True, padx=20, pady=(0, 5))
                resume_button = self._button(window, "RESUME SELECTED STAGE", lambda: None, 230, True)

                def refresh(*_):
                    row = labels[selected.get()]
                    stage_hint.configure(text=("Ready to resume this stage. Later incomplete stages will follow."
                                               if row["can_resume"] else
                                               "This stage is complete or needs an earlier stage first. Inspect its evidence here."))
                    resume_button.configure(state="normal" if row["can_resume"] else "disabled")
                    log_box.configure(state="normal")
                    log_box.delete("1.0", "end")
                    try:
                        preview = recovery_log_preview(folder, row["key"])
                    except (OSError, ValueError) as error:
                        preview = f"Log preview is unavailable: {error}"
                    log_box.insert("1.0", preview)
                    log_box.configure(state="disabled")

                selected.trace_add("write", refresh)
                refresh()
        row = ctk.CTkFrame(window, fg_color="transparent")
        row.pack(anchor="w", padx=20, pady=(10, 18))

        def choose(action):
            window.grab_release()
            window.destroy()
            action()

        self._button(row, "OPEN HISTORY", lambda: choose(lambda: self.show_page("history")), 145, True).pack(side="left")
        if incomplete and rows:
            resume_button.pack_forget()
            resume_button = self._button(row, "RESUME SELECTED STAGE",
                    lambda: choose(lambda: self._resume_analysis(folder, labels[selected.get()]["key"])), 220)
            resume_button.pack(side="left", padx=8)
            refresh()
        self._button(row, "LATER", lambda: choose(lambda: None), 95).pack(side="left", padx=8)
        window.protocol("WM_DELETE_WINDOW", lambda: choose(lambda: None))

    def _shortcut_analyze(self, with_review):
        if self.busy:
            return
        self.show_page("analyze")
        if self.page_name == "analyze":
            (self._start_analyze_review if with_review else self._start_analysis)()

    def _focus_activity_search(self, _event=None):
        if self.page_name not in {"analyze", "batch", "codex", "updates"}:
            self.show_page("analyze")
        if self.page_name not in {"analyze", "batch", "codex", "updates"}:
            return "break"
        if self.page_name == "analyze":
            self.analyze_tabs.set("Activity")
        self.activity_search_box.focus_set()
        return "break"

    def show_page(self, page):
        if self.page_name == "settings" and getattr(self, "allowed_servers_box", None) is not None:
            try:
                if self.allowed_servers_box.winfo_exists():
                    self.allowed_servers.set(self.allowed_servers_box.get("1.0", "end-1c"))
            except tk.TclError:
                pass
        self._remember_page_tab()
        self.page_name = page
        self._clear(page)
        self.nav_tabs.set(self.nav_group[page])
        for key, button in self.nav.items():
            button.configure(fg_color=FIELD if key == page else "transparent",
                             text_color=GREEN if key == page else MUTED)
        self.heading.configure(text={"analyze": "Analyze a binary", "dashboards": "Scan dashboards",
                                     "batch": "Batch jobs",
                                     "history": "Analysis history",
                                     "investigations": "Investigations", "coverage": "Decompilation coverage",
                                     "flow": "Candidate data flow", "corpus": "Known-answer corpus",
                                     "runtime": "Isolated runtime trace", "bundles": "Investigation bundles",
                                     "unpack": "Archive and firmware unpacking", "similar": "Similar functions",
                                     "plugins": "Review plugins",
                                     "queries": "REA actions", "libraries": "Third-party libraries",
                                     "console": "REA command console",
                                     "compare": "Compare builds", "callpaths": "Visual call paths", "codex": "Agent review",
                                     "advanced": "Graph lab", "lab": "Evidence lab",
                                     "reports": "Findings & evidence", "secrets": "Possible credentials",
                                     "updates": "Component center", "settings": "Settings & dependencies", "about": "About CastorPollux",
                                     "help": "Detailed help", "credits": "Sources & credits"}[page])
        {"analyze": self._analyze_page, "dashboards": self._dashboard_page,
         "batch": self._batch_page,
         "history": self._history_page,
         "investigations": self._investigations_page, "coverage": self._coverage_page,
         "flow": self._flow_page, "corpus": self._corpus_page,
         "runtime": self._runtime_page, "bundles": self._bundles_page,
         "unpack": self._unpack_page, "similar": self._similar_page,
         "plugins": self._plugins_page,
         "queries": self._queries_page, "libraries": self._libraries_page,
         "console": self._console_page,
         "compare": self._compare_page, "callpaths": self._callpaths_page,
         "advanced": self._advanced_page, "lab": self._lab_page, "codex": self._codex_page,
         "reports": self._reports_page, "secrets": self._secrets_page,
         "updates": self._updates_page, "settings": self._settings_page, "about": self._about_page,
         "help": self._help_page, "credits": self._credits_page}[page]()
        active_tabs = {"analyze": "analyze_tabs", "dashboards": "dashboard_tabs",
                       "settings": "settings_tabs"}.get(page)
        if active_tabs:
            self._restore_page_tab(page, getattr(self, active_tabs, None))
        self._save_workspace()

    def _save_workspace(self):
        try:
            self._remember_page_tab()
            save_workspace({"page": self.page_name,
                            "current_folder": str(self.current_folder or ""),
                            "input_path": self.input_path.get(), "output_path": self.output_path.get(),
                            "tabs": self.saved_tabs})
        except OSError as error:
            record_error(str(error), self.current_folder, "workspace preferences")

    def _context_help(self):
        topic = HELP_FOR_PAGE.get(self.page_name, "Find your way around")
        self.show_page("help")
        if topic in self.help_sections:
            self._show_help_topic(topic)
        else:
            self._show_help_topic("All topics")

    def _palette_actions(self):
        keywords = {
            "analyze": "scan decompile binary start", "history": "previous interrupted resume logs",
            "dashboards": "metrics charts performance", "codex": "agent security review",
            "reports": "findings export evidence", "investigations": "saved files browse",
            "coverage": "procedures decompilation", "flow": "source sink data",
            "compare": "diff builds", "settings": "preferences theme font tabs",
            "credits": "licenses sources", "help": "guide tips documentation",
            "console": "command line rea cli", "queries": "rea actions search",
        }
        actions = [(f"page:{key}", self.nav[key].cget("text").strip(),
                    f"{key} {keywords.get(key, '')}", lambda page=key: self.show_page(page))
                   for key in self.nav_group]
        actions += [("choose-binary", "Choose binary", "open browse target file", self._browse_input),
                    ("run-analysis", "Run analysis", "start scan decompile", lambda: self._shortcut_analyze(False)),
                    ("analyze-review", "Analyze and agent review", "scan codex security", lambda: self._shortcut_analyze(True)),
                    ("context-help", "Help for current screen", "guide tips documentation", self._context_help)]
        return actions

    def _command_palette(self):
        existing = getattr(self, "palette_window", None)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            return
        window = ctk.CTkToplevel(self)
        self.palette_window = window
        window.title("CastorPollux | Command palette")
        window.geometry("560x520")
        window.transient(self)
        window.grab_set()
        commands = self._palette_actions()
        by_id = {item[0]: item for item in commands}
        allowed = set(by_id)
        self.palette_state = load_palette(allowed)
        query = ctk.StringVar(value="")
        self.palette_query = query
        search = ctk.CTkEntry(window, textvariable=query, placeholder_text="Search names, keywords, or saved actions…",
                              fg_color=FIELD, text_color=TEXT, font=self._font(14))
        search.pack(fill="x", padx=15, pady=(15, 8))
        controls = ctk.CTkFrame(window, fg_color="transparent")
        controls.pack(fill="x", padx=15, pady=(0, 8))
        view_mode = ctk.StringVar(value="All actions")
        self.palette_view_mode = view_mode
        ctk.CTkOptionMenu(controls, variable=view_mode,
                          values=["All actions", "Saved actions", "Recent commands"],
                          command=lambda _value: render(), width=170,
                          fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(side="left")
        self.palette_clear_history = self._button(controls, "CLEAR HISTORY", lambda: clear_history(), 135)
        self.palette_clear_history.pack(side="right")
        summary = self._label(window, "", 11, MUTED)
        summary.pack(anchor="w", padx=16, pady=(0, 5))
        results = ctk.CTkScrollableFrame(window, fg_color="transparent")
        results.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.palette_results = results

        def invoke(command_id, action):
            self.palette_state["history"] = [command_id] + [value for value in self.palette_state["history"]
                                                               if value != command_id]
            self.palette_state = save_palette(self.palette_state, allowed)
            close()
            action()

        def close():
            if window.winfo_exists():
                window.grab_release()
                window.destroy()

        def toggle_saved(command_id):
            saved = self.palette_state["saved"]
            self.palette_state["saved"] = ([value for value in saved if value != command_id]
                                           if command_id in saved else [command_id] + saved)
            self.palette_state = save_palette(self.palette_state, allowed)
            render()

        def clear_history():
            if self.palette_state["history"] and messagebox.askyesno(
                    "CastorPollux", "Clear command history? Saved commands will remain available.", parent=window):
                self.palette_state["history"] = []
                self.palette_state = save_palette(self.palette_state, allowed)
                render()

        visible_matches = []

        def render(*_unused):
            for child in results.winfo_children():
                child.destroy()
            term = query.get().casefold().strip()[:100]
            rank = {value: index for index, value in enumerate(
                self.palette_state["saved"] + self.palette_state["history"])}
            selected = self.palette_state["saved"] if view_mode.get() == "Saved actions" else (
                self.palette_state["history"] if view_mode.get() == "Recent commands" else None)
            matches = [item for item in commands if (selected is None or item[0] in selected)
                       and term in f"{item[0]} {item[1]} {item[2]}".casefold()]
            matches.sort(key=lambda item: (0 if item[0] in self.palette_state["saved"] else 1,
                                           rank.get(item[0], 999), item[1]))
            visible_matches[:] = matches[:18]
            summary.configure(text=f"{len(self.palette_state['saved'])} saved  •  "
                                   f"{len(self.palette_state['history'])} recent  •  {len(matches)} matches")
            for command_id, title, _keywords, action in visible_matches:
                row = ctk.CTkFrame(results, fg_color="transparent")
                row.pack(fill="x", pady=3)
                self._button(row, title, lambda ident=command_id, command=action: invoke(ident, command), 390).pack(
                    side="left", fill="x", expand=True)
                self._button(row, "★ SAVED" if command_id in self.palette_state["saved"] else "☆ SAVE",
                             lambda ident=command_id: toggle_saved(ident), 95).pack(side="left", padx=(5, 0))
            if not matches:
                self._label(results, "No matching command", 13, MUTED).pack(anchor="w", pady=12)

        query.trace_add("write", render)
        render()
        search.focus_set()
        window.bind("<Escape>", lambda _event: close())
        window.protocol("WM_DELETE_WINDOW", close)
        search.bind("<Return>", lambda _event: invoke(visible_matches[0][0], visible_matches[0][3])
                    if visible_matches else None)

    def _card(self, parent, **kw):
        return ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12,
                            border_width=1, border_color=LINE, **kw)

    def _split_frame(self, parent, count=2, height=420):
        pane = tk.PanedWindow(parent, orient=tk.HORIZONTAL, sashwidth=9, sashpad=3,
                             showhandle=True, bg=BG, bd=0, height=height)
        pane.pack(fill="both", expand=True)
        frames = []
        for _ in range(count):
            frame = ctk.CTkFrame(pane, fg_color="transparent")
            pane.add(frame, minsize=180, stretch="always")
            frames.append(frame)
        pane.bind("<ButtonRelease-1>", lambda _event, p=pane: self._remember_split(p))

        def position():
            if not pane.winfo_exists() or pane.winfo_width() < 400:
                return
            ratio = self.settings["layout_presets"][self.settings["active_layout"]]
            width = pane.winfo_width()
            pane.sash_place(0, round(width * ratio), 0)
            if count == 3:
                pane.sash_place(1, round(width * min(.85, ratio + .25)), 0)

        self.after(120, position)
        return frames

    def _remember_split(self, pane):
        if pane.winfo_exists() and pane.winfo_width() > 0:
            x, _y = pane.sash_coord(0)
            self.last_split_ratio = max(.2, min(.8, x / pane.winfo_width()))

    def _save_current_layout(self):
        name = simpledialog.askstring("Save layout", "Preset name (1–32 letters, numbers, spaces, _ or -):",
                                      parent=self)
        if name is None:
            return
        name = name.strip()
        try:
            presets = {**self.settings["layout_presets"], name: round(self.last_split_ratio, 3)}
            self.settings = save_settings({**self.settings, "layout_presets": presets, "active_layout": name})
            self.layout_choice.set(name)
            self.status_text.set(f"LAYOUT PRESET SAVED: {name}")
        except (OSError, TypeError, ValueError) as error:
            messagebox.showerror("CastorPollux", str(error))

    def _analyze_page(self):
        self._label(self.body, "LOCAL ENGINE  /  REA SOURCE RECONSTRUCTION", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Decompile with REA and Ghidra, then optionally send reconstructed code to an agent.",
                    14, MUTED).pack(anchor="w", pady=(0, 10))
        tabs = ctk.CTkTabview(self.body, height=355, fg_color=BG,
                              segmented_button_fg_color=FIELD, segmented_button_selected_color=GREEN,
                              segmented_button_selected_hover_color=CYAN,
                              segmented_button_unselected_color=FIELD, text_color=TEXT)
        tabs.pack(fill="x", pady=(0, 10))
        for name in ("Target", "Options", "Activity"):
            tabs.add(name)
        self.analyze_tabs = tabs
        card = self._card(tabs.tab("Target"))
        card.pack(fill="x", pady=(0, 8))
        self._label(card, "01   TARGET BINARY", 11, CYAN, "bold", True).pack(anchor="w", padx=22, pady=(18, 8))
        drop_hint = ctk.CTkFrame(card, fg_color=FIELD, border_width=2, border_color=LINE, corner_radius=10)
        drop_hint.pack(fill="x", padx=22, pady=(0, 10))
        self.drop_hint = drop_hint
        self._label(drop_hint, "↓  DROP A BINARY HERE OR USE BROWSE FILE", 13, GREEN, "bold").pack(
            anchor="w", padx=14, pady=(10, 1))
        self._label(drop_hint, "Drop anywhere in CastorPollux. Selection alone does not start a scan.",
                    11, MUTED).pack(anchor="w", padx=14, pady=(0, 10))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=22)
        row.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(row, textvariable=self.input_path, height=42, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT, font=self._font(13),
                     placeholder_text="Choose or drop a PE, ELF, or Mach-O binary").grid(row=0, column=0, sticky="ew")
        self._button(row, "BROWSE FILE", self._browse_input, 125).grid(row=0, column=1, padx=(10, 0))
        self._label(card, "The binary is copied into a new investigation folder; CastorPollux does not run it during static analysis.",
                    11, MUTED, wraplength=800, justify="left").pack(anchor="w", padx=22, pady=(5, 0))
        self._label(card, "02   OUTPUT LOCATION", 11, CYAN, "bold", True).pack(anchor="w", padx=22, pady=(22, 8))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=22, pady=(0, 21))
        row.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(row, textvariable=self.output_path, height=42, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT, font=self._font(13),
                     placeholder_text="Existing folder for saved investigations and reports").grid(row=0, column=0, sticky="ew")
        self._button(row, "CHOOSE FOLDER", self._browse_output, 125).grid(row=0, column=1, padx=(10, 0))
        self._label(card, "A timestamped subfolder is created for each scan; completed work can be reopened from History.",
                    11, MUTED).pack(anchor="w", padx=22, pady=(5, 12))
        card = self._card(tabs.tab("Options"))
        card.pack(fill="x", pady=(0, 8))
        self._label(card, "OPTIONAL LOCAL PDB / DWARF FILE", 11, CYAN, "bold", True).pack(anchor="w", padx=22, pady=(14, 8))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=22, pady=(0, 16))
        ctk.CTkEntry(row, textvariable=self.symbol_path, height=38, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT, placeholder_text="Optional matching PDB or DWARF file").pack(
                         side="left", fill="x", expand=True)
        self._button(row, "BROWSE", self._browse_symbols, 100).pack(side="left", padx=(8, 0))
        self._button(row, "CLEAR", lambda: self.symbol_path.set(""), 75).pack(side="left", padx=(8, 0))
        self._label(card, "PDB GUID and age, or ELF build ID, must match this exact binary. Leave blank to continue without a sidecar.",
                    11, MUTED, wraplength=800, justify="left").pack(anchor="w", padx=22, pady=(0, 10))
        symbols_online = ctk.CTkFrame(card, fg_color="transparent")
        symbols_online.pack(fill="x", padx=22, pady=(0, 15))
        ctk.CTkCheckBox(symbols_online, text="Opt in to online symbol lookup", variable=self.symbol_server_enabled,
                        text_color=TEXT, fg_color=GREEN).pack(side="left")
        ctk.CTkEntry(symbols_online, textvariable=self.symbol_server, width=350, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT,
                     placeholder_text="Allowlisted HTTPS symbol server").pack(side="left", fill="x", expand=True, padx=(12, 0))
        self._label(card, "Online lookup is optional. A missing or mismatched symbol file is skipped; the scan continues.",
                    11, MUTED).pack(anchor="w", padx=22, pady=(0, 15))
        agent_row = ctk.CTkFrame(card, fg_color="transparent")
        agent_row.pack(fill="x", padx=22, pady=(0, 8))
        self._label(agent_row, "REVIEW AGENT", 11, CYAN, "bold", True).pack(side="left", padx=(0, 10))
        ctk.CTkOptionMenu(agent_row, variable=self.review_agent, values=["codex", "claude", "opencode", "ollama"],
                          command=self._agent_changed, width=145, fg_color=FIELD, button_color=LINE,
                          text_color=TEXT).pack(side="left")
        self._label(agent_row, "Report formats are selected on Agent Review.", 11, MUTED).pack(side="left", padx=15)
        self.daybreak_checkbox = ctk.CTkCheckBox(
            card, text="Use Daybreak Blue for Codex review (optional; access required)",
            variable=self.daybreak_blue, text_color=TEXT, fg_color=GREEN,
            hover_color=CYAN, font=self._font(12))
        self.daybreak_checkbox.pack(anchor="w", padx=22, pady=(0, 4))
        self.daybreak_checkbox.configure(state="normal" if self.review_agent.get() == "codex" else "disabled")
        self._label(card, "For best security review results, use a Daybreak-enabled model when available. Standard Codex works without it.",
                    11, MUTED).pack(anchor="w", padx=22, pady=(0, 14))
        self._activity_panel(tabs.tab("Activity"), height=240)
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 16))
        self.run_button = self._button(controls, "▶  ANALYZE", self._start_analysis, 130)
        self.run_button.pack(side="left")
        self.pipeline_button = self._button(controls, "✦  ANALYZE → AGENT REVIEW",
                                            self._start_analyze_review, 250, True)
        self.pipeline_button.pack(side="left", padx=(8, 0))
        self.cancel_button = self._button(controls, "■  CANCEL", self._cancel, 110)
        self.cancel_button.pack(side="left", padx=10)
        self.cancel_button.configure(state="normal" if self.busy else "disabled")
        self.open_button = self._button(controls, "↗  OPEN OUTPUT", self._open_output, 150)
        self.open_button.pack(side="right")
        self.open_button.configure(state="normal" if self.last_output else "disabled")
        scan_card = self._card(self.body)
        scan_card.pack(fill="x", pady=(0, 14))
        header = ctk.CTkFrame(scan_card, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(12, 2))
        initial_state = self.scan_state_text.get()
        state_color = RED if "STOPPED" in initial_state or "INCOMPLETE" in initial_state else \
            CYAN if "RUNNING" in initial_state else GREEN
        self.scan_state_label = self._label(header, "", 16, state_color, "bold",
                                            textvariable=self.scan_state_text)
        self.scan_state_label.pack(side="left")
        self._label(header, "", 17, CYAN, "bold", textvariable=self.scan_percent_text).pack(side="right")
        self._label(scan_card, "", 11, MUTED, textvariable=self.scan_stage_text).pack(
            anchor="w", padx=16, pady=(0, 3))
        self._label(scan_card, "", 11, MUTED, textvariable=self.scan_timing_text).pack(
            anchor="w", padx=16, pady=(0, 9))
        self.scan_progress_bar = ctk.CTkProgressBar(scan_card, height=11, fg_color=FIELD, progress_color=GREEN)
        self.scan_progress_bar.pack(fill="x", padx=16, pady=(0, 15))
        self.scan_progress_bar.set(int(self.scan_percent_text.get().rstrip("%")) / 100)
        controls.pack_configure(before=tabs)
        scan_card.pack_configure(before=tabs)
        if not self.log_records:
            self._log("Ready. Choose a binary to begin.")

    def _batch_page(self):
        self._label(self.body, "QUEUE  /  REPEATABLE LOCAL ANALYSIS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Analyze several binaries in sequence; use Agent Review settings for optional reports.",
                    14, MUTED).pack(anchor="w", pady=(0, 15))
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 8))
        self._button(controls, "ADD BINARIES", self._batch_add_sources, 155, True).pack(side="left")
        self._button(controls, "CLEAR QUEUE", self._batch_clear_sources, 130).pack(side="left", padx=8)
        self._label(controls, "AGENT", 11, CYAN, "bold", True).pack(side="left", padx=(20, 8))
        ctk.CTkOptionMenu(controls, variable=self.batch_agent,
                          values=["none", "codex", "claude", "opencode", "ollama"],
                          width=130, fg_color=FIELD, button_color=LINE,
                          text_color=TEXT).pack(side="left")
        self.batch_list = ctk.CTkTextbox(self.body, height=170, fg_color=SIDEBAR,
                                         border_color=LINE, border_width=1, text_color=TEXT,
                                         font=self._font(12, mono=True))
        self.batch_list.pack(fill="x", pady=(0, 12))
        self._render_batch_sources()
        output_row = ctk.CTkFrame(self.body, fg_color="transparent")
        output_row.pack(fill="x", pady=(0, 11))
        self._label(output_row, "OUTPUT FOLDER", 11, CYAN, "bold", True).pack(side="left", padx=(0, 8))
        ctk.CTkEntry(output_row, textvariable=self.output_path, height=38, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT,
                     placeholder_text="Existing folder for batch investigation subfolders").pack(side="left", fill="x", expand=True)
        self._button(output_row, "CHOOSE", self._browse_output, 100).pack(side="left", padx=(8, 0))
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=(0, 11))
        self.batch_button = self._button(row, "▶  RUN BATCH", self._run_batch_gui, 160, True)
        self.batch_button.pack(side="left")
        self._button(row, "■  CANCEL", self._cancel, 105).pack(side="left", padx=8)
        batch_status = self._card(self.body)
        batch_status.pack(fill="x", pady=(0, 10))
        self._label(batch_status, "CURRENT BINARY", 10, CYAN, "bold", True).pack(anchor="w", padx=13, pady=(9, 1))
        status_line = ctk.CTkFrame(batch_status, fg_color="transparent")
        status_line.pack(fill="x", padx=13)
        self._label(status_line, "", 12, TEXT, "bold", textvariable=self.scan_stage_text).pack(side="left")
        self._label(status_line, "", 12, CYAN, "bold", textvariable=self.scan_percent_text).pack(side="right")
        self._label(batch_status, "", 10, MUTED, textvariable=self.scan_timing_text).pack(
            anchor="w", padx=13, pady=(2, 10))
        self._label(self.body, "BATCH ACTIVITY", 11, MUTED, "bold", True).pack(anchor="w", pady=(0, 6))
        self._activity_panel(self.body, height=240)
        self._log("Choose binaries, then run the queue. A JSON summary is saved in the output folder.")

    def _render_batch_sources(self):
        self.batch_list.delete("1.0", "end")
        self.batch_list.insert("1.0", "\n".join(self.batch_sources) or "No binaries queued.")

    def _batch_add_sources(self):
        chosen = filedialog.askopenfilenames(title="Add binaries to batch")
        self.batch_sources = list(dict.fromkeys([*self.batch_sources, *chosen]))
        self._render_batch_sources()
        self._schedule_draft_save()

    def _batch_clear_sources(self):
        self.batch_sources = []
        self._render_batch_sources()
        self._schedule_draft_save()

    def _run_batch_gui(self):
        if not self.batch_sources:
            messagebox.showerror("CastorPollux", "Add at least one binary to the queue.")
            return
        target = Path(self.output_path.get()).expanduser()
        if not target.is_dir():
            messagebox.showerror("CastorPollux", "Choose an existing output folder.")
            return
        try:
            minimum = int(self.coverage_minimum.get())
            if not 0 <= minimum <= 100:
                raise ValueError
        except ValueError:
            messagebox.showerror("CastorPollux", "Minimum coverage must be a number from 0 to 100.")
            return
        from castorpollux_batch import run_batch
        jobs = home() / "Batches"
        jobs.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S") + "-" + str(time.time_ns() % 1000000).zfill(6)
        summary = target / ("castorpollux-batch-" + stamp + ".json")
        config_path = jobs / ("batch-" + stamp + ".json")
        agent = self.batch_agent.get()
        cli = self.codex_cli_path.get() if agent == self.review_agent.get() else str(find_agent_cli(agent) or "") if agent not in {"none", "ollama"} else ""
        if agent not in {"none", "ollama"} and not Path(cli).is_file():
            messagebox.showerror("CastorPollux", f"Choose or install the {agent} CLI before running this batch.")
            return
        config = {"inputs": list(self.batch_sources), "output": str(target.resolve()), "summary": str(summary.resolve()),
                  "agent": agent, "agent_cli": cli,
                  "formats": [name for name, variable in self.report_formats.items() if variable.get()],
                  "minimum_coverage": minimum, "redact_cloud": self.redact_cloud.get(),
                  "redaction_terms": [term.strip() for term in self.redaction_terms.get().split(",") if term.strip()],
                  "secondary_decompiler": self.secondary_decompiler.get(),
                  "retdec_cli": self.retdec_path.get(), "daybreak_blue": self.daybreak_blue.get(),
                  "local_model": self.local_model.get()}
        if self.symbol_path.get().strip():
            config["symbols"] = self.symbol_path.get().strip()
        if self.symbol_server_enabled.get():
            config["symbol_server"] = self.symbol_server.get().strip()
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        def task():
            try:
                code = run_batch(config_path, lambda message: self._emit("log", message),
                                 self.cancel_event.is_set, self._set_process)
                self._emit("log", f"Batch finished with exit code {code}. Summary: {summary}")
            finally:
                self._capture_agent_usage(None)
        self._start_task(task, kind="batch")

    def _history_page(self):
        self._label(self.body, "SAVED JOBS  /  RESUME INTERRUPTED WORK", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Resume reuses the saved binary and completed analysis stages in the same folder.",
                    13, MUTED).pack(anchor="w", pady=(0, 12))
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 12))
        self._button(controls, "+  ADD FOLDER", self._browse_history, 145, True).pack(side="left")
        self._button(controls, "↻  REFRESH", lambda: self.show_page("history"), 110).pack(side="left", padx=8)
        search = ctk.CTkEntry(self.body, textvariable=self.history_search, placeholder_text="Search filename, path, warnings…",
                              fg_color=FIELD, text_color=TEXT, font=self._font(12))
        search.pack(fill="x", pady=(0, 7))
        search.bind("<KeyRelease>", lambda _event: self._render_history())
        ctk.CTkOptionMenu(controls, variable=self.history_filter,
                          values=["all", "has findings", "needs review", "interrupted", "warnings"],
                          command=lambda _value: self._render_history(), width=145,
                          fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(side="right")
        self.history_list = ctk.CTkFrame(self.body, fg_color="transparent")
        self.history_list.pack(fill="both", expand=True)
        self._render_history()

    def _render_history(self):
        scroll = self.history_list
        for child in scroll.winfo_children():
            child.destroy()
        term = self.history_search.get().casefold().strip()
        selected = self.history_filter.get()
        items = self.library.details()
        if term:
            items = [item for item in items if term in (item["name"] + " " + item["path"] + " " +
                     " ".join(map(str, item["warnings"]))).casefold()]
        if selected == "has findings":
            items = [item for item in items if item["finding_count"]]
        elif selected == "needs review":
            items = [item for item in items if not item["review"]]
        elif selected == "interrupted":
            items = [item for item in items if (item["ghidra"] != "complete" or item["rea"] != "complete" or
                     item["decompile"] not in {"complete", "partial"}) and item["resumable"]]
        elif selected == "warnings":
            items = [item for item in items if item["warnings"]]
        self._label(scroll, f"{len(items)} SAVED INVESTIGATION(S)  •  NEWEST FIRST", 11, CYAN, "bold").pack(
            anchor="w", pady=(0, 6))
        if not items:
            self._label(scroll, "No saved investigations yet.", 13, MUTED).pack(pady=18)
        for item in items[:self.history_limit]:
            folder = Path(item["path"])
            row = self._card(scroll)
            row.pack(fill="x", padx=7, pady=5)
            self._label(row, f"{item['name']}  •  {item.get('date', '')[:19]}", 13, TEXT, "bold").pack(
                anchor="w", padx=14, pady=(10, 2))
            counts = item["coverage"]
            self._label(row, f"Ghidra export: {item['ghidra']}   |   REA evidence: {item['rea']}   |   "
                        f"REA code: {item['decompile']} ({counts.get('succeeded', 0)}/{counts.get('total', 0)})   |   "
                        f"Review: {'stale' if item['review_stale'] else 'saved' if item['review'] else 'none'}",
                        11, GREEN if item["ghidra"] == item["rea"] == item["decompile"] == "complete" else CYAN,
                        mono=True).pack(anchor="w", padx=14)
            if item["ghidra_failure_class"]:
                self._label(row, "Ghidra failure class: " + item["ghidra_failure_class"], 11, RED,
                            "bold").pack(anchor="w", padx=14)
            if item.get("recovery"):
                recovery = item["recovery"]
                self._label(row, "Automatic recovery: " + recovery.get("status", "unknown") +
                            ("  •  " + recovery.get("decision", {}).get("reason", "")[:120]
                             if recovery.get("decision") else ""),
                            11, GREEN if recovery.get("status") == "recovered" else CYAN,
                            "bold").pack(anchor="w", padx=14)
            if item.get("agent_usage"):
                self._label(row, usage_label(item["agent_usage"]), 10, MUTED).pack(anchor="w", padx=14)
            profile = item.get("binary_profile") or {}
            if profile:
                compiler = profile.get("compiler", {}).get("name", "unknown")
                self._label(row, f"TARGET: {profile.get('format', '?')} / {profile.get('architecture', '?')}"
                            f"  •  compiler marker: {compiler}  •  library leads: {item.get('library_leads', 0)}",
                            10, MUTED, mono=True).pack(anchor="w", padx=14)
            self._label(row, f"{str(item['progress'].get('percent', '—')) + '%' if item['progress'] else 'Legacy job'} • {item['progress'].get('stage', 'status unknown')}"
                        f"  |  {counts.get('succeeded', 0)}/{counts.get('total', 0)} procedures"
                        f"  |  {item['finding_count']} findings"
                        f"  |  {item['secret_leads']} secret leads",
                        11, TEXT, "bold").pack(anchor="w", padx=14, pady=(3, 0))
            self._history_timeline(row, folder)
            if item["warnings"]:
                self._label(row, "Latest warning: " + str(item["warnings"][-1])[:190], 11, RED,
                            anchor="w", wraplength=920).pack(anchor="w", padx=14)
            if item["finding_count"]:
                sev = item["severities"]
                self._label(row, f"CRITICAL {sev['critical']}  HIGH {sev['high']}  MEDIUM {sev['medium']}  LOW {sev['low']}",
                            10, RED if sev['critical'] or sev['high'] else CYAN, "bold", mono=True).pack(anchor="w", padx=14)
            self._label(row, str(folder), 10, MUTED, mono=True).pack(anchor="w", padx=14, pady=(0, 5))
            buttons = ctk.CTkFrame(row, fg_color="transparent")
            buttons.pack(anchor="w", padx=14, pady=(0, 10))
            self._button(buttons, "OPEN", lambda p=folder: self._select_investigation(p), 82).pack(side="left")
            if item["resumable"] and (item["ghidra"] != "complete" or item["rea"] != "complete" or
                                      item["decompile"] != "complete"):
                self._button(buttons, "▶  RESUME", lambda p=folder: self._resume_analysis(p), 110, True).pack(
                    side="left", padx=6)
            self._button(buttons, "DASHBOARD", lambda p=folder: self._open_dashboard(p), 120).pack(side="left", padx=6)
            self._button(buttons, "REVIEW", lambda p=folder: self._history_review(p), 100).pack(side="left", padx=6)
            if item["review"]:
                self._button(buttons, "FINDINGS", lambda p=folder: self._history_findings(p), 105).pack(side="left", padx=3)
            self._button(buttons, f"LOGS ({len(item['logs'])})", lambda p=folder: self._show_history_logs(p), 110).pack(
                side="left", padx=3)
            self._button(buttons, "DIAGNOSTICS ZIP", lambda p=folder: self._export_diagnostics(p), 145).pack(
                side="left", padx=3)
            if item.get("recovery"):
                extra = ctk.CTkFrame(row, fg_color="transparent")
                extra.pack(anchor="w", padx=14, pady=(0, 9))
                self._button(extra, "PREVIEW REDACTED DIAGNOSTICS", lambda p=folder: self._show_diagnostics(p), 250).pack(side="left")
                self._button(extra, "COMPARE RECOVERY ATTEMPTS", lambda p=folder: self._show_recovery(p), 235).pack(side="left", padx=6)
        if len(items) > self.history_limit:
            self._button(scroll, f"SHOW MORE ({len(items) - self.history_limit} REMAINING)",
                         self._more_history, 280).pack(pady=10)

    def _more_history(self):
        self.history_limit += 40
        self._render_history()

    def _history_timeline(self, parent, folder):
        try:
            _, detail = load_metrics(folder)
            stages = [(str(stage.get("name", "stage")), float(stage.get("wall_seconds", 0)))
                      for stage in detail.get("stages", []) if float(stage.get("wall_seconds", 0)) > 0]
        except (OSError, ValueError, TypeError):
            stages = []
        if not stages:
            return
        total = sum(seconds for _, seconds in stages)
        canvas = tk.Canvas(parent, height=29, bg=CARD, highlightthickness=0, cursor="hand2")
        canvas.pack(fill="x", padx=14, pady=(6, 1))
        def draw(event):
            canvas.delete("all")
            width = max(100, event.width - 4)
            position = 2.0
            for label, seconds in stages:
                segment = width * seconds / total
                color = CYAN if "REA" in label else GREEN if "Ghidra" in label else LINE
                canvas.create_rectangle(position, 3, position + segment, 15, fill=color, outline="")
                position += segment
            canvas.create_text(2, 24, anchor="w", fill=MUTED, font=self._tk_font(9),
                               text="SCAN TIMELINE  " + "  •  ".join(
                                   f"{name.replace('Running ', '')[:17]} {format_duration(seconds)}"
                                   for name, seconds in stages[:4]) + "  ↗ Dashboard")
        canvas.bind("<Configure>", draw)
        canvas.bind("<Button-1>", lambda _event, p=folder: self._open_dashboard(p))

    def _open_dashboard(self, folder):
        self.current_folder = Path(folder)
        self.dashboard_selection.set(str(self.current_folder))
        self.show_page("dashboards")

    def _dashboard_stat(self, parent, title, value, note="", color=GREEN):
        card = self._card(parent)
        card.pack(side="left", fill="both", expand=True, padx=4)
        self._label(card, title.upper(), 10, MUTED, "bold", True).pack(anchor="w", padx=14, pady=(12, 3))
        self._label(card, str(value), 22, color, "bold").pack(anchor="w", padx=14)
        if note:
            self._label(card, note, 10, MUTED, wraplength=200, justify="left").pack(
                anchor="w", padx=14, pady=(1, 12))
        else:
            self._label(card, " ", 10, MUTED).pack(anchor="w", padx=14, pady=(1, 12))

    def _dashboard_bars(self, parent, rows, unit="s"):
        maximum = max((float(value) for _, value in rows), default=0) or 1
        for name, value in rows:
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=4)
            self._label(row, str(name)[:48], 11, TEXT, "bold").pack(side="left")
            self._label(row, f"{value:.1f} {unit}", 11, CYAN, "bold", True).pack(side="right")
            bar = ctk.CTkProgressBar(parent, height=7, progress_color=CYAN, fg_color=FIELD)
            bar.pack(fill="x", padx=10, pady=(0, 5))
            bar.set(max(0, min(1, float(value) / maximum)))

    def _dashboard_plot(self, parent, values, title, unit, color=GREEN):
        self._label(parent, title, 12, TEXT, "bold").pack(anchor="w", padx=12, pady=(12, 3))
        canvas = tk.Canvas(parent, height=170, bg=FIELD, highlightthickness=0)
        canvas.pack(fill="x", padx=12, pady=(0, 13))
        if not values:
            canvas.create_text(20, 75, anchor="w", fill=MUTED, text="No samples recorded for this view.")
            return
        points = [max(0, float(value)) for value in values]
        def draw(event):
            canvas.delete("all")
            width = max(100, event.width)
            left, top, right, bottom = 42, 16, width - 18, 140
            ceiling = max(points) or 1
            for fraction in (0, 0.5, 1):
                y = bottom - fraction * (bottom - top)
                canvas.create_line(left, y, right, y, fill=LINE, dash=(3, 5))
                canvas.create_text(6, y, anchor="w", fill=MUTED,
                                   text=f"{ceiling * fraction:.0f}", font=self._tk_font(9, mono=True))
            coords = []
            for index, value in enumerate(points):
                x = left + index * (right - left) / max(1, len(points) - 1)
                y = bottom - value / ceiling * (bottom - top)
                coords.extend((x, y))
            if len(coords) >= 4:
                canvas.create_line(*coords, fill=color, width=2, smooth=False)
            elif coords:
                canvas.create_oval(coords[0] - 3, coords[1] - 3, coords[0] + 3, coords[1] + 3,
                                   fill=color, outline="")
            canvas.create_text(left, 154, anchor="w", fill=MUTED,
                               text=f"{len(points)} observations • peak {ceiling:.1f} {unit}",
                               font=self._tk_font(10))
        canvas.bind("<Configure>", draw)

    def _dashboard_page(self):
        self._label(self.body, "SCAN TELEMETRY  /  SAVED INVESTIGATIONS", 11, GREEN, mono=True).pack(
            anchor="w", pady=(0, 7))
        self._label(self.body, "Compare engine time, observed resource use, and decompilation quality.",
                    13, MUTED).pack(anchor="w", pady=(0, 12))
        items = self.library.details()
        if not items:
            self._label(self.body, "Run an analysis to populate the dashboards.", 14, MUTED).pack(pady=25)
            return
        self.dashboard_paths = {str(Path(item["path"])): item for item in items}
        choices = list(self.dashboard_paths)
        chosen = self.dashboard_selection.get()
        if chosen not in self.dashboard_paths:
            chosen = str(self.current_folder) if str(self.current_folder) in self.dashboard_paths else choices[0]
            self.dashboard_selection.set(chosen)
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 10))
        ctk.CTkOptionMenu(controls, variable=self.dashboard_selection, values=choices,
                          command=lambda _value: self.show_page("dashboards"), width=420,
                          fg_color=FIELD, button_color=LINE, text_color=TEXT,
                          font=self._font(11)).pack(side="left", fill="x", expand=True)
        self._button(controls, "REFRESH", lambda: self.show_page("dashboards"), 100).pack(side="left", padx=7)
        exports = ctk.CTkFrame(self.body, fg_color="transparent")
        exports.pack(fill="x", pady=(0, 10))
        self._button(exports, "EXPORT CSV", self._export_dashboard_csv, 130).pack(side="left")
        self._button(exports, "SHAREABLE HTML", self._export_dashboard_html, 160, True).pack(side="left", padx=8)
        item = self.dashboard_paths[chosen]
        folder = Path(chosen)
        try:
            index, detail = load_metrics(folder)
        except (OSError, ValueError, TypeError) as error:
            self._label(self.body, f"Metrics unavailable: {error}", 12, RED).pack(anchor="w")
            return
        seconds = detail.get("wall_seconds")
        counts = detail.get("rea_decompile_counts") or item["coverage"]
        succeeded, total = int(counts.get("succeeded", 0)), int(counts.get("total", 0))
        coverage = round(100 * succeeded / total) if total else 0
        runs = index.get("runs", [])
        tabs = ctk.CTkTabview(self.body, fg_color=BG, segmented_button_fg_color=FIELD,
                              segmented_button_selected_color=GREEN,
                              segmented_button_selected_hover_color=CYAN,
                              segmented_button_unselected_color=FIELD,
                              text_color=TEXT)
        tabs.pack(fill="both", expand=True)
        for name in ("Overview", "Performance", "Resources", "Quality"):
            tabs.add(name)
        self.dashboard_tabs = tabs

        overview = tabs.tab("Overview")
        stats = ctk.CTkFrame(overview, fg_color="transparent")
        stats.pack(fill="x", pady=(9, 14))
        self._dashboard_stat(stats, "Scan duration", f"{seconds:.1f} s" if seconds is not None else "Unknown",
                             "Latest analysis attempt")
        self._dashboard_stat(stats, "REA coverage", f"{coverage}%" if total else "Unknown",
                             f"{succeeded}/{total} procedures", GREEN if coverage >= 80 else CYAN)
        self._dashboard_stat(stats, "Run attempts", len(runs), "Includes resumed scans")
        self._dashboard_stat(stats, "Findings", item["finding_count"], "Saved agent findings", RED if item["finding_count"] else CYAN)
        status = self._card(overview)
        status.pack(fill="x", pady=5)
        self._label(status, "ENGINE STATUS", 11, CYAN, "bold", True).pack(anchor="w", padx=14, pady=(12, 4))
        self._label(status, f"Ghidra export: {item['ghidra']}    •    REA evidence: {item['rea']}    •    "
                    f"REA decompilation: {item['decompile']}", 12, TEXT, "bold").pack(anchor="w", padx=14, pady=(0, 12))
        self._label(overview, detail.get("sampling_note", ""), 11, MUTED, wraplength=850,
                    justify="left").pack(anchor="w", pady=10)

        performance = tabs.tab("Performance")
        summary = trend([Path(row["path"]) for row in items[:50]])
        perf_stats = ctk.CTkFrame(performance, fg_color="transparent")
        perf_stats.pack(fill="x", pady=(9, 13))
        self._dashboard_stat(perf_stats, "Recent median", f"{summary['median_seconds']:.1f} s"
                             if summary["median_seconds"] is not None else "Unknown", "Up to 50 investigations")
        self._dashboard_stat(perf_stats, "Recent p95", f"{summary['p95_seconds']:.1f} s"
                             if summary["p95_seconds"] is not None else "Unknown", "Across mixed binary sizes")
        self._dashboard_stat(perf_stats, "Current run", detail.get("status", "unknown"),
                             detail.get("finished_at", "")[:19])
        card = self._card(performance)
        card.pack(fill="x", pady=5)
        self._label(card, "LATEST RUN • STAGE DURATIONS", 11, CYAN, "bold", True).pack(anchor="w", padx=12, pady=(12, 4))
        stages = [(row.get("name", "stage"), float(row.get("wall_seconds", 0))) for row in detail.get("stages", [])]
        if stages:
            self._dashboard_bars(card, stages)
        else:
            self._label(card, "Stage timing was not captured for this investigation.", 11, MUTED).pack(
                anchor="w", padx=12, pady=12)
        recent = list(reversed(summary["rows"][:16]))
        trend_card = self._card(performance)
        trend_card.pack(fill="x", pady=5)
        self._dashboard_plot(trend_card, [row["seconds"] for row in recent],
                             "Recent investigation duration", "seconds", CYAN)
        self._label(performance, "Attempts for this investigation: " + "  •  ".join(
                    f"{run.get('status', '?')} {float(run.get('wall_seconds') or 0):.1f}s" for run in runs[-8:]),
                    11, MUTED, wraplength=880, justify="left").pack(anchor="w", pady=8)

        resources = tabs.tab("Resources")
        processes = detail.get("processes", [])
        if not processes:
            self._label(resources, "No process samples were captured. Legacy scans have timing only.",
                        13, MUTED).pack(anchor="w", pady=18)
        for process in processes:
            card = self._card(resources)
            card.pack(fill="x", pady=6)
            name = process.get("stage", "Engine")
            self._label(card, name.upper(), 11, CYAN, "bold", True).pack(anchor="w", padx=12, pady=(12, 3))
            peak = process.get("peak_working_set_bytes")
            private = process.get("peak_private_bytes")
            cpu = process.get("sampled_cpu_seconds")
            self._label(card, f"Peak working set: {peak / 1048576:.1f} MiB" if peak else "Peak working set: unavailable",
                        12, TEXT, "bold").pack(anchor="w", padx=12)
            self._label(card, f"Peak private bytes: {private / 1048576:.1f} MiB" if private else
                        "Peak private bytes: unavailable", 11, MUTED).pack(anchor="w", padx=12)
            self._label(card, f"Sampled CPU: {cpu:.1f} s" if cpu is not None else "Sampled CPU: unavailable",
                        11, MUTED).pack(anchor="w", padx=12)
            values = [sample.get("working_set_bytes", 0) / 1048576 for sample in process.get("samples", [])]
            self._dashboard_plot(card, values, "Working set over process time", "MiB")
        self._label(resources, "Values sample the launched engine process and its children every 2 seconds. "
                    "Short peaks can be missed; CPU is measured from the first observation.",
                    11, MUTED, wraplength=850, justify="left").pack(anchor="w", pady=8)

        quality = tabs.tab("Quality")
        quality_stats = ctk.CTkFrame(quality, fg_color="transparent")
        quality_stats.pack(fill="x", pady=(9, 13))
        inspected = items[:50]
        fully_decompiled = sum(row["decompile"] == "complete" for row in inspected)
        failed_ghidra = sum(row["ghidra"] == "failed" for row in inspected)
        self._dashboard_stat(quality_stats, "Complete REA", fully_decompiled,
                             f"of {len(inspected)} recent investigations")
        self._dashboard_stat(quality_stats, "Failed Ghidra", failed_ghidra,
                             "Check History for failure cause", RED if failed_ghidra else GREEN)
        self._dashboard_stat(quality_stats, "Latest coverage", f"{coverage}%" if total else "Unknown",
                             f"{succeeded} reconstructed procedures")
        quality_card = self._card(quality)
        quality_card.pack(fill="x", pady=5)
        self._label(quality_card, "RECENT DECOMPILATION COVERAGE", 11, CYAN, "bold", True).pack(
            anchor="w", padx=12, pady=(12, 4))
        rows = []
        for row in inspected[:12]:
            values = row["coverage"]
            count = int(values.get("total", 0))
            rows.append((row["name"], 100 * int(values.get("succeeded", 0)) / count if count else 0))
        self._dashboard_bars(quality_card, rows, "%")
        self._label(quality, "Coverage measures procedure decompilation, not correctness or review completeness.",
                    11, MUTED).pack(anchor="w", pady=8)

    def _export_dashboard_csv(self):
        folder = Path(self.dashboard_selection.get())
        if not folder.is_dir():
            return
        destination = filedialog.asksaveasfilename(title="Save scan metrics CSV", defaultextension=".csv",
                                                    initialfile=folder.name + "-scan-metrics.csv",
                                                    filetypes=[("CSV", "*.csv")])
        if destination:
            try:
                export_metrics_csv(folder, Path(destination))
                self.status_text.set("SCAN METRICS CSV EXPORTED")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _export_dashboard_html(self):
        folder = Path(self.dashboard_selection.get())
        if not folder.is_dir():
            return
        destination = filedialog.asksaveasfilename(title="Save standalone dashboard HTML",
                                                    defaultextension=".html",
                                                    initialfile=folder.name + "-dashboard.html",
                                                    filetypes=[("HTML", "*.html")])
        if not destination:
            return
        try:
            items = self.library.details()
            item = next(row for row in items if Path(row["path"]).resolve() == folder.resolve())
            export_dashboard_html(folder, item, items, Path(destination), APP_VERSION)
            self.status_text.set("SHAREABLE DASHBOARD HTML EXPORTED")
            messagebox.showinfo("CastorPollux", "Standalone dashboard saved. It includes the binary filename and "
                                "summary metrics; review the HTML before sharing.")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _history_findings(self, folder):
        self.current_folder = folder
        self.show_page("reports")

    def _show_history_logs(self, folder):
        logs = sorted(folder.glob("*.log"))
        logs += sorted((folder / "GhidraAttempts").glob("*.log"))
        errors = folder / "errors.jsonl"
        if errors.is_file():
            logs.append(errors)
        if not logs:
            messagebox.showinfo("CastorPollux", "No logs have been written for this investigation.")
            return
        window = ctk.CTkToplevel(self)
        window.title(f"CastorPollux logs • {folder.name}")
        window.geometry("950x650")
        choices = {str(path.relative_to(folder)): path for path in logs}
        selected = ctk.StringVar(value=next(iter(choices)))
        view = ctk.CTkTextbox(window, fg_color=SIDEBAR, text_color=TEXT, font=self._font(11, mono=True))
        self._install_log_menu(view)
        def show(_choice=None):
            path = choices[selected.get()]
            view.delete("1.0", "end")
            view.insert("1.0", path.read_text(encoding="utf-8", errors="replace")[-500000:])
        ctk.CTkOptionMenu(window, variable=selected, values=list(choices), command=show,
                          fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(fill="x", padx=12, pady=10)
        view.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        show()

    def _export_diagnostics(self, folder):
        path = filedialog.asksaveasfilename(title="Save redacted diagnostic ZIP", defaultextension=".zip",
                                            initialfile=folder.name + "-diagnostics.zip",
                                            filetypes=[("ZIP", "*.zip")])
        if not path:
            return
        try:
            export_diagnostics(folder, Path(path))
            messagebox.showinfo("CastorPollux", "Redacted diagnostics saved. Review the ZIP before sharing it.")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _browse_history(self):
        folder = filedialog.askdirectory(title="Choose a saved CastorPollux investigation")
        if folder:
            try:
                self.library.add(Path(folder))
                self.show_page("history")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _history_review(self, folder):
        self.current_folder = folder
        self.review_folder.set(str(folder))
        self.show_page("codex")

    def _resume_analysis(self, folder, stage=None):
        if self.busy:
            return
        try:
            manifest = read_manifest(folder)
            if stage is not None and stage not in {row["key"] for row in recovery_stages(manifest)
                                               if row["can_resume"]}:
                raise ValueError("That stage is complete or an earlier stage must finish first")
            binary = folder / manifest.get("saved_binary", "")
            if not binary.is_file():
                raise ValueError("The saved binary is missing")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            runner = AnalysisRunner(self.store, lambda m: self._emit("log", m),
                                    self.cancel_event.is_set, self._set_process)
            try:
                result = runner.run(binary, folder.parent, resume_folder=folder)
                self._diagnose_with_preview(runner, result)
                self._emit("output", str(result))
                self._signal_analysis_status(result)
            finally:
                self._capture_agent_usage(folder)
        self.show_page("analyze")
        self._start_task(task, kind="scan")

    def _investigations_page(self):
        self._label(self.body, "SAVED ANALYSIS  /  SEARCHABLE EVIDENCE", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 8))
        self._button(controls, "+  OPEN INVESTIGATION", self._browse_investigation, 185, True).pack(side="left")
        self._button(controls, "↗  OPEN FOLDER", self._open_current_folder, 145).pack(side="left", padx=8)
        self._button(controls, "SAVE LAYOUT", self._save_current_layout, 135).pack(side="right")
        current = str(self.current_folder) if self.current_folder else "No investigation selected"
        self.current_label = self._label(self.body, current, 11, MUTED, mono=True, anchor="w")
        self.current_label.pack(fill="x", pady=(0, 8))
        if self.current_folder:
            try:
                manifest = read_manifest(self.current_folder)
                signature = manifest.get("target_signature")
                if signature is None:
                    binary = self.current_folder / manifest.get("saved_binary", "")
                    signature = authenticode_status(binary)
                signed = signature.get("status", "unknown")
                subject = signature.get("subject", "")
                self._label(self.body, f"TARGET SIGNATURE: {signed}  {subject}"[:150], 10,
                            GREEN if signed == "Valid" else MUTED, mono=True, anchor="w").pack(fill="x", pady=(0, 8))
                symbol_info = manifest.get("symbols") or {}
                if symbol_info:
                    self._label(self.body,
                                f"DEBUG SYMBOLS: {symbol_info.get('kind', '?').upper()}  "
                                f"{symbol_info.get('status', '?')}  {symbol_info.get('file', '')}"[:150],
                                10, CYAN, mono=True, anchor="w").pack(fill="x", pady=(0, 8))
                profile = manifest.get("binary_profile") or {}
                if profile:
                    self._label(self.body,
                                f"BINARY: {profile.get('format', '?')} / {profile.get('architecture', '?')} "
                                f"({profile.get('bitness') or '?'}-bit)  |  compiler marker: "
                                f"{profile.get('compiler', {}).get('name', 'unknown')}",
                                10, CYAN, mono=True, anchor="w").pack(fill="x", pady=(0, 8))
            except Exception:
                pass
        recents = ctk.CTkFrame(self.body, fg_color=CARD, corner_radius=8)
        recents.pack(fill="x", pady=(0, 12))
        for item in self.library.list()[:3]:
            label = f"{item['name']}  •  {item.get('date', '')[:16]}  •  {item['sha256'][:12]}"
            self._button(recents, label, lambda p=Path(item["path"]): self._select_investigation(p), 500).pack(
                fill="x", pady=2)
        select = ctk.CTkFrame(self.body, fg_color="transparent")
        select.pack(fill="x", pady=(0, 8))
        self.category_picker = ctk.CTkSegmentedButton(select,
            values=["functions", "strings", "imports", "xrefs", "calls", "rea code", "pseudocode"],
            command=self._set_search_category, selected_color=FIELD, selected_hover_color=LINE,
            unselected_color=CARD, unselected_hover_color=FIELD, text_color=TEXT,
            font=self._font(11, "bold", True), height=33)
        self.category_picker.pack(fill="x")
        self.category_picker.set(self.search_category)
        search_row = ctk.CTkFrame(self.body, fg_color="transparent")
        search_row.pack(fill="x", pady=(0, 9))
        self.search_entry = ctk.CTkEntry(search_row, textvariable=self.search_text,
            placeholder_text="Search addresses, names, strings, or code…", height=37,
            fg_color=FIELD, border_color=LINE, text_color=TEXT, font=self._font(12))
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", lambda event: self._schedule_search())
        self._button(search_row, "SEARCH", self._search_results, 90).pack(side="left", padx=(8, 0))
        left, right = self._split_frame(self.body, height=455)
        self.rows_panel = ctk.CTkScrollableFrame(left, fg_color=CARD, border_width=1,
                                                  border_color=LINE, scrollbar_button_color=FIELD)
        self.rows_panel.pack(fill="both", expand=True, padx=(0, 4))
        self.detail_box = ctk.CTkTextbox(right, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                          text_color=TEXT, font=self._font(11, mono=True))
        self.detail_box.pack(fill="both", expand=True, padx=(4, 0))
        self.detail_box.insert("end", "Select a result to inspect saved evidence and pseudocode.")
        self._search_results()

    def _flow_page(self):
        self._label(self.body, "REA SOURCE → RISKY OPERATION  /  CANDIDATE LEADS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Bounded local and cross-function flow candidates. Validate every path manually.",
                    12, MUTED).pack(anchor="w", pady=(0, 12))
        flow_controls = ctk.CTkFrame(self.body, fg_color="transparent")
        flow_controls.pack(fill="x", pady=(0, 8))
        self._button(flow_controls, "REBUILD FLOW LEADS", self._rebuild_flow, 180, True).pack(side="left")
        self._button(flow_controls, "EDIT RULES", self._edit_flow_rules, 120).pack(side="left", padx=8)
        trial = ctk.CTkFrame(self.body, fg_color="transparent")
        trial.pack(fill="x", pady=(0, 8))
        ctk.CTkEntry(trial, textvariable=self.rule_candidate, fg_color=FIELD, border_color=LINE,
                     text_color=TEXT).pack(side="left", fill="x", expand=True)
        self._button(trial, "CANDIDATE JSON", self._browse_rule_candidate, 140).pack(side="left", padx=6)
        self._button(trial, "TEST CORPUS", self._test_rule_candidate, 125).pack(side="left")
        self._button(trial, "ENABLE TESTED", self._enable_rule_candidate, 145).pack(side="left", padx=(6, 0))
        self.flow_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                       text_color=TEXT, font=self._font(12, mono=True))
        self.flow_box.pack(fill="both", expand=True)
        self._show_flow()

    def _edit_flow_rules(self):
        try:
            active = create_default_rules()
            path = active.with_name("data-flow-rules-candidate.json")
            if not path.is_file():
                shutil.copy2(active, path)
            self.rule_candidate.set(str(path))
            self.rule_trial_sha256 = ""
            os.startfile(path)
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _browse_rule_candidate(self):
        path = filedialog.askopenfilename(title="Choose candidate flow rules", filetypes=[("JSON", "*.json")])
        if path:
            self.rule_candidate.set(path)
            self.rule_trial_sha256 = ""

    def _test_rule_candidate(self):
        def task():
            folders = [Path(item["path"]) for item in self.library.list()]
            result = evaluate_rule_change(Path(self.rule_candidate.get()), Path(self.corpus_path.get()), folders)
            self._emit("rule_trial", result)
        self._start_task(task)

    def _enable_rule_candidate(self):
        if not self.rule_trial_sha256:
            messagebox.showerror("CastorPollux", "Test this candidate against labeled corpus cases first.")
            return
        def task():
            folders = [Path(item["path"]) for item in self.library.list()]
            result = activate_rule_change(Path(self.rule_candidate.get()), Path(self.corpus_path.get()),
                                          folders, self.rule_trial_sha256)
            self._emit("rule_activated", result)
        self._start_task(task)

    def _show_flow(self):
        if not self.current_folder:
            self.flow_box.insert("1.0", "Choose an investigation first.")
            return
        path = self.current_folder / "data-flow.json"
        if not path.is_file():
            self.flow_box.insert("1.0", "No flow leads saved. Click REBUILD FLOW LEADS after REA decompilation.")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            lines = [f"{len(data['leads'])} leads across {data['procedures_scanned']}/{data['procedures_total']} procedures", ""]
            for lead in data["leads"]:
                lines += [f"{lead['function']} @ {lead['address']}",
                          f"  {lead['source_api']} line {lead['source_line']}: {lead['source_text']}",
                          f"  via: {' → '.join(lead['variables']) or 'direct call'}",
                          f"  {lead['sink_api']} line {lead['sink_line']}: {lead['sink_text']}", ""]
            inter_path = self.current_folder / "cross-function-flow.json"
            if inter_path.is_file():
                inter = json.loads(inter_path.read_text(encoding="utf-8"))
                lines += [f"CROSS-FUNCTION LEADS: {len(inter['leads'])}", ""]
                for lead in inter["leads"][:200]:
                    chain = " → ".join(item["name"] for item in lead["call_path"])
                    lines += [f"  {lead['source_api']} → {lead['sink_api']}: {chain}",
                              f"  source {lead['source_address']} line {lead['source_line']}: {lead['source_text']}",
                              f"  sink {lead['sink_address']} line {lead['sink_line']}: {lead['sink_text']}", ""]
                lines += ["CROSS-FUNCTION LIMITS"] + inter["limitations"]
            lines += ["LIMITS"] + data["limitations"]
            self.flow_box.insert("1.0", "\n".join(lines))
        except Exception as error:
            self.flow_box.insert("1.0", f"Cannot read flow report: {error}")

    def _rebuild_flow(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        def task():
            report = build_data_flow(self.current_folder)
            inter = build_cross_function_flow(self.current_folder)
            self._emit("log", f"Flow rebuilt: {len(report['leads'])} local and {len(inter['leads'])} cross-function lead(s).")
            self._emit("flow", len(report["leads"]))
        self._start_task(task)

    def _corpus_page(self):
        self._label(self.body, "ADJUDICATED TARGETS  /  FALSE POSITIVES  /  MISSED FINDINGS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Confirmed findings become expected answers. Mark a corpus case complete only after reviewing all findings.",
                    12, MUTED, wraplength=760).pack(anchor="w", pady=(0, 12))
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=(0, 10))
        ctk.CTkEntry(row, textvariable=self.corpus_path, height=38, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT).pack(side="left", fill="x", expand=True)
        self._button(row, "CHOOSE JSON", self._browse_corpus, 120).pack(side="left", padx=(8, 0))
        buttons = ctk.CTkFrame(self.body, fg_color="transparent")
        buttons.pack(fill="x", pady=(0, 10))
        self._button(buttons, "ADD CONFIRMED", self._add_corpus_case, 150, True).pack(side="left")
        self._button(buttons, "EVALUATE HISTORY", self._evaluate_corpus, 170).pack(side="left", padx=8)
        self._button(buttons, "OPEN CORPUS", self._open_corpus, 130).pack(side="left")
        answer_controls = ctk.CTkFrame(self.body, fg_color="transparent")
        answer_controls.pack(fill="x", pady=(0, 8))
        self._button(answer_controls, "SAVE FLOW ANSWERS", self._save_flow_answers, 160).pack(side="left")
        ctk.CTkCheckBox(answer_controls, text="All expected findings labeled", variable=self.corpus_complete,
                        text_color=MUTED, fg_color=GREEN, hover_color=CYAN).pack(side="left", padx=12)
        self._label(self.body, "Adjudicated expected flows for selected investigation (JSON; [] means known negative):",
                    11, CYAN).pack(anchor="w", pady=(0, 4))
        self.flow_answers = ctk.CTkTextbox(self.body, height=85, fg_color=FIELD, border_width=1,
                                           border_color=LINE, text_color=TEXT, font=self._font(11, mono=True))
        self.flow_answers.pack(fill="x", pady=(0, 8))
        self.flow_answers.insert("1.0", '[{"function":"parse","source_api":"ReadFile","sink_api":"memcpy"}]')
        self.corpus_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1,
                                         border_color=LINE, text_color=TEXT, font=self._font(12, mono=True))
        self.corpus_box.pack(fill="both", expand=True)
        self.corpus_box.insert("1.0", "Add confirmed findings from the selected investigation, then evaluate saved review results.\n"
                               "Corpus JSON is editable. Set complete=true only when all expected findings are labeled.")

    def _browse_corpus(self):
        path = filedialog.asksaveasfilename(title="Choose known-answer corpus JSON", defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if path:
            self.corpus_path.set(path)

    def _open_corpus(self):
        path = Path(self.corpus_path.get())
        if path.is_file():
            os.startfile(path)

    def _add_corpus_case(self):
        try:
            if not self.current_folder:
                raise ValueError("Choose an investigation first")
            case = add_confirmed_case(Path(self.corpus_path.get()), self.current_folder,
                                      self.corpus_complete.get())
            self.corpus_box.delete("1.0", "end")
            self.corpus_box.insert("1.0", json.dumps(case, indent=2))
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _evaluate_corpus(self):
        try:
            folders = [Path(item["path"]) for item in self.library.list()]
            result = evaluate_corpus(Path(self.corpus_path.get()), folders)
            output = Path(self.corpus_path.get()).with_name("known-answer-evaluation.json")
            output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            self.corpus_box.delete("1.0", "end")
            self.corpus_box.insert("1.0", json.dumps(result, indent=2))
            self.status_text.set(f"CORPUS: {result['cases_evaluated']} CASES EVALUATED")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _save_flow_answers(self):
        try:
            if not self.current_folder:
                raise ValueError("Choose an investigation first")
            answers = json.loads(self.flow_answers.get("1.0", "end"))
            case = set_flow_answers(Path(self.corpus_path.get()), self.current_folder,
                                    answers, self.corpus_complete.get())
            self.corpus_box.delete("1.0", "end")
            self.corpus_box.insert("1.0", json.dumps(case, indent=2))
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _runtime_page(self):
        self._label(self.body, "WINDOWS SANDBOX  /  UNTESTED FEATURE", 12, RED, "bold", True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Trace execution inside Windows Sandbox has not been tested on this build.",
                    12, RED).pack(anchor="w", pady=(0, 8))
        available = sandbox_executable() is not None
        self._label(self.body, "Windows Sandbox available" if available else
                    "Windows Sandbox is not installed; you can prepare a trace job for another supported PC.",
                    12, GREEN if available else MUTED, wraplength=760).pack(anchor="w", pady=(0, 12))
        self._label(self.body, str(self.current_folder or "Choose an investigation first"), 10, MUTED,
                    mono=True).pack(anchor="w", pady=(0, 8))
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=(0, 8))
        self._label(row, "Arguments (JSON array)", 11, CYAN).pack(side="left")
        ctk.CTkEntry(row, textvariable=self.trace_arguments, fg_color=FIELD, border_color=LINE,
                     text_color=TEXT, width=310).pack(side="left", padx=8)
        self._label(row, "Timeout (s)", 11, CYAN).pack(side="left")
        ctk.CTkEntry(row, textvariable=self.trace_timeout, fg_color=FIELD, border_color=LINE,
                     text_color=TEXT, width=75).pack(side="left", padx=8)
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 10))
        self._button(controls, "PREPARE JOB", self._prepare_runtime, 140, True).pack(side="left")
        self._button(controls, "LAUNCH SANDBOX", self._launch_runtime, 155).pack(side="left", padx=8)
        self._button(controls, "CORRELATE TRACE", self._correlate_runtime, 155).pack(side="left")
        self._button(controls, "TRACE TIMELINE", self._show_trace_timeline, 150).pack(side="left", padx=8)
        self.timeline_links = ctk.CTkScrollableFrame(self.body, height=130, fg_color=SIDEBAR)
        self.timeline_links.pack(fill="x", pady=(0, 8))
        self.runtime_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1,
                                           border_color=LINE, text_color=TEXT, font=self._font(12, mono=True))
        self.runtime_box.pack(fill="both", expand=True)
        self.runtime_box.insert("1.0", "The sandbox runs the saved binary for a bounded time and samples child processes and TCP metadata.\n"
                                "The output folder is writable from inside the sandbox; treat trace data as untrusted.\n"
                                "A related process event does not prove a static source-to-sink path executed.")

    def _latest_trace_job(self):
        root = self.current_folder / "RuntimeTraces" if self.current_folder else None
        jobs = sorted((path for path in root.iterdir() if path.is_dir()), reverse=True) if root and root.is_dir() else []
        return jobs[0] if jobs else None

    def _prepare_runtime(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        try:
            args = json.loads(self.trace_arguments.get())
            timeout = int(self.trace_timeout.get())
        except (ValueError, TypeError) as error:
            messagebox.showerror("CastorPollux", f"Enter a JSON argument array and numeric timeout: {error}")
            return
        def task():
            job = prepare_trace(self.current_folder, args, timeout)
            self._emit("runtime_prepared", str(job))
        self._start_task(task)

    def _launch_runtime(self):
        job = self._latest_trace_job()
        if not job:
            messagebox.showerror("CastorPollux", "Prepare a runtime trace job first.")
            return
        try:
            launch_trace(job)
            self.runtime_box.insert("end", f"\nSandbox launched: {job}\nClose the Sandbox after the trace finishes.")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _correlate_runtime(self):
        job = self._latest_trace_job()
        trace = job / "output" / "trace.json" if job else None
        if not trace or not trace.is_file():
            messagebox.showerror("CastorPollux", "No completed trace.json is available in the latest job.")
            return
        try:
            result = correlate_trace(self.current_folder, trace)
            self._render_timeline(result)
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _show_trace_timeline(self):
        job = self._latest_trace_job()
        path = job / "output" / "runtime-correlation.json" if job else None
        if not path or not path.is_file():
            messagebox.showerror("CastorPollux", "Correlate a completed trace first.")
            return
        self._render_timeline(json.loads(path.read_text(encoding="utf-8")))

    def _render_timeline(self, report):
        for child in self.timeline_links.winfo_children():
            child.destroy()
        self.runtime_box.delete("1.0", "end")
        self.runtime_box.insert("1.0", "UNTESTED WINDOWS SANDBOX FEATURE\n" +
                                report["limitations"] + "\n\n" +
                                f"{len(report.get('timeline', []))} timeline events\n")
        for event in report.get("timeline", []):
            label = f"{event['timestamp']}  {event['type']}  {len(event['candidate_citations'])} candidate citations"
            self._button(self.timeline_links, label,
                         lambda item=event: self._select_timeline_event(item), 540).pack(fill="x", pady=2)

    def _select_timeline_event(self, event):
        self.runtime_box.delete("1.0", "end")
        self.runtime_box.insert("1.0", "UNTESTED WINDOWS SANDBOX FEATURE\n\n" +
                                json.dumps(event["event"], indent=2) +
                                "\n\nSTATIC CANDIDATE LINKS (category match only)\n")
        for citation in event["candidate_citations"]:
            self._button(self.timeline_links, citation["location"],
                         lambda item=citation: self._jump_timeline_citation(item), 500).pack(fill="x", pady=2)

    def _jump_timeline_citation(self, citation):
        try:
            jump = evidence_jump(self.current_folder, citation)
            self.runtime_box.delete("1.0", "end")
            self.runtime_box.insert("1.0", "UNTESTED WINDOWS SANDBOX FEATURE\n"
                                    "A category match does not prove this procedure executed.\n\n" +
                                    citation["observation"] + "\n\n" + jump["code"] +
                                    "\n\nCROSS-REFERENCES\n" +
                                    "\n".join(json.dumps(item) for item in jump["xrefs"]))
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _unpack_page(self):
        self._label(self.body, "ARCHIVES  /  FIRMWARE CANDIDATES  /  NO EXECUTION", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "ZIP, TAR, GZIP, XZ and validated PE/ELF carving. Other firmware layouts may be missed.",
                    12, MUTED).pack(anchor="w", pady=(0, 12))
        for variable, title, action in ((self.unpack_source, "INPUT", self._browse_unpack_source),
                                        (self.unpack_output, "OUTPUT", self._browse_unpack_output)):
            row = ctk.CTkFrame(self.body, fg_color="transparent")
            row.pack(fill="x", pady=4)
            self._label(row, title, 11, CYAN, mono=True).pack(side="left", padx=(0, 8))
            ctk.CTkEntry(row, textvariable=variable, fg_color=FIELD, border_color=LINE,
                         text_color=TEXT).pack(side="left", fill="x", expand=True)
            self._button(row, "BROWSE", action, 100).pack(side="left", padx=(8, 0))
        self._button(self.body, "UNPACK AND IDENTIFY", self._run_unpack, 200, True).pack(anchor="w", pady=10)
        self.unpack_results = ctk.CTkScrollableFrame(self.body, fg_color=SIDEBAR)
        self.unpack_results.pack(fill="both", expand=True)

    def _browse_unpack_source(self):
        path = filedialog.askopenfilename(title="Choose archive or firmware image")
        if path:
            self.unpack_source.set(path)

    def _browse_unpack_output(self):
        path = filedialog.askdirectory(title="Choose empty unpack output folder")
        if path:
            self.unpack_output.set(path)

    def _run_unpack(self):
        def task():
            report = unpack_binary(Path(self.unpack_source.get()), Path(self.unpack_output.get()))
            self._emit("unpacked", report)
        self._start_task(task)

    def _similar_page(self):
        self._label(self.body, "REA PROCEDURE SIMILARITY  /  SAVED INVESTIGATIONS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Select a current procedure by name or address. Scores compare normalized pseudocode token shingles.",
                    12, MUTED, wraplength=760).pack(anchor="w", pady=(0, 12))
        self._label(self.body, str(self.current_folder or "No investigation selected"), 10, MUTED, mono=True).pack(anchor="w")
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=8)
        ctk.CTkEntry(row, textvariable=self.similarity_selector, placeholder_text="Function name or address",
                     fg_color=FIELD, text_color=TEXT).pack(side="left", fill="x", expand=True)
        ctk.CTkEntry(row, textvariable=self.similarity_minimum, width=75,
                     fg_color=FIELD, text_color=TEXT).pack(side="left", padx=8)
        self._button(row, "SEARCH", self._search_similar, 110, True).pack(side="left")
        self.similar_results = ctk.CTkScrollableFrame(self.body, fg_color=CARD)
        self.similar_results.pack(fill="both", expand=True)
        if self.current_folder:
            self._label(self.similar_results, f"{len(procedures(self.current_folder))} REA procedures in current investigation.",
                        11, MUTED).pack(anchor="w", pady=6)

    def _search_similar(self):
        try:
            minimum = float(self.similarity_minimum.get())
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        folder = self.current_folder
        selector = self.similarity_selector.get()
        investigations = [Path(item["path"]) for item in self.library.list()]
        def task():
            self._emit("similar", similar_functions(folder, selector, investigations, minimum))
        self._start_task(task)

    def _render_similar(self, rows):
        for child in self.similar_results.winfo_children():
            child.destroy()
        self._label(self.similar_results, f"{len(rows)} matches. Scores are approximate; inspect the code before inferring lineage.",
                    11, MUTED).pack(anchor="w", pady=7)
        for item in rows:
            label = f"{item['similarity']:.0%}  {item['name']} @ {item['address']}  |  {Path(item['folder']).name}"
            self._button(self.similar_results, label,
                         lambda row=item: self._show_similar(row), 700).pack(fill="x", pady=2)

    def _show_similar(self, row):
        self.current_folder = Path(row["folder"])
        self.search_category = "functions"
        self.search_text.set(row["address"])
        self.show_page("investigations")

    def _select_unpacked(self, path):
        self.input_path.set(str(path))
        self.show_page("analyze")

    def _bundles_page(self):
        self._label(self.body, "PORTABLE EVIDENCE  /  SHA-256 VERIFIED", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, str(self.current_folder or "Choose an investigation first"), 10, MUTED,
                    mono=True).pack(anchor="w", pady=(0, 12))
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=(0, 9))
        ctk.CTkEntry(row, textvariable=self.bundle_path, fg_color=FIELD, border_color=LINE,
                     text_color=TEXT, placeholder_text="Bundle ZIP path", height=38).pack(side="left", fill="x", expand=True)
        self._button(row, "CHOOSE ZIP", self._browse_bundle, 120).pack(side="left", padx=8)
        buttons = ctk.CTkFrame(self.body, fg_color="transparent")
        buttons.pack(fill="x", pady=(0, 10))
        self._button(buttons, "EXPORT CURRENT", self._export_bundle, 155, True).pack(side="left")
        self._button(buttons, "VERIFY ZIP", self._verify_bundle, 125).pack(side="left", padx=8)
        self._button(buttons, "IMPORT VERIFIED", self._import_bundle, 160).pack(side="left")
        self.bundle_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1,
                                          border_color=LINE, text_color=TEXT, font=self._font(12, mono=True))
        self.bundle_box.pack(fill="both", expand=True)
        self.bundle_box.insert("1.0", "Export includes the saved binary, reports, Ghidra project, logs, and manifest.\n"
                               "Verify compares every file hash before import. Choose a trusted destination for imported files.")

    def _browse_bundle(self):
        path = filedialog.askopenfilename(title="Choose CastorPollux bundle", filetypes=[("ZIP", "*.zip")])
        if path:
            self.bundle_path.set(path)

    def _export_bundle(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        path = filedialog.asksaveasfilename(title="Export investigation bundle", defaultextension=".zip",
                                            initialfile=self.current_folder.name + "-CastorPollux.zip",
                                            filetypes=[("ZIP", "*.zip")])
        if not path:
            return
        self.bundle_path.set(path)
        def task():
            self._emit("bundle_result", export_bundle(self.current_folder, Path(path)))
        self._start_task(task)

    def _verify_bundle(self):
        path = Path(self.bundle_path.get())
        def task():
            self._emit("bundle_result", verify_bundle(path))
        self._start_task(task)

    def _import_bundle(self):
        parent = filedialog.askdirectory(title="Choose a folder for the verified investigation")
        if not parent:
            return
        path = Path(self.bundle_path.get())
        def task():
            imported = import_bundle(path, Path(parent))
            self._emit("bundle_imported", str(imported))
        self._start_task(task)

    def _plugins_page(self):
        self._label(self.body, "DECLARATIVE RULES  /  REVIEW GUIDANCE  /  REPORT TEMPLATES", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Plugins are JSON files; they do not execute code. Enable a plugin in its JSON file, then reload.",
                    12, MUTED, wraplength=760).pack(anchor="w", pady=(0, 12))
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=(0, 10))
        self._button(row, "CREATE SAMPLE", self._create_plugin_sample, 155, True).pack(side="left")
        self._button(row, "VIEW EXAMPLE", self._view_plugin_sample, 155).pack(side="left", padx=8)
        self._button(row, "OPEN PLUGINS", self._open_plugin_folder, 150).pack(side="left", padx=8)
        self._button(row, "RELOAD", lambda: self.show_page("plugins"), 100).pack(side="left")
        self.plugin_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1,
                                          border_color=LINE, text_color=TEXT, font=self._font(12, mono=True))
        self.plugin_box.pack(fill="both", expand=True)
        try:
            plugins = load_plugins()
            self.plugin_box.insert("1.0", f"Folder: {plugin_dir()}\nEnabled plugins: {len(plugins)}\n\n" +
                                   "\n".join(f"{item['id']} v{item.get('version', '?')}\n  {item['path']}"
                                             for item in plugins))
        except Exception as error:
            self.plugin_box.insert("1.0", f"Plugin validation error: {error}")

    def _view_plugin_sample(self):
        from castorpollux_plugins import SAMPLE
        self.plugin_box.delete("1.0", "end")
        self.plugin_box.insert("1.0", "EXAMPLE PLUGIN — disabled until you choose to enable it.\n"
                               "Use CREATE SAMPLE to save an editable copy in your Plugins folder.\n\n" +
                               json.dumps(SAMPLE, indent=2))

    def _create_plugin_sample(self):
        try:
            os.startfile(create_sample())
            self.show_page("plugins")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _open_plugin_folder(self):
        plugin_dir().mkdir(parents=True, exist_ok=True)
        os.startfile(plugin_dir())

    def _coverage_page(self):
        self._label(self.body, "REA DECOMPILATION  /  EVERY PROCEDURE", 11, GREEN, mono=True).pack(
            anchor="w", pady=(0, 8))
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 8))
        self._button(controls, "CHOOSE INVESTIGATION", self._browse_coverage_folder, 185, True).pack(side="left")
        self._button(controls, "EXPORT CSV", self._export_coverage, 120).pack(side="right")
        self._button(controls, "SOURCE MAP", self._export_source_map, 130).pack(side="right", padx=8)
        self._button(controls, "CHECK ASM ↔ CODE", self._check_consistency, 165).pack(side="right", padx=8)
        self._button(controls, "IMPORT CRASH LOG", self._import_crash_log, 155).pack(side="right", padx=8)
        self.coverage_folder_label = self._label(self.body, str(self.current_folder or "No investigation selected"),
                                                  10, MUTED, mono=True, anchor="w")
        self.coverage_folder_label.pack(fill="x", pady=(0, 8))
        search = ctk.CTkFrame(self.body, fg_color="transparent")
        search.pack(fill="x", pady=(0, 9))
        field = ctk.CTkEntry(search, textvariable=self.coverage_search, placeholder_text="Search function, address, module, or error…",
                             fg_color=FIELD, border_color=LINE, text_color=TEXT, height=37)
        field.pack(side="left", fill="x", expand=True)
        field.bind("<KeyRelease>", lambda event: self._reset_coverage_page())
        ctk.CTkOptionMenu(search, variable=self.coverage_filter, values=["all", "ok", "failed", "pending"],
                          command=lambda _: self._reset_coverage_page(), width=125, fg_color=FIELD,
                          button_color=LINE, text_color=TEXT).pack(side="left", padx=(8, 0))
        self.coverage_summary = self._label(self.body, "", 11, CYAN, mono=True, anchor="w")
        self.coverage_summary.pack(fill="x", pady=(0, 8))
        page_row = ctk.CTkFrame(self.body, fg_color="transparent")
        page_row.pack(fill="x", pady=(0, 5))
        self._button(page_row, "PREVIOUS", lambda: self._step_coverage(-1), 105).pack(side="left")
        self.coverage_page_label = self._label(page_row, "", 10, MUTED, mono=True)
        self.coverage_page_label.pack(side="left", padx=12)
        self._button(page_row, "NEXT", lambda: self._step_coverage(1), 80).pack(side="left")
        panel = ctk.CTkFrame(self.body, fg_color="transparent")
        panel.pack(fill="both", expand=True)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_columnconfigure(1, weight=2)
        panel.grid_rowconfigure(0, weight=1)
        self.coverage_list = ctk.CTkScrollableFrame(panel, fg_color=CARD, border_width=1, border_color=LINE)
        self.coverage_list.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self.coverage_detail = ctk.CTkTextbox(panel, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                               text_color=TEXT, font=self._font(11, mono=True))
        self.coverage_detail.grid(row=0, column=1, sticky="nsew")
        self._render_coverage()

    def _browse_coverage_folder(self):
        folder = filedialog.askdirectory(title="Choose a CastorPollux investigation")
        if folder:
            try:
                read_manifest(Path(folder))
                self.current_folder = Path(folder)
                self.show_page("coverage")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _render_coverage(self):
        if self.page_name != "coverage":
            return
        for child in self.coverage_list.winfo_children():
            child.destroy()
        rows = coverage_rows(self.current_folder) if self.current_folder else []
        consistency = {}
        check_path = self.current_folder / "consistency-checks.json" if self.current_folder else None
        if check_path and check_path.is_file():
            try:
                consistency = {item["entry"].casefold().removeprefix("0x"): item for item in
                               json.loads(check_path.read_text(encoding="utf-8")).get("procedures", [])}
            except (OSError, ValueError, KeyError):
                pass
        counts = {"ok": sum(row["status"] == "ok" for row in rows),
                  "failed": sum(row["status"] not in ("ok", "pending") for row in rows),
                  "pending": sum(row["status"] == "pending" for row in rows)}
        self.coverage_summary.configure(text=f"{len(rows)} PROCEDURES    {counts['ok']} OK    "
                                             f"{counts['failed']} FAILED    {counts['pending']} PENDING")
        needle = self.coverage_search.get().strip().casefold()
        status = self.coverage_filter.get()
        filtered = []
        for row in rows:
            matched_status = status == "all" or row["status"] == status or \
                             (status == "failed" and row["status"] not in ("ok", "pending"))
            if not matched_status or (needle and needle not in " ".join(str(row[key]) for key in
                ("address", "name", "module", "section", "error")).casefold()):
                continue
            filtered.append(row)
        page_size = 150
        pages = max(1, (len(filtered) + page_size - 1) // page_size)
        self.coverage_page_index = min(self.coverage_page_index, pages - 1)
        self.coverage_page_label.configure(text=f"PAGE {self.coverage_page_index + 1}/{pages}  •  {len(filtered)} MATCH(ES)")
        for row in filtered[self.coverage_page_index * page_size:(self.coverage_page_index + 1) * page_size]:
            color = GREEN if row["status"] == "ok" else RED if row["status"] != "pending" else CYAN
            self._button(self.coverage_list,
                         f"{row['status'].upper():8} [{row['confidence'].upper()}] "
                         f"[{consistency.get(row['address'].casefold().removeprefix('0x'), {}).get('status', 'unchecked').upper()}] "
                         f"{row['name']} @ {row['address']}",
                         lambda item=row: self._show_coverage_row(item), 430).pack(fill="x", pady=2)
            self.coverage_list.winfo_children()[-1].configure(text_color=color, anchor="w")
        crash_path = self.current_folder / "crash-links.json" if self.current_folder else None
        if crash_path and crash_path.is_file():
            try:
                for link in json.loads(crash_path.read_text(encoding="utf-8")).get("links", [])[:30]:
                    self._button(self.coverage_list, f"CRASH {link['crash_address']} → {link['function']}",
                                 lambda item=link: self._show_crash_link(item), 430).pack(fill="x", pady=2)
            except (OSError, ValueError, KeyError):
                pass

    def _import_crash_log(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        path = filedialog.askopenfilename(title="Choose a crash log with absolute addresses")
        if path:
            try:
                result = link_crash_log(self.current_folder, Path(path))
                self._render_coverage()
                self.status_text.set(f"CRASH LOG: {len(result['links'])} ADDRESS LINK(S)")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _show_crash_link(self, link):
        row = next((row for row in coverage_rows(self.current_folder)
                    if int(row["address"], 16) == int(link["entry"], 16)), None)
        if row:
            self._show_coverage_row(row)
            self.coverage_detail.insert("1.0", f"Crash log address {link['crash_address']} (+{link['offset']} bytes). "
                                        "Address mapping only; verify image base and stack.\n\n")

    def _reset_coverage_page(self):
        self.coverage_page_index = 0
        self._render_coverage()

    def _step_coverage(self, direction):
        self.coverage_page_index = max(0, self.coverage_page_index + direction)
        self._render_coverage()

    def _show_coverage_row(self, row):
        detail = (f"{row['name']} @ {row['address']}\nStatus: {row['status']}\n"
                  f"Decompiler confidence: {row['confidence']} (heuristic)\n"
                  f"Why: {row['confidence_reason']}\n"
                  f"Module/namespace: {row['module']}\nSection: {row['section']}\n"
                  f"Source characters: {row['source_chars']}\n")
        if row["error"]:
            detail += f"Error: {row['error']}\n"
        check_path = self.current_folder / "consistency-checks.json" if self.current_folder else None
        if check_path and check_path.is_file():
            try:
                checks = json.loads(check_path.read_text(encoding="utf-8"))
                check = next((item for item in checks.get("procedures", [])
                              if item["entry"].casefold().removeprefix("0x") ==
                                 row["address"].casefold().removeprefix("0x")), None)
                if check:
                    detail += "\nAssembly cross-check: " + check["status"] + "\n"
                    detail += "\n".join(check["reasons"]) + "\n"
                    detail += "\n".join(check["assembly"]["sample"]) + "\n"
            except (OSError, ValueError, KeyError):
                pass
        detail += "\n" + (row["pseudocode"] or "No reconstructed code for this procedure.")
        self.coverage_detail.delete("1.0", "end")
        self.coverage_detail.insert("1.0", detail)

    def _check_consistency(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        folder = Path(self.current_folder)
        def task():
            result = check_consistency(folder)
            self._emit("log", f"Assembly cross-check: {result['summary']['review']} review lead(s), "
                              f"{result['summary']['unavailable']} unavailable.")
            self._emit("consistency", None)
        self._start_task(task)

    def _export_coverage(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        path = filedialog.asksaveasfilename(title="Export decompilation coverage", defaultextension=".csv",
                                            initialfile="decompilation-coverage.csv",
                                            filetypes=[("CSV files", "*.csv")])
        if path:
            try:
                export_coverage_csv(self.current_folder, Path(path))
                self.status_text.set("COVERAGE CSV SAVED")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _export_source_map(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        try:
            result = export_source_map(Path(self.current_folder))
            destination = filedialog.asksaveasfilename(title="Export reconstructed source map",
                defaultextension=".csv", initialfile="source-map.csv", filetypes=[("CSV files", "*.csv")])
            if destination:
                source = Path(self.current_folder) / "source-map.csv"
                if source.resolve() != Path(destination).resolve():
                    shutil.copyfile(source, destination)
                self.status_text.set(f"SOURCE MAP SAVED — {len(result['entries'])} PROCEDURES")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _select_investigation(self, folder):
        try:
            self.library.add(folder)
            self.current_folder = Path(folder)
            self.show_page("investigations")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _browse_investigation(self):
        folder = filedialog.askdirectory(title="Open a CastorPollux investigation")
        if folder:
            self._select_investigation(Path(folder))

    def _open_current_folder(self):
        if self.current_folder and self.current_folder.is_dir():
            os.startfile(self.current_folder)

    def _set_search_category(self, category):
        self.search_category = category
        self._search_results()

    def _schedule_search(self):
        if hasattr(self, "search_after"):
            self.after_cancel(self.search_after)
        self.search_after = self.after(250, self._search_results)

    def _search_results(self):
        if self.page_name != "investigations" or not hasattr(self, "rows_panel"):
            return
        self.search_serial += 1
        serial = self.search_serial
        folder, category, query = self.current_folder, self.search_category, self.search_text.get()
        if not folder:
            self._render_results([], category)
            return
        def worker():
            try:
                rows = search_pseudocode(folder, query, 150,
                                         "pseudocode.c" if category == "pseudocode" else "rea-pseudocode.c") \
                       if category in ("pseudocode", "rea code") else \
                       search_rows(folder, category, query, 150)
                self._emit("results", (serial, category, rows))
            except Exception as error:
                self._emit("log", f"Search failed: {error}")
        threading.Thread(target=worker, daemon=True).start()

    def _render_results(self, rows, category):
        if self.page_name != "investigations" or not self.rows_panel.winfo_exists():
            return
        for child in self.rows_panel.winfo_children():
            child.destroy()
        self._label(self.rows_panel, f"{len(rows)} RESULT(S)" + ("  •  first 150" if len(rows) == 150 else ""),
                    10, GREEN, mono=True).pack(anchor="w", padx=7, pady=(5, 8))
        columns = CATEGORIES[category][1:] if category in CATEGORIES else ("entry", "line", "text")
        for row in rows:
            title = "  ".join(str(row.get(col, "")) for col in columns)
            title = title.replace("\n", " ")[:95]
            ctk.CTkButton(self.rows_panel, text=title, height=30, anchor="w", corner_radius=5,
                          fg_color="transparent", hover_color=FIELD, text_color=TEXT,
                          font=self._font(11, mono=True),
                          command=lambda r=row, c=category: self._show_result(r, c)).pack(fill="x", pady=1)
        if not rows:
            self.detail_box.delete("1.0", "end")
            self.detail_box.insert("end", "No matching saved results. Enter a search term for pseudocode.")

    def _show_result(self, row, category):
        details = [f"{key}: {value}" for key, value in row.items()]
        entry = row.get("entry") if category in ("functions", "pseudocode", "rea code") else None
        if entry and self.current_folder:
            source_name = "pseudocode.c" if category == "pseudocode" else "rea-pseudocode.c"
            details += ["", "PSEUDOCODE", "=" * 60,
                        pseudocode_for(self.current_folder, entry, source_name=source_name)]
            incoming, outgoing = function_links(self.current_folder, entry)
            details += ["", f"INCOMING CALLS ({len(incoming)})"]
            details += [f"{r['caller_name']} @ {r['caller_entry']}" for r in incoming[:100]]
            details += ["", f"OUTGOING CALLS ({len(outgoing)})"]
            details += [f"{r['callee_name']} @ {r['callee_entry']}" for r in outgoing[:100]]
        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("end", "\n".join(details))

    def _queries_page(self):
        self._label(self.body, "SNAPSHOT-ASSISTED  /  REA ACTIONS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Choose an action below. CastorPollux builds the REA command and reuses the saved snapshot.",
                    14, MUTED).pack(anchor="w", pady=(0, 16))
        card = self._card(self.body)
        card.pack(fill="x", pady=(0, 13))
        self._label(card, "INVESTIGATION", 11, CYAN, "bold", True).pack(anchor="w", padx=19, pady=(16, 5))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=19)
        self.query_folder = ctk.StringVar(value=str(self.current_folder or ""))
        ctk.CTkEntry(row, textvariable=self.query_folder, height=38, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT).pack(side="left", fill="x", expand=True)
        self._button(row, "BROWSE", self._browse_query_folder, 100).pack(side="left", padx=(8, 0))
        self._label(card, "SEARCH TEXT / FUNCTION / ADDRESS", 11, CYAN, "bold", True).pack(anchor="w", padx=19, pady=(17, 5))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=19, pady=(0, 17))
        ctk.CTkEntry(row, textvariable=self.rea_query_text, height=38, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT,
                     placeholder_text="Leave empty for Overview; other actions use this value").pack(side="left", fill="x", expand=True)
        self.query_buttons = []
        for actions in ((("OVERVIEW", "inspect"), ("FIND STRINGS", "search_strings"),
                         ("FIND FUNCTIONS", "search_procedures"), ("FUNCTION", "function")),
                        (("DECOMPILE", "decompile"), ("INSTRUCTIONS", "instructions"),
                         ("XREFS", "xrefs"), ("TRACE", "trace"))):
            action_row = ctk.CTkFrame(self.body, fg_color="transparent")
            action_row.pack(fill="x", pady=(0, 6))
            for label, operation in actions:
                button = self._button(action_row, label, lambda op=operation: self._run_query(op), 142,
                                      operation == "decompile")
                button.pack(side="left", padx=(0, 7))
                self.query_buttons.append(button)
        self.query_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                        text_color=TEXT, font=self._font(11, mono=True))
        self.query_box.pack(fill="both", expand=True)
        self.query_box.insert("end", "Query results are saved in the investigation's rea-queries folder.\n"
                                       "A matching REA snapshot is reused when available.")

    def _browse_query_folder(self):
        folder = filedialog.askdirectory(title="Choose a saved investigation")
        if folder:
            try:
                self.library.add(Path(folder))
                self.current_folder = Path(folder)
                self.query_folder.set(folder)
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _run_query(self, operation="inspect"):
        folder = Path(self.query_folder.get())
        value = self.rea_query_text.get().strip()
        try:
            read_manifest(folder)
            if operation != "inspect" and not value:
                raise ValueError("Enter a search term, function name, or address")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            path = run_rea_query(self.store, folder, operation, value,
                                 lambda m: self._emit("log", m), self.cancel_event.is_set, self._set_process)
            self._emit("rea_query", str(path))
        self._start_task(task)

    def _libraries_page(self):
        self._label(self.body, "LIBRARY SIGNATURES  /  CVE LEADS  /  DLL INVENTORY", 11, GREEN,
                    mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Binary markers are leads. Confirm that matching library code is actually included and reachable.",
                    13, MUTED).pack(anchor="w", pady=(0, 10))
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=(0, 10))
        self._button(row, "CHOOSE INVESTIGATION", self._browse_libraries_folder, 190).pack(side="left", padx=(0, 8))
        self._button(row, "RESCAN LOCAL", self._rescan_libraries, 145).pack(side="left")
        self._button(row, "CHECK KNOWN CVEs", self._lookup_libraries, 175, True).pack(side="left", padx=8)
        self._button(row, "OFFLINE CACHE", lambda: self._lookup_libraries(True), 135).pack(side="left")
        self._button(row, "DLL INVENTORY", self._rescan_dlls, 130).pack(side="left", padx=8)
        rule_row = ctk.CTkFrame(self.body, fg_color="transparent")
        rule_row.pack(fill="x", pady=(0, 8))
        self._button(rule_row, "EDIT BUILD RULES", self._edit_advisory_rules, 160).pack(side="left")
        self._button(rule_row, "CHECK APPLICABILITY", self._recheck_applicability, 180).pack(side="left", padx=8)
        self._button(rule_row, "IMPORT SBOM", self._import_sbom, 135).pack(side="left", padx=8)
        self._label(self.body, "Online lookup contacts NVD. Offline cache can be stale; both are advisory leads.",
                    11, MUTED).pack(anchor="w", pady=(0, 8))
        self.libraries_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1,
                                            border_color=LINE, text_color=TEXT, font=self._font(12, mono=True))
        self.libraries_box.pack(fill="both", expand=True)
        self._render_libraries()

    def _render_libraries(self):
        if self.page_name != "libraries":
            return
        lines = [f"Investigation: {self.current_folder or 'none'}", ""]
        folder = self.current_folder
        if folder:
            for filename in ("binary-profile.json", "embedded-libraries.json", "known-vulnerabilities.json",
                             "cve-reachability.json", "advisory-applicability.json", "dll-signatures.json",
                             "sbom-comparison.json"):
                path = folder / filename
                if path.is_file():
                    try:
                        data = json.loads(path.read_text(encoding="utf-8"))
                        lines += [filename.upper(), json.dumps(data, indent=2), ""]
                    except (OSError, ValueError) as error:
                        lines += [f"{filename}: {error}"]
        self.libraries_box.delete("1.0", "end")
        self.libraries_box.insert("1.0", "\n".join(lines))

    def _import_sbom(self):
        try:
            if not self.current_folder:
                raise ValueError("Choose an investigation first")
            read_manifest(self.current_folder)
            source = filedialog.askopenfilename(title="Choose CycloneDX or SPDX JSON SBOM",
                                                filetypes=[("JSON SBOM", "*.json"), ("All files", "*.*")])
            if not source:
                return
            folder = Path(self.current_folder)
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            report = compare_sbom(folder, Path(source))
            self._emit("log", f"SBOM comparison: {len(report['detected_libraries'])} local library lead(s), "
                              f"{report['component_count']} declared component(s).")
            self._emit("libraries", None)
        self._start_task(task)

    def _browse_libraries_folder(self):
        folder = filedialog.askdirectory(title="Choose a saved CastorPollux investigation")
        if folder:
            try:
                self.library.add(Path(folder))
                self.current_folder = Path(folder)
                self._render_libraries()
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _rescan_libraries(self):
        try:
            folder = Path(self.current_folder)
            manifest = read_manifest(folder)
            binary = folder / manifest["saved_binary"]
            if not binary.is_file():
                raise ValueError("Saved binary is missing")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            result = scan_embedded_libraries(binary, folder)
            if (folder / "SBOM" / "imported.json").is_file():
                compare_sbom(folder)
            try:
                summary = json.loads((folder / "ghidra-summary.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                summary = None
            manifest["binary_profile"] = detect_binary_profile(binary, summary)
            (folder / "binary-profile.json").write_text(json.dumps(manifest["binary_profile"], indent=2),
                                                          encoding="utf-8")
            manifest["embedded_library_candidates"] = len(result["libraries"])
            (folder / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self._emit("log", f"Library scan found {len(result['libraries'])} signature candidate(s).")
            self._emit("libraries", None)
        self._start_task(task)

    def _lookup_libraries(self, offline=False):
        try:
            folder = Path(self.current_folder)
            read_manifest(folder)
            if not (folder / "embedded-libraries.json").is_file():
                raise ValueError("Run the local library scan first")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            result = check_known_vulnerabilities(folder, offline=offline)
            reach = cve_reachability(folder)
            try:
                manifest = read_manifest(folder)
                applicability = evaluate_applicability(folder, folder / manifest["saved_binary"])
                self._emit("log", f"Build rules evaluated {len(applicability['results'])} CVE lead(s).")
            except Exception as error:
                self._emit("log", f"Build-rule check unavailable: {error}")
            self._emit("log", f"{'Offline cache' if offline else 'NVD'} checked {len(result['results'])} library version(s); "
                              f"{len(reach['results'])} advisory reachability lead(s).")
            self._emit("libraries", None)
        self._start_task(task)

    def _edit_advisory_rules(self):
        try:
            os.startfile(ensure_advisory_rules())
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _recheck_applicability(self):
        try:
            folder = Path(self.current_folder)
            manifest = read_manifest(folder)
            binary = folder / manifest["saved_binary"]
            if not (folder / "known-vulnerabilities.json").is_file():
                raise ValueError("Check known CVEs or the offline cache first")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            result = evaluate_applicability(folder, binary)
            self._emit("log", f"Build rules evaluated {len(result['results'])} CVE lead(s); "
                              f"{result['active_rules']} enabled rule(s).")
            self._emit("libraries", None)
        self._start_task(task)

    def _rescan_dlls(self):
        try:
            folder = Path(self.current_folder)
            manifest = read_manifest(folder)
            original = Path(manifest.get("input_path", ""))
            binary = original if original.is_file() and sha256(original) == manifest.get("sha256") else folder / manifest["saved_binary"]
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            result = dll_signature_inventory(folder, binary)
            self._emit("log", f"Inspected {len(result['dlls'])} imported DLL name(s).")
            self._emit("libraries", None)
        self._start_task(task)

    def _console_page(self):
        self._label(self.body, "FULL REA CLI  /  LOCAL COMMANDS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Run any REA subcommand. Enter arguments as a JSON array; no shell is involved.",
                    13, MUTED).pack(anchor="w", pady=(0, 12))
        card = self._card(self.body)
        card.pack(fill="x", pady=(0, 8))
        self._label(card, "SAVED INVESTIGATION", 11, CYAN, "bold", True).pack(anchor="w", padx=17, pady=(15, 5))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=17)
        self.console_folder = ctk.StringVar(value=str(self.current_folder or ""))
        ctk.CTkEntry(row, textvariable=self.console_folder, height=37, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT).pack(side="left", fill="x", expand=True)
        self._button(row, "BROWSE", self._browse_console_folder, 100).pack(side="left", padx=(8, 0))
        self._label(card, "REA ARGUMENTS", 11, CYAN, "bold", True).pack(anchor="w", padx=17, pady=(14, 5))
        ctk.CTkEntry(card, textvariable=self.rea_console_args, height=37, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT, font=self._font(12, mono=True)).pack(
            fill="x", padx=17, pady=(0, 8))
        self._label(card, 'Examples: ["--help"]   ["decompile", "{binary}", "--procedure=0x1000", "--provider", "ghidra", "--format", "json", "--snapshot", "{snapshot}"]',
                    10, MUTED, mono=True).pack(anchor="w", padx=17, pady=(0, 15))
        buttons = ctk.CTkFrame(self.body, fg_color="transparent")
        buttons.pack(fill="x", pady=(0, 10))
        self.console_button = self._button(buttons, ">_  RUN REA", self._run_console, 155, True)
        self.console_button.pack(side="left")
        self._button(buttons, "■  CANCEL", self._cancel, 100).pack(side="left", padx=8)
        self._button(buttons, "SHOW COMMANDS", lambda: self.rea_console_args.set('["--help"]'), 150).pack(side="left")
        self.console_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                           text_color=TEXT, font=self._font(11, mono=True))
        self.console_box.pack(fill="both", expand=True, pady=(5, 0))
        self.console_box.insert("end", "Use {binary} for the saved target and {snapshot} for its REA snapshot.\n"
                                         "Some REA commands can launch targets or change data; inspect the command before running it.")

    def _browse_console_folder(self):
        folder = filedialog.askdirectory(title="Choose a saved investigation")
        if folder:
            try:
                self.library.add(Path(folder))
                self.current_folder = Path(folder)
                self.console_folder.set(folder)
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _run_console(self):
        folder = Path(self.console_folder.get())
        try:
            arguments = json.loads(self.rea_console_args.get())
            read_manifest(folder)
        except Exception as error:
            messagebox.showerror("CastorPollux", "Enter a saved investigation and JSON argument array. " + str(error))
            return
        def task():
            path = run_rea_command(self.store, folder, arguments,
                                   lambda m: self._emit("log", m), self.cancel_event.is_set, self._set_process)
            self._emit("rea_console", str(path))
        self._start_task(task)

    def _compare_page(self):
        self._label(self.body, "BINARY DIFF  /  SAVED INVESTIGATIONS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Compare function pseudocode, strings, imports, and call edges.",
                    14, MUTED).pack(anchor="w", pady=(0, 18))
        if self.current_folder and not self.compare_left.get():
            self.compare_left.set(str(self.current_folder))
        card = self._card(self.body)
        card.pack(fill="x", pady=(0, 15))
        for number, title, variable in (("01", "OLDER BUILD", self.compare_left),
                                         ("02", "NEWER BUILD", self.compare_right)):
            self._label(card, number + "   " + title, 11, CYAN, "bold", True).pack(anchor="w", padx=20, pady=(17, 6))
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=(0, 6))
            ctk.CTkEntry(row, textvariable=variable, height=39, fg_color=FIELD,
                         border_color=LINE, text_color=TEXT).pack(side="left", fill="x", expand=True)
            self._button(row, "BROWSE", lambda v=variable: self._browse_compare(v), 100).pack(side="left", padx=(8, 0))
        ctk.CTkFrame(card, height=10, fg_color="transparent").pack()
        compare_actions = ctk.CTkFrame(self.body, fg_color="transparent")
        compare_actions.pack(fill="x", pady=(0, 14))
        self.compare_button = self._button(compare_actions, "◇  COMPARE BUILDS", self._run_compare, 180, True)
        self.compare_button.pack(side="left")
        self._button(compare_actions, "BLOCK MAP", self._open_block_map, 145).pack(side="left", padx=8)
        self._button(compare_actions, "TYPE MAP", self._open_type_map, 130).pack(side="left")
        self._button(compare_actions, "PATCH CHECKLIST", self._open_patch_checklist, 165).pack(side="left", padx=8)
        self.compare_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                           text_color=TEXT, font=self._font(12, mono=True))
        self.compare_box.pack(fill="both", expand=True)
        self.compare_box.insert("end", "Choose two saved investigations. The report destination is selected when you run the comparison.")

    def _open_type_map(self):
        path = self.compare_destination / "type-signature-diff.json" if self.compare_destination else None
        if not path or not path.is_file():
            messagebox.showerror("CastorPollux", "Run Compare Builds first, then open its type map.")
            return
        changes = json.loads(path.read_text(encoding="utf-8")).get("changes", [])
        window = ctk.CTkToplevel(self)
        window.title("CastorPollux | Inferred type signatures")
        window.geometry("1050x720")
        self._label(window, "INFERRED TYPE SIGNATURES  /  OLDER → NEWER", 12, GREEN,
                    "bold", True).pack(anchor="w", padx=15, pady=(14, 7))
        self._label(window, "Decompiler types can change without an ABI change. Click a pair for details.",
                    11, MUTED).pack(anchor="w", padx=15)
        canvas = tk.Canvas(window, bg=SIDEBAR, height=440, highlightbackground=LINE)
        bar = tk.Scrollbar(window, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=bar.set)
        canvas.pack(side="top", fill="both", expand=True, padx=15, pady=8)
        bar.place(relx=0.975, rely=0.11, relheight=0.62)
        detail = ctk.CTkTextbox(window, fg_color=SIDEBAR, text_color=TEXT,
                                font=self._font(11, mono=True), height=150)
        detail.pack(fill="x", padx=15, pady=(0, 15))
        if not changes:
            detail.insert("1.0", "No inferred type-signature changes in matched functions.")
        for index, change in enumerate(changes[:200]):
            y = 30 + index * 45
            tag = f"type-{index}"
            color = RED if change.get("arity_changed") else CYAN
            canvas.create_rectangle(15, y-17, 470, y+17, fill=FIELD, outline=color, width=2, tags=tag)
            canvas.create_rectangle(580, y-17, 1030, y+17, fill=FIELD, outline=color, width=2, tags=tag)
            canvas.create_line(470, y, 580, y, fill=color, width=2, arrow=tk.LAST, tags=tag)
            canvas.create_text(25, y, anchor="w", fill=TEXT, text=change["before"]["raw"][:65],
                               font=self._tk_font(10, mono=True), tags=tag)
            canvas.create_text(590, y, anchor="w", fill=TEXT, text=change["after"]["raw"][:65],
                               font=self._tk_font(10, mono=True, bold=True), tags=tag)
            canvas.tag_bind(tag, "<Button-1>", lambda event, item=change: (
                detail.delete("1.0", "end"), detail.insert("1.0", json.dumps(item, indent=2))))
        canvas.configure(scrollregion=(0, 0, 1050, max(450, len(changes[:200]) * 45 + 50)))
        canvas.bind("<MouseWheel>", lambda event: canvas.yview_scroll(-int(event.delta/120), "units"))

    def _open_patch_checklist(self):
        path = self.compare_destination / "patch-verification.json" if self.compare_destination else None
        if not path or not path.is_file():
            messagebox.showinfo("CastorPollux", "Compare two builds first to generate a patch checklist.")
            return
        self._show_text("Patch verification checklist", path.read_text(encoding="utf-8"))

    def _open_block_map(self):
        path = self.compare_destination / "basic-block-diff.json" if self.compare_destination else None
        if not path or not path.is_file():
            messagebox.showerror("CastorPollux", "Run Compare Builds first, then open its block map.")
            return
        try:
            procedures = json.loads(path.read_text(encoding="utf-8"))["procedures"]
            if not procedures:
                raise ValueError("No matched function pairs have block data")
        except (OSError, ValueError, KeyError) as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        window = ctk.CTkToplevel(self)
        window.title("CastorPollux | Basic-block diff")
        window.geometry("1130x790")
        window.lift()
        self._label(window, "BASIC-BLOCK DIFF  /  APPROXIMATE INSTRUCTION MAP", 12, GREEN,
                    "bold", True).pack(anchor="w", padx=16, pady=(14, 3))
        self._label(window, "Green: unchanged · red: changed/removed · cyan: added. Click a block for instructions.",
                    11, MUTED).pack(anchor="w", padx=16, pady=(0, 8))
        labels = [f"{index+1}. {item['name']} @ {item['old_entry']} → {item['new_entry']}"
                  for index, item in enumerate(procedures)]
        selection = ctk.StringVar(value=labels[0])
        picker = ctk.CTkOptionMenu(window, values=labels, variable=selection, width=770,
                                   fg_color=FIELD, button_color=LINE, text_color=TEXT)
        picker.pack(anchor="w", padx=16, pady=(0, 8))
        panel = ctk.CTkFrame(window, fg_color="transparent")
        panel.pack(fill="both", expand=True, padx=16)
        canvas = tk.Canvas(panel, bg=SIDEBAR, highlightthickness=1, highlightbackground=LINE,
                           height=440)
        scrollbar = tk.Scrollbar(panel, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        detail = ctk.CTkTextbox(window, fg_color=SIDEBAR, text_color=TEXT,
                                font=self._font(11, mono=True), height=165)
        detail.pack(fill="x", padx=16, pady=(8, 15))

        def draw(*_):
            item = procedures[labels.index(selection.get())]
            canvas.delete("all")
            old_blocks, new_blocks = item["old_blocks"], item["new_blocks"]
            matched_old = {match["old_index"]: match for match in item["matches"]}
            matched_new = {match["new_index"]: match for match in item["matches"]}
            canvas.create_text(230, 17, text="OLDER BUILD", fill=CYAN, font=self._tk_font(11, bold=True))
            canvas.create_text(800, 17, text="NEWER BUILD", fill=CYAN, font=self._tk_font(11, bold=True))
            for match in item["matches"]:
                color = GREEN if match["status"] == "unchanged" else RED
                canvas.create_line(420, 50 + match["old_index"] * 42,
                                   610, 50 + match["new_index"] * 42, fill=color, width=2)
            for side, blocks, matches, x in (("old", old_blocks, matched_old, 38),
                                             ("new", new_blocks, matched_new, 610)):
                for index, block in enumerate(blocks):
                    match = matches.get(index)
                    status = match["status"] if match else "removed" if side == "old" else "added"
                    color = GREEN if status == "unchanged" else RED if status in {"changed", "removed"} else CYAN
                    y = 50 + index * 42
                    tag = f"{side}-{index}"
                    canvas.create_rectangle(x, y-15, x+382, y+15, fill=FIELD, outline=color,
                                            width=2, tags=tag)
                    canvas.create_text(x+191, y, text=f"{status.upper():9} {block['entry']}  "
                                        f"{block['instruction_count']} instruction(s)", fill=TEXT,
                                        font=self._tk_font(10, mono=True, bold=True), tags=tag)
                    canvas.tag_bind(tag, "<Button-1>",
                                    lambda event, b=block, s=side, state=status: show_block(b, s, state))
            canvas.configure(scrollregion=(0, 0, 1050, 75 + max(len(old_blocks), len(new_blocks)) * 42))
            detail.delete("1.0", "end")
            detail.insert("1.0", f"{item['name']}\n{item['counts']}\n\n"
                          "Select a block. Address shifts and compiler optimizations can change this heuristic map.")

        def show_block(block, side, status):
            detail.delete("1.0", "end")
            detail.insert("1.0", f"{side.upper()}  {status.upper()}  {block['entry']}–{block['end']}\n\n" +
                          "\n".join(block["instructions"]))

        picker.configure(command=draw)
        canvas.bind("<MouseWheel>", lambda event: canvas.yview_scroll(-int(event.delta/120), "units"))
        draw()

    def _browse_compare(self, variable):
        folder = filedialog.askdirectory(title="Choose a saved CastorPollux investigation")
        if folder:
            try:
                read_manifest(Path(folder))
                variable.set(folder)
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _run_compare(self):
        left, right = Path(self.compare_left.get()), Path(self.compare_right.get())
        try:
            read_manifest(left)
            read_manifest(right)
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        destination = filedialog.askdirectory(title="Choose a folder for the comparison report")
        if not destination:
            return
        def task():
            result = compare_investigations(left, right, Path(destination))
            checklist = patch_checklist(Path(destination), result)
            self._emit("log", f"Patch verification checklist: {len(checklist['items'])} changed function(s).")
            self._emit("comparison", (result, destination))
        self._start_task(task)

    def _lab_page(self):
        folder = self.current_folder
        self._label(self.body, "INDEXED SOURCE  /  DECOMPILER DIFFERENCES  /  LINKED DISASSEMBLY", 11,
                    GREEN, "bold", True).pack(anchor="w", pady=(0, 7))
        self._label(self.body, str(folder or "Choose an investigation in History"), 10, MUTED,
                    mono=True).pack(anchor="w", pady=(0, 12))
        if not folder or not (folder / "rea-pseudocode.c").is_file():
            self._label(self.body, "This view needs saved REA pseudocode.", 13, MUTED).pack(anchor="w")
            return
        tools = ctk.CTkFrame(self.body, fg_color="transparent")
        tools.pack(fill="x", pady=(0, 12))
        self._button(tools, "INDEX SOURCE", self._lab_index, 135).pack(side="left")
        self._button(tools, "CALIBRATION", self._lab_calibration, 140).pack(side="left", padx=7)
        self._button(tools, "DIAGNOSTIC PREVIEW", lambda: self._show_diagnostics(folder), 190).pack(side="left")
        self._button(tools, "RECOVERY HISTORY", lambda: self._show_recovery(folder), 170).pack(side="left", padx=7)
        self._button(tools, "SAVE LAYOUT", self._save_current_layout, 135).pack(side="right")
        search = ctk.CTkFrame(self.body, fg_color="transparent")
        search.pack(fill="x", pady=(0, 10))
        ctk.CTkEntry(search, textvariable=self.lab_query, placeholder_text="Search indexed REA pseudocode",
                     fg_color=FIELD, text_color=TEXT, font=self._font(12)).pack(side="left", fill="x", expand=True)
        self._button(search, "SEARCH", self._lab_search, 110).pack(side="left", padx=(8, 0))
        self.lab_results = ctk.CTkTextbox(self.body, height=100, fg_color=SIDEBAR, text_color=TEXT,
                                           font=self._font(11, mono=True))
        self.lab_results.pack(fill="x", pady=(0, 12))
        locator = ctk.CTkFrame(self.body, fg_color="transparent")
        locator.pack(fill="x", pady=(0, 8))
        self._label(locator, "SOURCE LINE", 10, CYAN, "bold").pack(side="left")
        ctk.CTkEntry(locator, textvariable=self.lab_line, width=90, fg_color=FIELD,
                     text_color=TEXT).pack(side="left", padx=7)
        self._button(locator, "MAP TO BINARY", self._lab_map_line, 150).pack(side="left")
        rows = coverage_rows(folder)
        self.lab_rows = rows
        self._label(self.body, "SYNCHRONIZED PROCEDURE VIEW  •  source lines map to procedure entry unless an exact marker exists",
                    11, CYAN, "bold").pack(anchor="w", pady=(0, 5))
        options = [f"{row['name']} @ {row['address']}" for row in rows[:5000]]
        if options:
            if self.lab_function.get() not in options:
                self.lab_function.set(options[0])
            ctk.CTkOptionMenu(self.body, variable=self.lab_function, values=options,
                              command=lambda _value: self._lab_show_function(), width=550,
                              fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(anchor="w", pady=(0, 8))
        pane_frames = self._split_frame(self.body, height=355)
        for panel, (title, attribute) in zip(pane_frames,
            (("REA PSEUDOCODE", "lab_source"), ("BINARY DISASSEMBLY", "lab_assembly"))):
            self._label(panel, title, 10, CYAN, "bold").pack(anchor="w")
            box = ctk.CTkTextbox(panel, height=300, fg_color=SIDEBAR, text_color=TEXT,
                                 font=self._font(10, mono=True))
            box.pack(fill="both", expand=True)
            setattr(self, attribute, box)
        self._lab_show_function()
        heat = disagreement_heatmap(folder)[:30]
        self._label(self.body, "DECOMPILER DISAGREEMENT HEATMAP  •  token overlap heuristic", 11,
                    CYAN, "bold").pack(anchor="w", pady=(5, 6))
        for item in heat:
            line = ctk.CTkFrame(self.body, fg_color="transparent")
            line.pack(fill="x", pady=2)
            self._label(line, f"{item['name'][:34]:34} {item['label']}", 10, TEXT, mono=True,
                        width=450, anchor="w").pack(side="left")
            bar = ctk.CTkProgressBar(line, width=300, progress_color=RED if item["score"] > .7 else CYAN)
            bar.pack(side="left", padx=8)
            bar.set(item["score"])
            self._label(line, f"{item['score']:.0%}", 10, MUTED, mono=True).pack(side="left")
        self._label(self.body, "COVERAGE-GUIDED REVIEW PRIORITY  •  inspect missing or low-confidence procedures first",
                    11, CYAN, "bold").pack(anchor="w", pady=(15, 5))
        for item in review_priority(folder)[:20]:
            self._label(self.body, f"{item['score']:2}  {item['name']} @ {item['address']}  "
                        f"{item['status']} / {item['confidence']}  {', '.join(item['signals'])}",
                        10, RED if item["status"] != "ok" else MUTED, mono=True).pack(anchor="w", pady=2)

    def _lab_show_function(self):
        if not getattr(self, "lab_rows", None):
            return
        selected = self.lab_function.get()
        row = next((item for item in self.lab_rows if selected == f"{item['name']} @ {item['address']}"), None)
        if not row:
            return
        self.lab_source.delete("1.0", "end")
        self.lab_source.insert("1.0", row["pseudocode"] or "No REA source for this procedure.")
        address = int(row["address"], 16)
        higher = [int(item["address"], 16) for item in self.lab_rows if int(item["address"], 16) > address]
        end = min(higher) if higher else address + 4096
        disassembly = self.current_folder / "disassembly.txt"
        instructions = []
        if disassembly.is_file():
            with disassembly.open("r", encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    match = re.match(r"^([0-9A-Fa-f]+)\s", line)
                    if match and address <= int(match.group(1), 16) < end:
                        instructions.append(line)
                        if len(instructions) >= 2000:
                            break
        self.lab_assembly.delete("1.0", "end")
        self.lab_assembly.insert("1.0", "".join(instructions) or "No matching disassembly in saved export.")

    def _lab_index(self):
        try:
            item = build_source_index(self.current_folder)
            self.lab_results.delete("1.0", "end")
            self.lab_results.insert("1.0", f"Indexed {item['lines']} source lines; SHA-256 {item['sha256']}")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _lab_search(self):
        try:
            rows = search_index(self.current_folder, self.lab_query.get(), 100)
            self.lab_results.delete("1.0", "end")
            self.lab_results.insert("1.0", "\n".join(f"line {row['line']} @ {row['address']} (procedure entry): {row['text']}"
                                                        for row in rows) or "No matches.")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _lab_map_line(self):
        try:
            result = line_address(self.current_folder, int(self.lab_line.get()))
            self.lab_results.delete("1.0", "end")
            self.lab_results.insert("1.0", json.dumps(result, indent=2))
            row = next((row for row in self.lab_rows if row["address"].casefold() == result["address"].casefold()), None)
            if row:
                self.lab_function.set(f"{row['name']} @ {row['address']}")
                self._lab_show_function()
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _lab_calibration(self):
        try:
            value = confidence_calibration(Path(self.corpus_path.get()),
                                           [Path(item["path"]) for item in self.library.list()])
            self._show_text("Corpus confidence calibration", json.dumps(value, indent=2))
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _show_text(self, title, value):
        window = ctk.CTkToplevel(self)
        window.title("CastorPollux | " + title)
        window.geometry("920x670")
        box = ctk.CTkTextbox(window, fg_color=SIDEBAR, text_color=TEXT, font=self._font(11, mono=True))
        box.pack(fill="both", expand=True, padx=12, pady=12)
        box.insert("1.0", value)

    def _show_diagnostics(self, folder):
        try:
            self._show_text("Redacted diagnostic preview", diagnostic_preview(folder).read_text(encoding="utf-8"))
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _show_recovery(self, folder):
        attempts = recovery_comparison(folder)
        lines = []
        for item in attempts:
            before, after = set(item.get("before", [])), set(item.get("after", []))
            lines.extend((f"ATTEMPT {item['sequence']}  •  {item.get('started_at', '')}  •  {item.get('status', '?')}",
                          "Resolved: " + ("; ".join(sorted(before - after)) or "none"),
                          "Remaining: " + ("; ".join(sorted(after)) or "none"),
                          "New failures: " + ("; ".join(sorted(after - before)) or "none"),
                          "Agent decision: " + str(item.get("decision", {}).get("reason", "not available")),
                          "Saved record: RecoveryAttempts/" + str(item.get("record", "")), ""))
        self._show_text("Recovery attempt comparison", "\n".join(lines) if lines else
                        "No recovery attempts saved for this investigation.")

    def _advanced_page(self):
        self._label(self.body, "GRAPH LAB  /  SSA · DISPATCH · COVERAGE · SUPPLY CHAIN", 11, GREEN,
                    "bold", True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Click evidence nodes for saved addresses. Candidate edges remain marked by confidence.",
                    12, MUTED).pack(anchor="w", pady=(0, 10))
        toolbar = ctk.CTkFrame(self.body, fg_color="transparent")
        toolbar.pack(fill="x", pady=(0, 10))
        for title, action in (("CHOOSE INVESTIGATION", self._advanced_choose),
                              ("REBUILD GRAPH", self._advanced_rebuild),
                              ("SCAN OVERFLOWS", self._advanced_overflows),
                              ("IMPORT VEX", lambda: self._advanced_import("vex")),
                              ("IMPORT FUZZ HITS", lambda: self._advanced_import("fuzz"))):
            self._button(toolbar, title, action, 160).pack(side="left", padx=(0, 7))
        pin = ctk.CTkFrame(self.body, fg_color="transparent")
        pin.pack(fill="x", pady=(0, 8))
        self._label(pin, "TRUSTED SBOM SHA-256", 10, CYAN, "bold", True).pack(side="left", padx=(0, 9))
        ctk.CTkEntry(pin, textvariable=self.sbom_pin, height=34, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT).pack(side="left", fill="x", expand=True)
        self._button(pin, "VERIFY BY DIGEST", self._advanced_verify, 160).pack(side="left", padx=(7, 0))
        replay = ctk.CTkFrame(self.body, fg_color="transparent")
        replay.pack(fill="x", pady=(0, 8))
        self._label(replay, "OVERFLOW LEAD #", 10, CYAN, "bold", True).pack(side="left", padx=(0, 8))
        ctk.CTkEntry(replay, textvariable=self.overflow_lead_index, width=70, height=32,
                     fg_color=FIELD, border_color=LINE, text_color=TEXT).pack(side="left")
        self._button(replay, "CREATE BOUNDARY INPUTS", self._advanced_boundary, 205).pack(side="left", padx=8)
        self._label(replay, "Generated inputs are unverified; Sandbox status: UNTESTED", 10, MUTED).pack(side="left")
        self._label(self.body, str(self.current_folder or "Choose an investigation"), 10, MUTED,
                    mono=True).pack(anchor="w", pady=(0, 10))
        views = ["SSA flow", "SSA leads", "Aliases", "Virtual calls", "Jump tables", "Edge checks",
                 "Fuzz overlay", "Overflow leads", "VEX", "SBOM provenance"]
        tabs = ctk.CTkFrame(self.body, fg_color="transparent")
        tabs.pack(fill="x", pady=(0, 10))
        self.advanced_tabs = {}
        for index, name in enumerate(views):
            button = self._button(tabs, name.upper(), lambda value=name: self._advanced_select(value), 165)
            button.grid(row=index // 5, column=index % 5, padx=3, pady=3, sticky="ew")
            self.advanced_tabs[name] = button
        for index in range(5):
            tabs.grid_columnconfigure(index, weight=1)
        stats = self._card(self.body)
        stats.pack(fill="x", pady=(0, 10))
        self.advanced_stats = self._label(stats, "No graph data", 11, TEXT, "bold", True,
                                          anchor="w", wraplength=1000)
        self.advanced_stats.pack(fill="x", padx=15, pady=13)
        panel = ctk.CTkFrame(self.body, fg_color="transparent")
        panel.pack(fill="both", expand=True)
        self.advanced_canvas = tk.Canvas(panel, bg=SIDEBAR, height=540,
                                         highlightthickness=1, highlightbackground=LINE)
        bar = tk.Scrollbar(panel, orient="vertical", command=self.advanced_canvas.yview)
        self.advanced_canvas.configure(yscrollcommand=bar.set)
        self.advanced_canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="left", fill="y")
        self.advanced_canvas.bind("<MouseWheel>",
                                  lambda event: self.advanced_canvas.yview_scroll(-int(event.delta/120), "units"))
        self.advanced_detail = ctk.CTkTextbox(self.body, height=170, fg_color=SIDEBAR,
                                               text_color=TEXT, font=self._font(11, mono=True))
        self.advanced_detail.pack(fill="x", pady=(9, 0))
        self._advanced_draw()

    def _advanced_choose(self):
        selected = filedialog.askdirectory(title="Choose a CastorPollux investigation")
        if selected:
            try:
                read_manifest(Path(selected))
                self.current_folder = Path(selected)
                self.show_page("advanced")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _advanced_rebuild(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first")
            return
        folder = Path(self.current_folder)
        def task():
            build_advanced_graph(folder)
            check_call_edges(folder)
            self._emit("advanced_refresh", "Graph and edge checks rebuilt")
        self._start_task(task)

    def _advanced_import(self, kind):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first")
            return
        source = filedialog.askopenfilename(title="Choose " + ("VEX" if kind == "vex" else "fuzz coverage") + " JSON",
                                            filetypes=[("JSON", "*.json")])
        if not source:
            return
        folder = Path(self.current_folder)
        def task():
            report = import_vex(folder, Path(source)) if kind == "vex" else import_fuzz_coverage(folder, Path(source))
            self._emit("advanced_refresh", f"{kind.upper()} imported: {report.get('matched', report.get('hit_blocks', 0))} matched")
        self._start_task(task)

    def _advanced_verify(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first")
            return
        try:
            report = verify_sbom_provenance(Path(self.current_folder), self.sbom_pin.get())
            self.advanced_view.set("SBOM provenance")
            self._advanced_draw()
            self.status_text.set("SBOM INTEGRITY: " + report["integrity"].upper())
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _advanced_overflows(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first")
            return
        report = scan_overflows(Path(self.current_folder))
        self.advanced_view.set("Overflow leads")
        self._advanced_draw()
        self.status_text.set(f"{report['count']} STATIC OVERFLOW LEADS")

    def _advanced_boundary(self):
        try:
            if not self.current_folder:
                raise ValueError("Choose an investigation first")
            result = create_boundary_inputs(Path(self.current_folder), int(self.overflow_lead_index.get()))
            self.advanced_detail.delete("1.0", "end")
            self.advanced_detail.insert("1.0", json.dumps(result, indent=2))
            self.status_text.set("BOUNDARY INPUTS SAVED — REPRODUCTION UNVERIFIED")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _advanced_draw(self):
        if not hasattr(self, "advanced_canvas") or not self.advanced_canvas.winfo_exists():
            return
        canvas = self.advanced_canvas
        canvas.delete("all")
        self.advanced_detail.delete("1.0", "end")
        folder = Path(self.current_folder) if self.current_folder else None
        view = self.advanced_view.get()
        for name, button in self.advanced_tabs.items():
            button.configure(fg_color=GREEN if name == view else FIELD,
                             text_color=BG if name == view else TEXT)
        filename, field = {"SSA flow": ("advanced-graph.json", "flows"),
                           "SSA leads": ("advanced-graph.json", "ssa_source_sink_leads"),
                           "Aliases": ("advanced-graph.json", "aliases"),
                           "Virtual calls": ("advanced-graph.json", "virtual_calls"),
                           "Jump tables": ("advanced-graph.json", "jump_table_details"),
                           "Edge checks": ("call-edge-checks.json", "edges"),
                           "Fuzz overlay": ("fuzz-coverage.json", "blocks"),
                           "Overflow leads": ("overflow-leads.json", "leads"),
                           "VEX": ("vex-import.json", "statements"),
                           "SBOM provenance": ("sbom-provenance.json", "declared_metadata")}[view]
        path = folder / filename if folder else None
        if not path or not path.is_file():
            self.advanced_stats.configure(text="No saved " + view + " evidence. Analyze or import the corresponding data.")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            self.advanced_stats.configure(text=str(error))
            return
        values = data.get(field, [])
        if isinstance(values, dict):
            values = [{"field": key, "value": value} for key, value in values.items()]
        self.advanced_stats.configure(text=(f"{view.upper()}  ·  {len(values):,} records  ·  " +
                                            "  ·  ".join(f"{key}: {data[key]:,}" for key in
                                                ("ssa_ops", "def_use_edges", "pointer_alias_leads", "virtual_dispatch_leads",
                                                 "jump_tables", "ssa_source_sink_count", "corroborated", "disputed", "independently_verified",
                                                 "hit_blocks", "total_blocks",
                                                 "matched", "unmatched") if isinstance(data.get(key), int)) +
                                            (f"  ·  integrity: {data['integrity']}" if "integrity" in data else "")))
        for index, item in enumerate(values[:140]):
            y = 32 + index * 40
            if view == "SSA flow":
                label = f"{item.get('function_entry', '')}  op {item.get('from_index')}  →  op {item.get('to_index')}  {item.get('varnode', '')}"
            elif view == "SSA leads":
                label = (f"{item.get('source_api', '')} @ {item.get('source_site', '')}  →  "
                         f"{item.get('sink_api', '')} @ {item.get('sink_site', '')}  {item.get('confidence', '')}")
            elif view == "Fuzz overlay":
                label = f"{item.get('function', '')}  {item.get('block_entry', '')}  hits {item.get('hits', 0)}"
            elif view == "Jump tables":
                label = f"{item.get('function', '')}  {item.get('site', '')}  →  {item.get('case_count', 0)} targets"
            elif view == "VEX":
                label = f"{item.get('vulnerability', '')}  {item.get('status', '')}  {item.get('match', '')}"
            elif view == "Edge checks":
                label = (f"{item.get('caller_name', '')}  →  {item.get('callee_name', '')}  "
                         f"Ghidra: {item.get('status', '')}  Raw: {item.get('independent_check', {}).get('status', '')}")
            elif view == "Overflow leads":
                label = f"#{index}  {item.get('function', '')}:{item.get('line', '')}  {item.get('api', '')}  {item.get('relation', '')}"
            else:
                label = (item.get("function", "") + "  " + item.get("address", "") + "  " +
                         item.get("opcode", item.get("field", item.get("site", "")))).strip()
            bad = item.get("status") in {"disputed", "unobserved"} or item.get("match") == "unmatched"
            color = RED if bad else CYAN if index % 2 else GREEN
            tag = f"record-{index}"
            if view == "SSA flow":
                canvas.create_line(380, y, 565, y, fill=color, width=2, arrow=tk.LAST, tags=tag)
                for left, right, caption in ((20, 380, f"DEF  {item.get('from_index')}  {item.get('varnode', '')}"),
                                             (565, 1000, f"USE  {item.get('to_index')}  slot {item.get('input_slot')}")):
                    canvas.create_rectangle(left, y-15, right, y+15, fill=FIELD, outline=color, width=2, tags=tag)
                    canvas.create_text(left+12, y, anchor="w", text=caption[:58], fill=TEXT,
                                       font=self._tk_font(10, mono=True, bold=True), tags=tag)
            elif view == "Jump tables":
                targets = item.get("targets", [])
                canvas.create_rectangle(18, y-15, 330, y+15, fill=FIELD, outline=color, width=2, tags=tag)
                canvas.create_text(28, y, anchor="w", text=f"{item.get('site', '')}  {item.get('function', '')}"[:36],
                                   fill=TEXT, font=self._tk_font(10, mono=True, bold=True), tags=tag)
                canvas.create_line(330, y, 400, y, fill=color, width=2, arrow=tk.LAST, tags=tag)
                canvas.create_text(410, y, anchor="w", text="  /  ".join(targets[:7])[:100] or "TARGETS UNRESOLVED",
                                   fill=TEXT, font=self._tk_font(10, mono=True), tags=tag)
            elif view == "Fuzz overlay":
                canvas.create_rectangle(18, y-15, 1100, y+15, fill=FIELD, outline=color, width=2, tags=tag)
                if item.get("hits", 0):
                    canvas.create_rectangle(18, y-15, min(1080, 18 + 80 + 120 * (item["hits"].bit_length())), y+15,
                                            fill=GREEN, outline="", tags=tag)
                canvas.create_text(30, y, anchor="w", text=label[:150], fill=TEXT,
                                   font=self._tk_font(10, mono=True, bold=True), tags=tag)
            else:
                canvas.create_rectangle(18, y-15, 1100, y+15, fill=FIELD, outline=color, width=2, tags=tag)
                canvas.create_text(30, y, anchor="w", text=label[:150], fill=TEXT,
                                   font=self._tk_font(10, mono=True, bold=True), tags=tag)
            canvas.tag_bind(tag, "<Button-1>", lambda event, record=item: self._advanced_detail(record))
        canvas.configure(scrollregion=(0, 0, 1120, max(500, 55 + min(len(values), 140) * 40)))
        self.advanced_detail.insert("1.0", "Click a row to inspect its full evidence. First 140 records are drawn; all records remain in the JSON artifact.\n\n" +
                                    "\n".join(data.get("limitations", [])))

    def _advanced_detail(self, record):
        self.advanced_detail.delete("1.0", "end")
        self.advanced_detail.insert("1.0", json.dumps(record, indent=2, ensure_ascii=False))

    def _advanced_select(self, name):
        self.advanced_view.set(name)
        self._advanced_draw()

    def _callpaths_page(self):
        self._label(self.body, "VISUAL CALL PATHS  /  DIRECT + INFERRED CALLS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Enter function names or addresses. Click a node for REA pseudocode and cross-references.",
                    13, MUTED).pack(anchor="w", pady=(0, 10))
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 10))
        self._button(controls, "CHOOSE INVESTIGATION", self._browse_callpaths_folder, 185).pack(side="left")
        self._button(controls, "SUGGEST PATH", self._suggest_callpath, 130).pack(side="left", padx=8)
        self._button(controls, "RESOLVE INDIRECT", self._resolve_indirect, 160).pack(side="left")
        self.call_folder_label = self._label(self.body, str(self.current_folder or "No investigation selected"),
                                             10, MUTED, mono=True, anchor="w")
        self.call_folder_label.pack(fill="x", pady=(0, 10))
        for title, variable in (("FROM", self.call_source), ("TO", self.call_target)):
            row = ctk.CTkFrame(self.body, fg_color="transparent")
            row.pack(fill="x", pady=3)
            self._label(row, title, 11, CYAN, "bold", True).pack(side="left", padx=(0, 10))
            ctk.CTkEntry(row, textvariable=variable, fg_color=FIELD, border_color=LINE,
                         text_color=TEXT, height=36).pack(side="left", fill="x", expand=True)
        buttons = ctk.CTkFrame(self.body, fg_color="transparent")
        buttons.pack(fill="x", pady=10)
        self._button(buttons, "FIND PATHS", self._run_callpaths, 135, True).pack(side="left")
        self._button(buttons, "PREVIOUS", lambda: self._step_callpath(-1), 105).pack(side="left", padx=(8, 0))
        self._button(buttons, "NEXT", lambda: self._step_callpath(1), 80).pack(side="left", padx=8)
        self.call_path_label = self._label(buttons, "", 11, MUTED, mono=True)
        self.call_path_label.pack(side="left", padx=8)
        panel = ctk.CTkFrame(self.body, fg_color="transparent")
        panel.pack(fill="both", expand=True)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_columnconfigure(1, weight=1)
        self.call_canvas = tk.Canvas(panel, bg=SIDEBAR, highlightthickness=1, highlightbackground=LINE,
                                     height=700)
        self.call_canvas.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self.call_detail = ctk.CTkTextbox(panel, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                          text_color=TEXT, font=self._font(11, mono=True))
        self.call_detail.grid(row=0, column=1, sticky="nsew")
        self.call_detail.insert("1.0", "A path is a saved static call-graph lead. Indirect calls may be missing.")
        if self.active_call_report:
            self._draw_callpath()

    def _resolve_indirect(self):
        try:
            if not self.current_folder:
                raise ValueError("Choose an investigation first")
            folder = Path(self.current_folder)
            read_manifest(folder)
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            report = resolve_indirect_calls(folder)
            self._emit("log", f"Indirect calls: {len(report['resolved'])} candidate edge(s), "
                              f"{len(report['unresolved'])} unresolved site(s).")
            self._emit("indirect_calls", report)
        self._start_task(task)

    def _browse_callpaths_folder(self):
        path = filedialog.askdirectory(title="Choose a saved CastorPollux investigation")
        if path:
            try:
                read_manifest(Path(path))
                self.current_folder = Path(path)
                self.active_call_report = None
                self.show_page("callpaths")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _suggest_callpath(self):
        try:
            if not self.current_folder:
                raise ValueError("Choose an investigation first")
            graph = load_graph(self.current_folder)
            source, neighbours = next((source, targets) for source, targets in graph["edges"].items() if targets)
            self.call_source.set(source)
            self.call_target.set(neighbours[0])
            self._run_callpaths()
        except (ValueError, StopIteration) as error:
            messagebox.showerror("CastorPollux", str(error))

    def _run_callpaths(self):
        try:
            folder = Path(self.current_folder)
            read_manifest(folder)
            source, target = self.call_source.get(), self.call_target.get()
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        def task():
            self._emit("call_paths", explore_paths(folder, source, target))
        self._start_task(task)

    def _step_callpath(self, direction):
        if self.active_call_report and self.active_call_report["paths"]:
            self.call_path_index = max(0, min(len(self.active_call_report["paths"]) - 1,
                                            self.call_path_index + direction))
            self._draw_callpath()

    def _draw_callpath(self):
        self.call_canvas.delete("all")
        report = self.active_call_report
        if not report or not report["paths"]:
            self.call_path_label.configure(text="NO SAVED DIRECT PATH")
            self.call_canvas.create_text(240, 70, text="No direct path found in calls.csv", fill=MUTED,
                                         font=self._tk_font(14))
            return
        paths = report["paths"]
        self.call_path_label.configure(text=f"PATH {self.call_path_index + 1}/{len(paths)}" +
                                            ("  •  SEARCH TRUNCATED" if report["truncated"] else ""))
        nodes = paths[self.call_path_index]
        step = min(76, max(49, 625 // max(1, len(nodes))))
        for index, node in enumerate(nodes):
            y = 42 + index * step
            if index:
                self.call_canvas.create_line(210, y - step + 25, 210, y - 24, fill=CYAN,
                                             width=2, arrow=tk.LAST)
            tag = f"call_node_{index}"
            self.call_canvas.create_rectangle(38, y - 23, 382, y + 23, fill=FIELD,
                                              outline=GREEN if index in (0, len(nodes)-1) else LINE,
                                              width=2, tags=tag)
            label = f"{node['name'][:28]} @ {node['entry']}"
            self.call_canvas.create_text(210, y - 5, text=label, fill=TEXT,
                                         font=self._tk_font(10, mono=True, bold=True), tags=tag)
            self.call_canvas.create_text(210, y + 12,
                                         text=f"{node['callers']} callers  ·  {node['callees']} callees" +
                                              (f"  ·  {node['incoming']['confidence']} {node['incoming']['kind']}"
                                               if node.get("incoming") else ""),
                                         fill=MUTED, font=self._tk_font(9), tags=tag)
            self.call_canvas.tag_bind(tag, "<Button-1>", lambda event, item=node: self._select_call_node(item))
        self._select_call_node(nodes[0])

    def _select_call_node(self, node):
        detail = f"{node['name']} @ {node['entry']}\n{node['callers']} callers · {node['callees']} callees\n\n"
        if node.get("incoming"):
            detail += "INCOMING EDGE: " + json.dumps(node["incoming"], indent=2) + "\n\n"
        try:
            if node["entry"].startswith("EXTERNAL:"):
                detail += "External function: no local pseudocode body."
            else:
                jump = evidence_jump(self.current_folder, {"file": "rea-pseudocode.c",
                                                           "location": "0x" + node["entry"]})
                detail += jump["code"] or "No REA pseudocode saved for this node."
                detail += "\n\nCROSS-REFERENCES\n" + "\n".join(json.dumps(item) for item in jump["xrefs"][:50])
        except Exception as error:
            detail += "Cannot resolve pseudocode: " + str(error)
        self.call_detail.delete("1.0", "end")
        self.call_detail.insert("1.0", detail)

    def _codex_page(self):
        self._label(self.body, "DEFENSIVE REVIEW  /  EVIDENCE-BASED", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Choose an installed agent to review saved pseudocode and analysis evidence.",
                    14, MUTED).pack(anchor="w", pady=(0, 8))
        settings = ctk.CTkScrollableFrame(self.body, fg_color="transparent", scrollbar_button_color=FIELD)
        settings.pack(fill="both", expand=True, pady=(0, 8))
        card = self._card(settings)
        card.pack(fill="x")
        self._label(card, "INVESTIGATION", 11, CYAN, "bold", True).pack(anchor="w", padx=19, pady=(16, 5))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=19)
        if not self.review_folder.get() and self.current_folder:
            self.review_folder.set(str(self.current_folder))
        ctk.CTkEntry(row, textvariable=self.review_folder, height=38, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT,
                     placeholder_text="Saved investigation folder from History").pack(side="left", fill="x", expand=True)
        self._button(row, "BROWSE", self._browse_review_folder, 100).pack(side="left", padx=(8, 0))
        self._label(card, "REVIEW AGENT", 11, CYAN, "bold", True).pack(anchor="w", padx=19, pady=(12, 5))
        ctk.CTkOptionMenu(card, variable=self.review_agent, values=["codex", "claude", "opencode", "ollama"],
                          command=self._agent_changed, width=150, fg_color=FIELD, button_color=LINE,
                          text_color=TEXT).pack(anchor="w", padx=19)
        self._label(card, "REVIEW SCOPE", 11, CYAN, "bold", True).pack(anchor="w", padx=19, pady=(12, 5))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=19)
        ctk.CTkOptionMenu(row, variable=self.scope_mode, values=["all", "functions", "modules"],
                          width=125, fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(side="left")
        ctk.CTkEntry(row, textvariable=self.scope_selection, height=38, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT,
                     placeholder_text="Comma-separated function names/addresses or modules").pack(
                         side="left", fill="x", expand=True, padx=(8, 0))
        self._button(row, "OPTIONS", self._scope_options, 90).pack(side="left", padx=(8, 0))
        self._label(card, "All reviews every staged procedure. Functions accepts names or addresses; modules accepts Ghidra namespaces.",
                    11, MUTED, wraplength=820, justify="left").pack(anchor="w", padx=19, pady=(4, 0))
        self._label(card, "AGENT CLI", 11, CYAN, "bold", True).pack(anchor="w", padx=19, pady=(12, 5))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=19)
        ctk.CTkEntry(row, textvariable=self.codex_cli_path, height=38, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT,
                     placeholder_text="Installed Codex, Claude Code, or OpenCode CLI").pack(side="left", fill="x", expand=True)
        self._button(row, "AUTO DETECT", self._locate_agent_cli, 118).pack(side="left", padx=(8, 0))
        self._button(row, "BROWSE", self._browse_codex_cli, 100).pack(side="left", padx=(8, 0))
        self._label(card, "The CLI runs a defensive, read-only evidence review. Cloud providers may decline a request; analysis remains saved.",
                    11, MUTED, wraplength=820, justify="left").pack(anchor="w", padx=19, pady=(4, 0))
        self._label(card, "OFFLINE LOCAL MODEL  /  OLLAMA ON 127.0.0.1", 11, CYAN, "bold", True).pack(
            anchor="w", padx=19, pady=(12, 5))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=19)
        self.local_model_picker = ctk.CTkOptionMenu(row, variable=self.local_model,
            values=[self.local_model.get() or "No local model detected"], width=250,
            fg_color=FIELD, button_color=LINE, text_color=TEXT)
        self.local_model_picker.pack(side="left")
        self._button(row, "CHECK LOCAL MODELS", self._refresh_local_models, 170).pack(side="left", padx=8)
        self.daybreak_checkbox = ctk.CTkCheckBox(
            card, text="Use Daybreak Blue for Codex review (optional; access required)",
            variable=self.daybreak_blue, text_color=TEXT, fg_color=GREEN,
            hover_color=CYAN, font=self._font(12))
        self.daybreak_checkbox.pack(anchor="w", padx=19, pady=(10, 3))
        self.daybreak_checkbox.configure(state="normal" if self.review_agent.get() == "codex" else "disabled")
        self._label(card, "For best security review results, use a Daybreak-enabled model when available. Standard Codex works without it.",
                    11, MUTED).pack(anchor="w", padx=19, pady=(0, 8))
        review_options = ctk.CTkFrame(card, fg_color="transparent")
        review_options.pack(fill="x", padx=19, pady=(0, 8))
        self._label(review_options, "MINIMUM COVERAGE %", 11, CYAN, "bold", True).pack(side="left")
        ctk.CTkEntry(review_options, textvariable=self.coverage_minimum, width=70,
                     fg_color=FIELD, border_color=LINE, text_color=TEXT).pack(side="left", padx=(8, 18))
        ctk.CTkCheckBox(review_options, text="RetDec check for high findings", variable=self.secondary_decompiler,
                        text_color=TEXT, fg_color=GREEN, font=self._font(11)).pack(side="left")
        retdec_row = ctk.CTkFrame(card, fg_color="transparent")
        retdec_row.pack(fill="x", padx=19, pady=(0, 8))
        self._label(retdec_row, "RETDEC CLI", 11, CYAN, "bold", True).pack(side="left", padx=(0, 8))
        ctk.CTkEntry(retdec_row, textvariable=self.retdec_path, fg_color=FIELD, border_color=LINE,
                     text_color=TEXT, placeholder_text="Optional RetDec executable for a second decompiler check").pack(
                         side="left", fill="x", expand=True)
        self._button(retdec_row, "BROWSE", self._browse_retdec, 95).pack(side="left", padx=(8, 0))
        privacy_row = ctk.CTkFrame(card, fg_color="transparent")
        privacy_row.pack(fill="x", padx=19, pady=(0, 8))
        ctk.CTkCheckBox(privacy_row, text="Redact cloud evidence", variable=self.redact_cloud,
                        text_color=TEXT, fg_color=GREEN, font=self._font(11)).pack(side="left")
        ctk.CTkEntry(privacy_row, textvariable=self.redaction_terms, fg_color=FIELD,
                     border_color=LINE, text_color=TEXT,
                     placeholder_text="Additional literal terms to redact, separated by commas").pack(
                         side="left", fill="x", expand=True, padx=(12, 0))
        formats_row = ctk.CTkFrame(card, fg_color="transparent")
        formats_row.pack(anchor="w", padx=19, pady=(0, 8))
        self._label(formats_row, "EXPORT:", 11, CYAN, "bold", True).pack(side="left", padx=(0, 8))
        for name in REPORT_FORMATS:
            ctk.CTkCheckBox(formats_row, text=name.upper(), variable=self.report_formats[name],
                            width=70, checkbox_width=17, checkbox_height=17, text_color=TEXT,
                            fg_color=GREEN, hover_color=CYAN, font=self._font(11)).pack(side="left", padx=2)
        self._label(card, "Cloud agents receive scoped text exports. Ollama uses loopback only. The binary is excluded.",
                    11, MUTED).pack(anchor="w", padx=19, pady=(0, 14))
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=(0, 13))
        self.review_button = self._button(row, "✦  RUN REVIEW", self._run_codex_review, 175, True)
        self.review_button.pack(side="left")
        self._button(row, "■  CANCEL", self._cancel, 105).pack(side="left", padx=8)
        self._button(row, "PROMPT PREVIEW", self._preview_prompt, 155).pack(side="left")
        self._button(row, "EVIDENCE PREVIEW", self._preview_evidence, 160).pack(side="left", padx=(8, 0))
        self._button(row, "↗  OPEN REPORTS", self._open_review_reports, 145).pack(side="right")
        self._label(self.body, "LIVE AGENT OUTPUT", 11, CYAN, "bold").pack(anchor="w", pady=(0, 5))
        self._activity_panel(self.body, height=235)
        try:
            _, warnings = review_readiness(Path(self.review_folder.get()))
            self._log("Ready for review." + (" " + " ".join(warnings) if warnings else ""))
        except Exception as error:
            self._log("Select a completed or partial investigation. " + str(error))

    def _agent_changed(self, agent):
        self.codex_cli_path.set(str(find_agent_cli(agent) or "") if agent != "ollama" else "")
        if agent != "codex":
            self.daybreak_blue.set(False)
        self.daybreak_checkbox.configure(state="normal" if agent == "codex" else "disabled")
        if agent == "ollama" and self.page_name == "codex":
            self._refresh_local_models()

    def _scope_options(self):
        folder = Path(self.review_folder.get()) if getattr(self, "review_folder", None) else self.current_folder
        rows = coverage_rows(folder) if folder and folder.is_dir() else []
        modules = sorted({row["module"] for row in rows})
        examples = "\n".join(f"{row['name']} @ {row['address']}" for row in rows[:12])
        messagebox.showinfo("Review scope", "Functions: enter names or addresses separated by commas.\n"
                            "Modules: enter a module/namespace name from this list:\n" +
                            (", ".join(modules) or "No investigation selected") +
                            "\n\nExample functions:\n" + examples)

    def _refresh_local_models(self):
        def task():
            names = ollama_models()
            self._emit("local_models", names)
        self._start_task(task)

    def _preview_prompt(self):
        folder = Path(self.review_folder.get()) if getattr(self, "review_folder", None) else self.current_folder
        try:
            scope = resolve_scope(folder, self.scope_mode.get(), self.scope_selection.get())
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        window = ctk.CTkToplevel(self)
        window.title("Exact agent review prompt")
        window.geometry("790x600")
        box = ctk.CTkTextbox(window, fg_color=SIDEBAR, text_color=TEXT, font=self._font(12, mono=True))
        box.pack(fill="both", expand=True, padx=15, pady=15)
        box.insert("1.0", build_review_prompt(scope, self.review_agent.get() == "ollama"))
        box.configure(state="disabled")

    def _locate_agent_cli(self):
        if self.review_agent.get() == "ollama":
            self._refresh_local_models()
            return
        path = find_agent_cli(self.review_agent.get())
        if path:
            self.codex_cli_path.set(str(path))
            self._log(f"Found {self.review_agent.get()} at {path}")
        else:
            messagebox.showerror("CastorPollux", f"No {self.review_agent.get()} CLI was found. Install it or browse to its executable.")

    def _browse_review_folder(self):
        folder = filedialog.askdirectory(title="Choose a saved investigation")
        if folder:
            try:
                read_manifest(Path(folder))
                self.review_folder.set(folder)
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _browse_codex_cli(self):
        path = filedialog.askopenfilename(title="Choose agent executable",
                                          filetypes=[("CLI executable", "*.exe *.cmd *.bat"), ("All files", "*.*")])
        if path:
            self.codex_cli_path.set(path)

    def _browse_retdec(self):
        path = filedialog.askopenfilename(title="Choose RetDec decompiler",
                                          filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            self.retdec_path.set(path)

    def _preview_evidence(self):
        if self.review_agent.get() == "ollama":
            messagebox.showinfo("Evidence preview", "Cloud staging applies to Codex, Claude Code, and OpenCode. Ollama receives bounded code chunks on loopback.")
            return
        try:
            preview = cloud_evidence_preview(Path(self.review_folder.get()), self.scope_mode.get(),
                                             self.scope_selection.get(), self.redact_cloud.get(),
                                             [term.strip() for term in self.redaction_terms.get().split(",") if term.strip()],
                                             self.review_agent.get())
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        window = ctk.CTkToplevel(self)
        window.title("Cloud evidence preview")
        window.geometry("900x650")
        box = ctk.CTkTextbox(window, fg_color=SIDEBAR, text_color=TEXT, font=self._font(12, mono=True))
        box.pack(fill="both", expand=True, padx=16, pady=16)
        box.insert("1.0", preview)
        box.configure(state="disabled")

    def _run_codex_review(self):
        folder = Path(self.review_folder.get())
        try:
            read_manifest(folder)
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        agent = self.review_agent.get()
        executable = Path(self.codex_cli_path.get()) if agent != "ollama" else None
        if agent != "ollama":
            if not executable.is_file():
                detected = find_agent_cli(agent)
                if detected:
                    executable = detected
                    self.codex_cli_path.set(str(detected))
            if not executable.is_file():
                messagebox.showerror("CastorPollux", "Choose or locate an installed agent CLI first.")
                return
        try:
            resolve_scope(folder, self.scope_mode.get(), self.scope_selection.get())
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))
            return
        daybreak = self.daybreak_blue.get()
        try:
            minimum_coverage = int(self.coverage_minimum.get())
            if not 0 <= minimum_coverage <= 100:
                raise ValueError
        except ValueError:
            messagebox.showerror("CastorPollux", "Minimum coverage must be a number from 0 to 100.")
            return
        redaction_terms = [term.strip() for term in self.redaction_terms.get().split(",") if term.strip()]
        redact_cloud = self.redact_cloud.get()
        secondary = self.secondary_decompiler.get()
        retdec = Path(self.retdec_path.get()) if self.retdec_path.get() else None
        formats = {name for name, variable in self.report_formats.items() if variable.get()}
        scope_mode, scope_selection, local_model = self.scope_mode.get(), self.scope_selection.get(), self.local_model.get()
        if not formats:
            messagebox.showerror("CastorPollux", "Select at least one report format.")
            return
        self.current_folder = folder
        def task():
            self._emit("log", "CASTORPOLLUX_STAGE 0 Agent review in progress • live output below")
            review = CodexReview(lambda m: self._emit("log", m), self.cancel_event.is_set, self._set_process)
            try:
                result = review.run(folder, daybreak, executable, formats, agent,
                                    scope_mode, scope_selection, local_model, minimum_coverage,
                                    redact_cloud, redaction_terms, secondary, retdec)
            except Exception as error:
                record_error(str(error), folder, "agent review", traceback.format_exc())
                raise
            finally:
                self._capture_agent_usage(folder, agent)
            self._emit("codex_report", (result, str(folder)))
            self._emit("log", "CASTORPOLLUX_STAGE 100 Agent review complete")
        self._start_task(task)

    def _open_review_reports(self):
        folder = self.current_folder if self.page_name == "reports" else \
                 Path(self.review_folder.get()) if getattr(self, "review_folder", None) else self.current_folder
        if folder:
            for extension in ("html", "pdf", "md", "json", "csv", "sarif"):
                target = folder / ("security-report." + extension)
                if target.is_file():
                    os.startfile(target)
                    return
        elif folder and folder.is_dir():
            os.startfile(folder)

    def _reports_page(self):
        self._label(self.body, "FINDINGS  /  CLICKABLE EVIDENCE  /  TRIAGE", 11, GREEN, mono=True).pack(
            anchor="w", pady=(0, 8))
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 8))
        self._button(controls, "CHOOSE INVESTIGATION", self._browse_reports_folder, 185, True).pack(side="left")
        self._button(controls, "OPEN REPORT FILE", self._open_review_reports, 145).pack(side="right")
        self._button(controls, "OPEN AUDIT LOG", self._open_audit_log, 145).pack(side="right", padx=8)
        self._button(controls, "DISCLOSURE ZIP", self._export_disclosure, 135).pack(side="right", padx=8)
        self._button(controls, "REDUCE INPUT", self._minimize_input, 125).pack(side="right", padx=8)
        self.report_folder_label = self._label(self.body, str(self.current_folder or "No investigation selected"),
                                               10, MUTED, mono=True, anchor="w")
        self.report_folder_label.pack(fill="x", pady=(0, 8))
        self.report_runs = {}
        folder = self.current_folder
        if folder:
            current = folder / "security-review-data.json"
            if not current.is_file():
                current = folder / "security-report.json"
            if current.is_file():
                self.report_runs["Current"] = current
            history = folder / "ReviewHistory"
            if history.is_dir():
                for archived in sorted(history.iterdir(), reverse=True):
                    path = archived / "security-review-data.json"
                    if not path.is_file():
                        path = archived / "security-report.json"
                    if path.is_file():
                        self.report_runs[archived.name] = path
        self.report_run = ctk.StringVar(value=next(iter(self.report_runs), "No report"))
        run_row = ctk.CTkFrame(self.body, fg_color="transparent")
        run_row.pack(fill="x", pady=(0, 8))
        self._label(run_row, "REVIEW RUN", 11, CYAN, "bold", True).pack(side="left", padx=(0, 8))
        ctk.CTkOptionMenu(run_row, variable=self.report_run,
                          values=list(self.report_runs) or ["No report"], command=self._display_report_run,
                          width=260, fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(side="left")
        self._button(run_row, "SAVE LAYOUT", self._save_current_layout, 135).pack(side="right")
        self.report_summary = self._label(self.body, "", 11, MUTED, anchor="w", wraplength=760)
        self.report_summary.pack(fill="x", pady=(0, 8))
        people = ctk.CTkFrame(self.body, fg_color="transparent")
        people.pack(fill="x", pady=(0, 5))
        ctk.CTkEntry(people, textvariable=self.triage_actor, placeholder_text="Reviewer name",
                     width=170, fg_color=FIELD, border_color=LINE, text_color=TEXT).pack(side="left")
        ctk.CTkEntry(people, textvariable=self.triage_assignee, placeholder_text="Assignee / team",
                     width=200, fg_color=FIELD, border_color=LINE, text_color=TEXT).pack(side="left", padx=8)
        self._label(people, "Decisions saved to findings-audit.jsonl", 10, MUTED).pack(side="left")
        triage = ctk.CTkFrame(self.body, fg_color=CARD, corner_radius=8)
        triage.pack(fill="x", pady=(0, 8))
        self.triage_status = ctk.StringVar(value="unreviewed")
        ctk.CTkOptionMenu(triage, variable=self.triage_status,
                          values=["unreviewed", "confirmed", "false_positive", "needs_more_evidence"],
                          width=190, fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(
                              side="left", padx=8, pady=8)
        self.triage_note = ctk.CTkEntry(triage, placeholder_text="Analyst note for selected finding",
                                        fg_color=FIELD, border_color=LINE, text_color=TEXT)
        self.triage_note.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._button(triage, "SAVE TRIAGE", self._save_finding_triage, 120).pack(side="right", padx=8)
        suppress = ctk.CTkFrame(self.body, fg_color=CARD, corner_radius=8)
        suppress.pack(fill="x", pady=(0, 8))
        self.suppression_reason = ctk.CTkEntry(suppress, placeholder_text="Suppression reason (required)",
                                               fg_color=FIELD, border_color=LINE, text_color=TEXT)
        self.suppression_reason.pack(side="left", fill="x", expand=True, padx=8, pady=8)
        self.suppression_expiry = ctk.CTkEntry(suppress, placeholder_text="YYYY-MM-DD", width=110,
                                               fg_color=FIELD, border_color=LINE, text_color=TEXT)
        self.suppression_expiry.pack(side="left", padx=(0, 8))
        self._button(suppress, "SUPPRESS", self._save_suppression, 100).pack(side="left", padx=(0, 8))
        self._button(suppress, "CLEAR", self._clear_suppression, 75).pack(side="left", padx=(0, 8))
        findings_frame, evidence_frame, detail_frame = self._split_frame(self.body, count=3, height=440)
        self.report_findings = ctk.CTkScrollableFrame(findings_frame, fg_color=CARD, border_width=1, border_color=LINE)
        self.report_findings.pack(fill="both", expand=True)
        self.report_evidence = ctk.CTkScrollableFrame(evidence_frame, fg_color=CARD, border_width=1, border_color=LINE)
        self.report_evidence.pack(fill="both", expand=True)
        self.report_detail = ctk.CTkTextbox(detail_frame, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                            text_color=TEXT, font=self._font(11, mono=True))
        self.report_detail.pack(fill="both", expand=True)
        self.selected_finding = None
        self._display_report_run(self.report_run.get())

    def _browse_reports_folder(self):
        folder = filedialog.askdirectory(title="Choose a CastorPollux investigation")
        if folder:
            try:
                read_manifest(Path(folder))
                self.current_folder = Path(folder)
                self.show_page("reports")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _minimize_input(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        sample = filedialog.askopenfilename(title="Choose a candidate input sample (16 MiB maximum)")
        if sample:
            try:
                result = minimize_candidate_input(self.current_folder, Path(sample))
                self.status_text.set(f"CANDIDATE INPUT: {result['source_bytes']} → {result['candidate_bytes']} BYTES; UNVERIFIED")
                messagebox.showinfo("CastorPollux", "Saved " + result["candidate_file"] +
                                    "\n\nThe reduced input has not been tested and may not reproduce the crash.")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _export_disclosure(self):
        if not self.current_folder:
            messagebox.showerror("CastorPollux", "Choose an investigation first.")
            return
        target = filedialog.asksaveasfilename(title="Save coordinated disclosure draft",
                                               defaultextension=".zip", initialfile="disclosure-draft.zip",
                                               filetypes=[("ZIP files", "*.zip")])
        if target:
            try:
                disclosure_packet(self.current_folder, Path(target))
                self.status_text.set("DISCLOSURE DRAFT SAVED — REVIEW BEFORE SHARING")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _display_report_run(self, name):
        for panel in (self.report_findings, self.report_evidence):
            for child in panel.winfo_children():
                child.destroy()
        self.report_detail.delete("1.0", "end")
        path = self.report_runs.get(name)
        if not path:
            self.report_summary.configure(text="No structured review is saved for this investigation.")
            self.report_detail.insert("1.0", "Run Agent Review to create a report.")
            return
        try:
            self.active_report = json.loads(path.read_text(encoding="utf-8"))
            findings = self.active_report["result"]["findings"]
            self.report_asset_folder = path.parent
        except (OSError, ValueError, KeyError, TypeError) as error:
            self.report_detail.insert("1.0", f"Cannot read report: {error}")
            return
        stale = review_is_stale(self.current_folder, self.active_report)
        versions = self.active_report.get("analysis_context", {}).get("engine_versions", {})
        engine_text = ", ".join(f"{key} {value}" for key, value in versions.items())
        self.report_summary.configure(text=f"{'STALE — rerun review after resumed analysis  •  ' if stale else ''}"
                                           f"{self.active_report.get('agent', 'Agent').upper()}  •  "
                                           f"{len(findings)} finding(s)  •  {self.active_report.get('created_at', '')}"
                                           f"  •  {engine_text}", text_color=RED if stale else MUTED)
        for index, finding in enumerate(findings, 1):
            suppressed = bool(active_suppression(self.current_folder, finding))
            button = self._button(self.report_findings,
                         f"{index}. {'SUPPRESSED' if suppressed else finding.get('severity', '').upper()}  {finding.get('title', '')}",
                         lambda item=finding: self._select_report_finding(item), 250)
            severity = str(finding.get("severity", "")).lower()
            severity_colors = {"critical": "#8F233C", "high": "#A83D42", "medium": "#A16B24",
                               "low": "#236E81", "informational": FIELD, "info": FIELD}
            button.configure(fg_color=FIELD if suppressed else severity_colors.get(severity, FIELD),
                             hover_color=LINE if suppressed else severity_colors.get(severity, LINE),
                             text_color=MUTED if suppressed else "#FFFFFF", anchor="w")
            button.pack(fill="x", pady=2)
        if findings:
            self._select_report_finding(findings[0])
        else:
            self.report_detail.insert("1.0", self.active_report["result"].get("summary", "No findings."))

    def _select_report_finding(self, finding):
        self.selected_finding = finding
        for child in self.report_evidence.winfo_children():
            child.destroy()
        triage = load_triage(self.current_folder).get(finding_key(finding), {})
        self.triage_status.set(triage.get("status", "unreviewed"))
        self.triage_note.delete(0, "end")
        self.triage_note.insert(0, triage.get("note", ""))
        self.triage_assignee.set(triage.get("assignee", ""))
        suppression = active_suppression(self.current_folder, finding)
        self.suppression_reason.delete(0, "end")
        self.suppression_expiry.delete(0, "end")
        if suppression:
            self.suppression_reason.insert(0, suppression["reason"])
            self.suppression_expiry.insert(0, suppression["expires_on"])
        for item in finding.get("evidence", []):
            freshness = evidence_freshness(self.current_folder, self.active_report, item)
            self._button(self.report_evidence,
                         f"[{freshness}]  {item.get('file', '')}  {item.get('location', '')}",
                         lambda evidence=item: self._show_report_evidence(evidence), 250).pack(fill="x", pady=2)
        self._button(self.report_evidence, "VIEW CODE + ASSEMBLY",
                     self._report_to_lab, 250).pack(fill="x", pady=(10, 2))
        if finding.get("code_excerpts"):
            self._button(self.report_evidence, "REPORT CODE EXCERPTS",
                         lambda item=finding: self._show_finding_excerpts(item), 250).pack(fill="x", pady=2)
        if finding.get("call_path_image"):
            self._button(self.report_evidence, "VIEW FINDING CALL PATH",
                         lambda item=finding: self._open_finding_call_path(item), 250).pack(fill="x", pady=2)
        self._button(self.report_evidence, "CONFIRMATION CHECKLIST",
                     lambda item=finding: self._open_finding_checklist(item), 250).pack(fill="x", pady=2)
        detail = (finding.get("title", "") + "\n\n" + finding.get("description", "") +
                  "\n\nVulnerability class: " + finding.get("vulnerability_type", "unclassified").replace("_", " ") +
                  "\n\nPotential impact: " + finding.get("impact", "") +
                  "\n\nRecommendation: " + finding.get("recommendation", "") +
                  "\n\nValidation: " + finding.get("validation", "") +
                  "\n\nRoot cause: " + finding.get("root_cause", "") +
                  "\n\nData flow: " + finding.get("data_flow", "") +
                  "\n\nExploit prerequisites: " + finding.get("exploit_prerequisites", "") +
                  "\n\nCounter-evidence / uncertainty: " + finding.get("counter_evidence", "") +
                  "\n\nDetailed remediation: " + finding.get("remediation_detail", "") +
                  "\n\nCWE: " + str(finding.get("cwe", {}).get("id") or "Unmapped") +
                  "\n" + finding.get("cwe", {}).get("explanation", "") +
                  "\n\nStatic reachability: " + finding.get("reachability", {}).get("rank", "unknown") +
                  "\n" + finding.get("reachability", {}).get("explanation", "") +
                  "\n\nConfidence reasons (agent label: " + finding.get("confidence", "unknown") + "):\n" +
                  "\n".join("• " + reason for reason in
                            finding.get("confidence_assessment", {}).get("reasons", [])) +
                  ("\n\nSUPPRESSED until " + suppression["expires_on"] + ": " + suppression["reason"] if suppression else "") +
                  "\n\nClick an evidence item to jump to its saved code and cross-references.")
        candidate = finding.get("proof_of_concept")
        if isinstance(candidate, dict):
            detail += ("\n\nPYTHON PROOF-OF-CONCEPT CANDIDATE (UNVERIFIED)\n"
                       "Status: " + candidate.get("status", "unknown") +
                       "\nSetup: " + candidate.get("setup", "") +
                       "\nExpected observation: " + candidate.get("expected_observation", "") +
                       "\nLimitations: " + candidate.get("limitations", ""))
            if candidate.get("python"):
                detail += "\n\n" + candidate["python"]
        audit = self.current_folder / "findings-audit.jsonl" if self.current_folder else None
        if audit and audit.is_file():
            try:
                events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line.strip()]
                related = [item for item in events if item.get("finding_key") == finding_key(finding)]
                if related:
                    detail += "\n\nDECISION HISTORY\n" + "\n".join(
                        f"{item.get('timestamp', '')}  {item.get('actor', '')}: "
                        f"{item.get('after', {}).get('status', '')}  "
                        f"{item.get('after', {}).get('note', '')}" for item in related[-25:])
            except (OSError, ValueError):
                detail += "\n\nDecision history could not be read."
        self.report_detail.delete("1.0", "end")
        self.report_detail.insert("1.0", detail)

    def _show_finding_excerpts(self, finding):
        excerpts = finding.get("code_excerpts", [])
        lines = ["REA reconstructed pseudocode — verify against disassembly before citing.", ""]
        for excerpt in excerpts:
            lines += [f"{excerpt['function']} @ {excerpt['address']}  |  "
                      f"procedure lines {excerpt['start_line']}–{excerpt['end_line']}",
                      excerpt["note"], "Source SHA-256: " + excerpt["source_sha256"],
                      "", excerpt["code"], "", ""]
        self._show_text("Report-ready code excerpts", "\n".join(lines))

    def _open_finding_call_path(self, finding):
        relative = str(finding.get("call_path_image", ""))
        if not re.fullmatch(r"finding-assets/finding-\d{2,4}-call-path\.png", relative):
            messagebox.showerror("CastorPollux", "The saved call-path image name is invalid.")
            return
        image_path = Path(getattr(self, "report_asset_folder", self.current_folder)) / relative
        if not image_path.is_file():
            messagebox.showerror("CastorPollux", "The call-path image is missing. Re-run Agent Review to regenerate it.")
            return
        os.startfile(image_path)

    def _open_finding_checklist(self, finding):
        steps = finding.get("confirmation_checklist") or confirmation_steps(finding)
        key = finding_key(finding)
        saved = load_confirmation_state(Path(self.current_folder)).get(key, {})
        window = ctk.CTkToplevel(self)
        window.title("CastorPollux | Confirm finding")
        window.geometry("970x570")
        self._label(window, "CONFIRMATION CHECKLIST", 18, GREEN, "bold").pack(anchor="w", padx=20, pady=(18, 5))
        self._label(window, finding.get("title", "Potential finding"), 13, TEXT,
                    wraplength=900).pack(anchor="w", padx=20, pady=(0, 8))
        self._label(window, "Checks are analyst decisions. Completing them does not automatically verify a vulnerability.",
                    11, MUTED, wraplength=900).pack(anchor="w", padx=20, pady=(0, 14))
        panel = ctk.CTkScrollableFrame(window, fg_color=CARD)
        panel.pack(fill="both", expand=True, padx=18)
        values = {}
        for step in steps:
            value = ctk.BooleanVar(value=bool(saved.get(step["id"], False)))
            values[step["id"]] = value
            ctk.CTkCheckBox(panel, text=step["label"], variable=value, text_color=TEXT,
                            font=self._font(12)).pack(anchor="w", padx=12, pady=11)
        def save():
            try:
                save_confirmation_state(Path(self.current_folder), key,
                                        {name: value.get() for name, value in values.items()})
                self.status_text.set("FINDING CHECKLIST SAVED")
                window.destroy()
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))
        self._button(window, "SAVE CHECKLIST", save, 180, True).pack(anchor="e", padx=20, pady=16)

    def _show_report_evidence(self, evidence):
        self.selected_evidence = evidence
        try:
            jump = evidence_jump(self.current_folder, evidence)
            text = (f"{jump['file']}  {jump['location']}\n{jump['observation']}\n\n"
                    f"FUNCTION: {jump['function']} @ {jump['address']}\n\n"
                    "RECONSTRUCTED CODE\n" + (jump["code"] or "No matching REA code found.") +
                    "\n\nCITED FILE EXCERPT\n" + (jump["excerpt"] or "No line excerpt available.") +
                    f"\n\nCROSS-REFERENCES ({len(jump['xrefs'])})\n" +
                    "\n".join(json.dumps(row, ensure_ascii=False) for row in jump["xrefs"]))
        except Exception as error:
            text = f"Cannot resolve citation: {error}"
        self.report_detail.delete("1.0", "end")
        self.report_detail.insert("1.0", text)

    def _report_to_lab(self):
        if not self.current_folder:
            return
        evidence = getattr(self, "selected_evidence", None)
        if evidence:
            try:
                jump = evidence_jump(self.current_folder, evidence)
                address = str(jump.get("address", "")).lower().removeprefix("0x")
                row = next((row for row in coverage_rows(self.current_folder)
                            if str(row["address"]).lower().removeprefix("0x") == address), None)
                if row:
                    self.lab_function.set(f"{row['name']} @ {row['address']}")
            except Exception:
                pass
        self.show_page("lab")

    def _save_finding_triage(self):
        if not self.selected_finding or not self.current_folder:
            return
        try:
            save_triage(self.current_folder, self.selected_finding,
                        self.triage_status.get(), self.triage_note.get(),
                        self.triage_actor.get(), self.triage_assignee.get())
            self.status_text.set("FINDING TRIAGE SAVED")
            self._select_report_finding(self.selected_finding)
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _save_suppression(self):
        if not self.selected_finding or not self.current_folder:
            return
        try:
            set_suppression(self.current_folder, self.selected_finding, self.suppression_reason.get(),
                            self.suppression_expiry.get(), self.triage_actor.get())
            self._refresh_suppression_report()
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _clear_suppression(self):
        if not self.selected_finding or not self.current_folder:
            return
        try:
            clear_suppression(self.current_folder, self.selected_finding, self.triage_actor.get())
            self._refresh_suppression_report()
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _refresh_suppression_report(self):
        sarif = self.current_folder / "security-report.sarif"
        if sarif.is_file() and self.report_run.get() == "Current":
            write_sarif(sarif, self.active_report, self.current_folder)
        self.status_text.set("FINDING SUPPRESSION SAVED")
        self._display_report_run(self.report_run.get())

    def _open_audit_log(self):
        path = self.current_folder / "findings-audit.jsonl" if self.current_folder else None
        if path and path.is_file():
            os.startfile(path)
        else:
            messagebox.showinfo("CastorPollux", "No triage decisions have been saved yet.")

    def _secrets_page(self):
        self._label(self.body, "REDACTED STATIC LEADS", 11, GREEN, "bold").pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Possible credentials found in saved pseudocode and strings. Confirm before acting on a lead.",
                    13, MUTED, wraplength=850).pack(anchor="w", pady=(0, 10))
        row = ctk.CTkFrame(self.body, fg_color="transparent")
        row.pack(fill="x", pady=(0, 10))
        self._button(row, "CHOOSE INVESTIGATION", self._browse_secrets_folder, 185, True).pack(side="left")
        self._button(row, "RESCAN EVIDENCE", self._rescan_secrets, 155).pack(side="left", padx=8)
        self._label(self.body, str(self.current_folder or "No investigation selected"), 10, MUTED,
                    mono=True).pack(anchor="w", pady=(0, 8))
        self.secret_results = ctk.CTkScrollableFrame(self.body, fg_color=CARD, height=360)
        self.secret_results.pack(fill="both", expand=True)
        self._render_secrets()

    def _browse_secrets_folder(self):
        folder = filedialog.askdirectory(title="Choose a saved investigation")
        if folder:
            try:
                read_manifest(Path(folder))
                self.current_folder = Path(folder)
                self.show_page("secrets")
            except Exception as error:
                messagebox.showerror("CastorPollux", str(error))

    def _rescan_secrets(self):
        if not self.current_folder:
            return
        def task():
            self._emit("secret_scan", scan_secrets(self.current_folder))
        self._start_task(task)

    def _render_secrets(self):
        for child in self.secret_results.winfo_children():
            child.destroy()
        path = self.current_folder / "secret-evidence.json" if self.current_folder else None
        try:
            report = json.loads(path.read_text(encoding="utf-8")) if path and path.is_file() else None
        except (OSError, ValueError):
            report = None
        if report is None:
            self._label(self.secret_results, "No scan saved. Choose RESCAN EVIDENCE.", 12, MUTED).pack(pady=12)
            return
        self._label(self.secret_results, f"{report['count']} candidate lead(s). Complete values are not stored here.",
                    12, GREEN, "bold").pack(anchor="w", padx=12, pady=10)
        for lead in report.get("leads", [])[:200]:
            color = RED if lead["confidence"] == "high" else CYAN
            card = self._card(self.secret_results)
            card.pack(fill="x", padx=7, pady=4)
            self._label(card, f"{lead['confidence'].upper()}  {lead['type']}", 12, color, "bold").pack(
                anchor="w", padx=12, pady=(8, 2))
            self._label(card, f"{lead['file']}:{lead['line']}  •  {lead['preview']}  •  SHA-256 {lead['value_sha256'][:16]}…",
                        10, MUTED, mono=True).pack(anchor="w", padx=12, pady=(0, 8))

    def _settings_page(self):
        self._label(self.body, "APPEARANCE  /  SYMBOL POLICY  /  DEPENDENCIES", 11, GREEN, "bold").pack(
            anchor="w", pady=(0, 12))
        tabs = ctk.CTkTabview(self.body, height=710, fg_color=BG,
                              segmented_button_fg_color=FIELD, segmented_button_selected_color=GREEN,
                              segmented_button_selected_hover_color=CYAN,
                              segmented_button_unselected_color=FIELD, text_color=TEXT)
        tabs.pack(fill="x", expand=True)
        for name in ("Appearance", "Symbols", "Engines", "Shortcuts"):
            tabs.add(name)
        self.settings_tabs = tabs
        card = self._card(tabs.tab("Appearance"))
        card.pack(fill="x", pady=(0, 12))
        self._label(card, "THEME", 12, CYAN, "bold").pack(anchor="w", padx=16, pady=(14, 6))
        ctk.CTkOptionMenu(card, variable=self.theme_choice, values=list(THEMES), width=250,
                          fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(anchor="w", padx=16, pady=(0, 14))
        self._label(card, "Daylight is the daytime palette; High Contrast uses bold light-on-dark colors.",
                    11, MUTED).pack(anchor="w", padx=16, pady=(0, 10))
        appearance = ctk.CTkFrame(card, fg_color="transparent")
        appearance.pack(fill="x", padx=16, pady=(0, 12))
        self._label(appearance, "TEXT SIZE", 11, TEXT, "bold").pack(side="left", padx=(0, 9))
        ctk.CTkOptionMenu(appearance, variable=self.font_scale_choice,
                          values=["85", "100", "115", "130", "150"], width=90,
                          fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(side="left")
        self._label(appearance, "%  •  Rebuilds the interface when saved", 11, MUTED).pack(side="left", padx=9)
        layout_row = ctk.CTkFrame(card, fg_color="transparent")
        layout_row.pack(fill="x", padx=16, pady=(0, 12))
        self._label(layout_row, "PANE LAYOUT", 11, TEXT, "bold").pack(side="left", padx=(0, 9))
        ctk.CTkOptionMenu(layout_row, variable=self.layout_choice,
                          values=list(self.settings["layout_presets"]), width=170,
                          fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(side="left")
        self._button(layout_row, "SAVE CURRENT SPLIT", self._save_current_layout, 175).pack(side="left", padx=9)
        self._label(card, "Resize a sash in Investigations, Evidence Lab, or Findings, then save its position as a preset.",
                    11, MUTED).pack(anchor="w", padx=16, pady=(0, 10))
        ctk.CTkCheckBox(card, text="Notify me when a long scan finishes", variable=self.desktop_notifications,
                        fg_color=GREEN, text_color=TEXT).pack(anchor="w", padx=16, pady=(0, 10))
        ctk.CTkCheckBox(card, text="Reopen selected tabs from the last session (optional)",
                        variable=self.restore_tabs_choice, fg_color=GREEN, text_color=TEXT).pack(
            anchor="w", padx=16, pady=(0, 10))
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(anchor="w", padx=16, pady=(0, 12))
        self._label(row, "Minimum scan duration (seconds)", 11, TEXT).pack(side="left")
        ctk.CTkEntry(row, textvariable=self.notification_min_seconds, width=80,
                     fg_color=FIELD, text_color=TEXT).pack(side="left", padx=9)
        self._button(card, "SAVE SETTINGS", self._save_settings, 150, True).pack(anchor="w", padx=16, pady=(0, 16))
        card = self._card(tabs.tab("Symbols"))
        card.pack(fill="x", pady=(0, 12))
        self._label(card, "APPROVED HTTPS SYMBOL SERVERS  •  ONE URL PER LINE", 12, CYAN, "bold").pack(
            anchor="w", padx=16, pady=(14, 5))
        self.allowed_servers_box = ctk.CTkTextbox(card, height=85, fg_color=FIELD, text_color=TEXT,
                                                   font=self._font(11, mono=True))
        self.allowed_servers_box.pack(fill="x", padx=16)
        self.allowed_servers_box.insert("1.0", self.allowed_servers.get())
        self.allowed_servers_box.bind("<KeyRelease>", lambda _event: self._refresh_settings_dirty())
        inner_servers = self.allowed_servers_box._textbox
        inner_servers.edit_modified(False)
        def servers_modified(_event):
            if inner_servers.edit_modified():
                inner_servers.edit_modified(False)
                self._refresh_settings_dirty()
        inner_servers.bind("<<Modified>>", servers_modified, add="+")
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=12)
        self._label(row, "CACHE DAYS", 11, TEXT, "bold").pack(side="left")
        ctk.CTkEntry(row, textvariable=self.cache_days, width=65, fg_color=FIELD,
                     text_color=TEXT).pack(side="left", padx=(6, 18))
        self._label(row, "CACHE MiB", 11, TEXT, "bold").pack(side="left")
        ctk.CTkEntry(row, textvariable=self.cache_mb, width=75, fg_color=FIELD,
                     text_color=TEXT).pack(side="left", padx=(6, 18))
        self._button(row, "CLEAR CACHE", self._clear_symbol_cache, 130).pack(side="left")
        self._button(row, "SAVE SETTINGS", self._save_settings, 150, True).pack(side="right")
        cache = home() / "SymbolCache"
        count = sum(1 for path in cache.iterdir() if path.is_file()) if cache.is_dir() else 0
        self._label(card, f"Cached symbol files and metadata: {count}  •  {cache}", 10, MUTED,
                    mono=True).pack(anchor="w", padx=16, pady=(0, 12))
        limits = self._card(tabs.tab("Engines"))
        limits.pack(fill="x", pady=(0, 12))
        self._label(limits, "PER-ENGINE LIMITS  /  WALL TIME AND MANAGED HEAP", 12, CYAN, "bold").pack(
            anchor="w", padx=16, pady=(14, 6))
        for key, title in (("ghidra_timeout_seconds", "Ghidra time (s)"),
                           ("rea_timeout_seconds", "REA time (s)"),
                           ("ghidra_heap_mb", "Ghidra heap (MiB)"),
                           ("rea_heap_mb", "REA Node heap (MiB)")):
            line = ctk.CTkFrame(limits, fg_color="transparent")
            line.pack(anchor="w", padx=16, pady=3)
            self._label(line, title, 11, TEXT, width=170, anchor="w").pack(side="left")
            ctk.CTkEntry(line, textvariable=self.engine_limit_vars[key], width=95,
                         fg_color=FIELD, text_color=TEXT).pack(side="left")
        self._label(limits, "Heap settings limit managed memory, not total process-tree memory.",
                    10, MUTED).pack(anchor="w", padx=16, pady=(5, 10))
        self._label(tabs.tab("Engines"), "REQUIRED ENGINES AND OPTIONAL REVIEW TOOLS", 12, CYAN, "bold").pack(
            anchor="w", pady=(2, 7))
        for key in ("ghidra", "jdk", "node", "rea"):
            active = self.store.active_path(key)
            bundled = bundled_component(key)
            location = active or (bundled[1] if bundled else None)
            state = "READY" if location and location.exists() else "BUNDLED ARCHIVE • INSTALLS ON FIRST ANALYSIS" if key in {"ghidra", "jdk"} else "MISSING"
            row = self._card(tabs.tab("Engines"))
            row.pack(fill="x", pady=3)
            self._label(row, f"{key.upper()} {self.store.current_version(key)}  •  {state}", 12,
                        GREEN if state == "READY" else CYAN if "BUNDLED" in state else RED,
                        "bold").pack(anchor="w", padx=12, pady=(8, 2))
            self._label(row, str(location or resource("archives")), 10, MUTED, mono=True).pack(
                anchor="w", padx=12, pady=(0, 8))
        for name in ("codex", "claude", "opencode"):
            executable = find_agent_cli(name)
            self._label(tabs.tab("Engines"), f"{name.upper()}: " + (str(executable) if executable else "not detected (optional)"),
                        11, GREEN if executable else MUTED).pack(anchor="w", pady=2)
        self._label(tabs.tab("Engines"), "RETDEC: " + (str(find_retdec()) if find_retdec() else "not detected (optional)"),
                    11, MUTED).pack(anchor="w", pady=2)
        self._label(tabs.tab("Engines"), "WINDOWS SANDBOX: UNTESTED optional runtime trace", 11, RED, "bold").pack(
            anchor="w", pady=(3, 8))
        self._button(tabs.tab("Engines"), "CHECK ENGINE COMPATIBILITY", self._check_engine_compatibility, 245).pack(anchor="w", pady=6)
        self._button(tabs.tab("Engines"), "OPEN ERROR LOG", self._open_global_errors, 160).pack(anchor="w", pady=8)
        shortcut_panel = self._card(tabs.tab("Shortcuts"))
        shortcut_panel.pack(fill="x", pady=(0, 12))
        self._label(shortcut_panel, "CUSTOM KEYBOARD SHORTCUTS", 12, CYAN, "bold").pack(
            anchor="w", padx=16, pady=(14, 5))
        self._label(shortcut_panel, "Enter Tk key sequences such as <Control-k> or <F1>. Each action needs a unique shortcut.",
                    11, MUTED, wraplength=680, justify="left").pack(anchor="w", padx=16, pady=(0, 9))
        for action, variable in self.shortcut_vars.items():
            line = ctk.CTkFrame(shortcut_panel, fg_color="transparent")
            line.pack(fill="x", padx=16, pady=3)
            self._label(line, action, 11, TEXT, width=190, anchor="w").pack(side="left")
            ctk.CTkEntry(line, textvariable=variable, width=190, fg_color=FIELD,
                         text_color=TEXT, font=self._font(11, mono=True)).pack(side="left")
        self.shortcut_check_label = self._label(shortcut_panel, "", 11, MUTED)
        self.shortcut_check_label.pack(anchor="w", padx=16, pady=(8, 5))
        actions = ctk.CTkFrame(shortcut_panel, fg_color="transparent")
        actions.pack(anchor="w", padx=16, pady=(0, 16))
        self._button(actions, "CHECK CONFLICTS", self._check_shortcuts, 160).pack(side="left")
        self._button(actions, "RESTORE DEFAULTS", self._restore_default_shortcuts, 165).pack(side="left", padx=8)
        self._button(actions, "SAVE SETTINGS", self._save_settings, 150, True).pack(side="left")
        self._check_shortcuts()

    def _check_shortcuts(self):
        try:
            selected = {name: variable.get() for name, variable in self.shortcut_vars.items()}
            validate_shortcuts(selected)
            self.shortcut_check_label.configure(text="No conflicts. All shortcuts are valid.", text_color=GREEN)
            return True
        except ValueError as error:
            self.shortcut_check_label.configure(text=str(error), text_color=RED)
            return False

    def _restore_default_shortcuts(self):
        for action, sequence in SHORTCUT_ACTIONS.items():
            self.shortcut_vars[action].set(sequence)
        self._check_shortcuts()

    def _check_engine_compatibility(self):
        def task():
            from castorpollux_preflight import engine_compatibility
            paths = self.store.analysis_paths(lambda message: self._emit("log", message), self.cancel_event.is_set)
            self._emit("engine_compatibility", engine_compatibility(self.store, paths))
        self._start_task(task)

    def _save_settings(self):
        try:
            servers = [line.strip() for line in self.allowed_servers_box.get("1.0", "end-1c").splitlines() if line.strip()]
            saved = save_settings({"theme": self.theme_choice.get(), "symbol_servers": servers,
                                   "symbol_cache_days": self.cache_days.get(), "symbol_cache_mb": self.cache_mb.get(),
                                   "desktop_notifications": self.desktop_notifications.get(),
                                   "restore_tabs": self.restore_tabs_choice.get(),
                                   "notification_min_seconds": self.notification_min_seconds.get(),
                                   "font_scale": self.font_scale_choice.get(),
                                   "shortcuts": {name: variable.get() for name, variable in self.shortcut_vars.items()},
                                   "layout_presets": self.settings["layout_presets"],
                                   "active_layout": self.layout_choice.get(),
                                   **{key: variable.get() for key, variable in self.engine_limit_vars.items()}})
            old_theme = self.settings["theme"]
            old_scale = self.settings["font_scale"]
            self._remember_page_tab()
            self.settings = saved
            self.allowed_servers.set("\n".join(saved["symbol_servers"]))
            self._bind_shortcuts()
            self._set_dirty("Settings", False)
            self._schedule_draft_save()
            self.font_scale = saved["font_scale"] / 100
            ctk.ThemeManager.theme["CTkFont"]["size"] = round(13 * self.font_scale)
            self.last_split_ratio = saved["layout_presets"][saved["active_layout"]]
            self.status_text.set("SETTINGS SAVED")
            if saved["theme"] != old_theme or saved["font_scale"] != old_scale:
                apply_palette(saved["theme"])
                self.configure(fg_color=BG)
                for child in self.winfo_children():
                    child.destroy()
                self._layout()
                self.show_page("settings")
            else:
                self.show_page("settings")
        except Exception as error:
            messagebox.showerror("CastorPollux", str(error))

    def _clear_symbol_cache(self):
        cache = home() / "SymbolCache"
        if cache.is_dir():
            for path in cache.iterdir():
                if path.is_file() and path.suffix in {".pdb", ".debug", ".json", ".download"}:
                    path.unlink()
        self.show_page("settings")

    def _open_global_errors(self):
        path = home() / "Logs" / "castorpollux-errors.jsonl"
        if path.is_file():
            os.startfile(path)
        else:
            messagebox.showinfo("CastorPollux", "No application errors have been recorded.")

    def _updates_page(self):
        self._label(self.body, "OFFICIAL SOURCES  /  VERIFIED DOWNLOADS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Check for releases, then install and activate analysis components here.",
                    14, MUTED).pack(anchor="w", pady=(0, 18))
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 14))
        self.check_button = self._button(controls, "↻  CHECK UPDATES", self._check_updates, 165, True)
        self.check_button.pack(side="left")
        self.all_button = self._button(controls, "UPDATE ALL", self._update_all, 132)
        self.all_button.pack(side="left", padx=9)
        self.update_cancel = self._button(controls, "CANCEL", self._cancel, 95)
        self.update_cancel.pack(side="left")
        self.update_cancel.configure(state="normal" if self.busy else "disabled")
        self._button(controls, "EXPORT INVENTORY", self._export_inventory, 165).pack(side="right")
        self._button(controls, "APP SIGNATURE", self._check_app_signature, 145).pack(side="right", padx=(0, 8))
        self._label(self.body, "GHIDRA + JAVA  •  REA + NODE.JS", 11, CYAN, "bold").pack(
            anchor="w", pady=(0, 7))
        grid = ctk.CTkFrame(self.body, fg_color="transparent")
        grid.pack(fill="x")
        grid.grid_columnconfigure((0, 1), weight=1, uniform="component")
        self.update_rows = {}
        labels = {"ghidra": ("GHIDRA", "Decompiler & project engine"),
                  "jdk": ("TEMURIN JDK", "Java runtime for Ghidra"),
                  "rea": ("REA", "Evidence & analysis CLI"),
                  "node": ("NODE.JS", "Runtime for REA")}
        for index, key in enumerate(("ghidra", "jdk", "rea", "node")):
            card = self._card(grid)
            card.grid(row=index // 2, column=index % 2, sticky="nsew", padx=5, pady=5)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=17, pady=(13, 4))
            self._label(top, labels[key][0], 14, TEXT, "bold", True).pack(side="left")
            button = self._button(top, "UPDATE", lambda k=key: self._update_one(k), 90)
            button.pack(side="right")
            rollback = self._button(top, "ROLL BACK", lambda k=key: self._rollback_component(k), 95)
            rollback.pack(side="right", padx=(0, 7))
            health = self._button(top, "HEALTH", lambda k=key: self._health_component(k), 80)
            health.pack(side="right", padx=(0, 7))
            detail = self._label(card, "", 11, MUTED, mono=True)
            detail.pack(anchor="w", padx=17, pady=(0, 4))
            self._label(card, labels[key][1], 11, MUTED).pack(anchor="w", padx=17, pady=(0, 12))
            self.update_rows[key] = (detail, button, health, rollback)
        self._label(self.body, "UPDATE ACTIVITY", 11, MUTED, "bold", True).pack(anchor="w", pady=(10, 5))
        self._activity_panel(self.body, height=160)
        self._refresh_versions()

    def _content_file(self, name):
        if name != "help.html":
            raise ValueError("Unknown content file")
        target = home() / "Content" / name
        if not target.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(resource("content", name), target)
        return target

    def _render_content(self, box, source):
        render_html(box, source,
                    lambda size, bold=False, mono=False: self._tk_font(size, bold=bold, mono=mono),
                    {"accent": GREEN, "secondary": CYAN, "text": TEXT, "muted": MUTED})

    def _about_page(self):
        source = resource("content", "about.html").read_text(encoding="utf-8")
        about_brand = ctk.CTkFrame(self.body, fg_color="transparent")
        about_brand.pack(fill="x", pady=(0, 10))
        self.about_brand_mark = ctk.CTkImage(Image.open(resource("assets", "castorpollux-gemini.png")), size=(84, 84))
        ctk.CTkLabel(about_brand, text="", image=self.about_brand_mark, width=84, height=84).pack(side="left")
        self._label(about_brand, "CastorPollux", 28, TEXT, "bold").pack(side="left", padx=(12, 0))
        self._label(self.body, "PURPOSE  /  PIPELINE  /  LIMITS", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "What CastorPollux does, what the agent receives, and what the results mean.",
                    14, MUTED).pack(anchor="w", pady=(0, 12))
        self.about_view = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                          corner_radius=10, text_color=TEXT, font=self._font(16),
                                          scrollbar_button_color=FIELD, wrap="word")
        self.about_view.pack(fill="both", expand=True)
        self._render_content(self.about_view, source)

    def _help_page(self):
        path = self._content_file("help.html")
        self._label(self.body, "COMPLETE USER GUIDE", 11, GREEN, mono=True).pack(anchor="w", pady=(0, 8))
        self._label(self.body, "Choose a topic or read the full guide.",
                    14, MUTED).pack(anchor="w", pady=(0, 12))
        raw = path.read_text(encoding="utf-8")
        self.help_sections = help_sections(raw)
        controls = ctk.CTkFrame(self.body, fg_color="transparent")
        controls.pack(fill="x", pady=(0, 8))
        self.help_topic = ctk.StringVar(value="All topics")
        ctk.CTkOptionMenu(controls, variable=self.help_topic, values=list(self.help_sections),
                          command=self._show_help_topic, width=240, fg_color=FIELD, button_color=LINE,
                          text_color=TEXT).pack(side="left")
        search = ctk.CTkEntry(controls, textvariable=self.help_search, width=250,
                              placeholder_text="Search this guide", fg_color=FIELD,
                              text_color=TEXT, font=self._font(12))
        search.pack(side="left", padx=8)
        search.bind("<KeyRelease>", lambda _event: self._show_help_topic("All topics"))
        self._button(controls, "RELOAD", lambda: self.show_page("help"), 95).pack(side="left", padx=8)
        self._button(controls, "OPEN HTML FILE", lambda: os.startfile(path), 150).pack(side="right")
        examples = ctk.CTkFrame(self.body, fg_color="transparent")
        examples.pack(fill="x", pady=(0, 9))
        self._label(examples, "EXAMPLES", 11, CYAN, "bold").pack(side="left", padx=(0, 8))
        for label, topic in (("First scan", "Start here"),
                             ("Agent review", "Agent review"),
                             ("REA", "REA actions and console"),
                             ("Troubleshooting", "Troubleshooting")):
            self._button(examples, label, lambda t=topic: self._show_help_topic(t), 115).pack(side="left", padx=3)
        self.help_box = ctk.CTkTextbox(self.body, fg_color=SIDEBAR, border_width=1, border_color=LINE,
                                        corner_radius=10, text_color=TEXT, font=self._font(14),
                                        scrollbar_button_color=FIELD, wrap="word")
        self.help_box.pack(fill="both", expand=True)
        self._show_help_topic("All topics")

    def _show_help_topic(self, topic):
        if topic in self.help_sections:
            self.help_topic.set(topic)
        source = self.help_sections.get(topic, "")
        query = self.help_search.get().casefold().strip()
        if query:
            matches = [section for title, section in self.help_sections.items() if title != "All topics" and
                       query in (title + " " + plain_text(section)).casefold()]
            source = "\n".join(matches) if matches else "<h2>No matching topics</h2><p>Try another word.</p>"
        self._render_content(self.help_box, source)

    def _credits_page(self):
        intro = ctk.CTkFrame(self.body, fg_color="transparent")
        intro.pack(fill="x", pady=(0, 12))
        self._label(intro, "PROJECTS AND SOURCES", 13, GREEN, "bold").pack(anchor="w", pady=(0, 4))
        self._label(intro, "CastorPollux combines these projects. Open the complete license texts and notices for redistribution details.",
                    15, MUTED, wraplength=1100, justify="left").pack(anchor="w")
        self._button(self.body, "↗  OPEN FULL NOTICES", self._open_notices, 205, True).pack(anchor="w", pady=(0, 12))
        search = ctk.CTkEntry(self.body, textvariable=self.credits_search,
                              placeholder_text="Search project or license…", fg_color=FIELD,
                              text_color=TEXT, font=self._font(14))
        search.pack(fill="x", pady=(0, 8))
        search.bind("<KeyRelease>", lambda _event: self._render_credits())
        self.credits_count = self._label(self.body, "", 12, MUTED)
        self.credits_count.pack(anchor="w", pady=(0, 5))
        self.credits_results = ctk.CTkScrollableFrame(self.body, fg_color="transparent",
                                                       scrollbar_button_color=GREEN)
        self.credits_results.pack(fill="both", expand=True)
        sources = [
            ("REA", "morluto/rea • MIT", "https://github.com/morluto/rea"),
            ("GHIDRA", "National Security Agency • Apache 2.0", "https://github.com/NationalSecurityAgency/ghidra"),
            ("TEMURIN JDK", "Eclipse Adoptium • GPLv2 with Classpath Exception", "https://adoptium.net/"),
            ("NODE.JS", "OpenJS Foundation & contributors", "https://nodejs.org/"),
            ("CUSTOMTKINTER", "Tom Schimansky • MIT", "https://github.com/TomSchimansky/CustomTkinter"),
            ("PNPM", "pnpm contributors • MIT", "https://pnpm.io/"),
            ("PYTHON", "Python Software Foundation • PSF License", "https://www.python.org/"),
            ("PYINSTALLER", "PyInstaller contributors • GPL with bootloader exception", "https://pyinstaller.org/"),
            ("REPORTLAB", "ReportLab Inc. • BSD-style", "https://www.reportlab.com/"),
            ("PILLOW", "Pillow contributors • MIT-CMU", "https://python-pillow.github.io/"),
            ("CHARSET-NORMALIZER", "Contributors • MIT", "https://github.com/jawah/charset_normalizer"),
            ("DARKDETECT", "Albertosottile • BSD 3-Clause", "https://github.com/albertosottile/darkdetect"),
            ("PACKAGING", "Python Packaging Authority • Apache 2.0 or BSD 2-Clause", "https://github.com/pypa/packaging"),
            ("CODEX CLI", "Optional OpenAI tool; separate installation", "https://developers.openai.com/codex"),
            ("CLAUDE CODE CLI", "Optional Anthropic tool; separate installation", "https://code.claude.com/docs/en/cli-reference"),
            ("OPENCODE CLI", "Optional OpenCode tool; separate installation", "https://opencode.ai/docs/cli/"),
            ("OLLAMA", "Optional local model server; separate installation", "https://ollama.com/"),
            ("RETDEC", "Optional independent decompiler; separate installation", "https://github.com/avast/retdec"),
            ("WINDOWS SANDBOX", "Optional isolated runtime environment; Windows feature", "https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file"),
        ]
        self.credit_sources = sources
        self._render_credits()
        self.body.bind("<Configure>", lambda _event: self._resize_credits())

    def _credit_columns(self):
        usable = max(0, self.winfo_width() - 270)
        return 3 if usable >= 1050 * self.font_scale else 2 if usable >= 650 * self.font_scale else 1

    def _resize_credits(self):
        if self.page_name == "credits" and getattr(self, "credits_columns", None) != self._credit_columns():
            self._render_credits()

    def _render_credits(self):
        for child in self.credits_results.winfo_children():
            child.destroy()
        columns = self._credit_columns()
        self.credits_columns = columns
        term = self.credits_search.get().casefold().strip()[:100]
        matches = [(index, row) for index, row in enumerate(self.credit_sources)
                   if term in (row[0] + " " + row[1]).casefold()]
        self.credits_count.configure(text=f"{len(matches)} OF {len(self.credit_sources)} SOURCES")
        if not matches:
            self._label(self.credits_results, "No matching projects or licenses.", 14, MUTED).pack(anchor="w", pady=12)
            return
        for heading, group in (("BUNDLED COMPONENTS", [row for index, row in matches if index < 13]),
                               ("OPTIONAL TOOLS AND WINDOWS FEATURES", [row for index, row in matches if index >= 13])):
            if not group:
                continue
            self._label(self.credits_results, heading, 13, CYAN, "bold").pack(anchor="w", pady=(8, 8))
            grid = ctk.CTkFrame(self.credits_results, fg_color="transparent")
            grid.pack(fill="x")
            grid.grid_columnconfigure(tuple(range(columns)), weight=1, uniform="credits")
            for index, (name, license_text, url) in enumerate(group):
                card = self._card(grid)
                card.grid(row=index // columns, column=index % columns, sticky="nsew", padx=5, pady=5)
                self._label(card, name, 16, CYAN, "bold").pack(anchor="w", padx=14, pady=(10, 4))
                self._label(card, license_text, 14, TEXT, wraplength=350, justify="left").pack(
                    anchor="w", padx=14, pady=(0, 7))
                actions = ctk.CTkFrame(card, fg_color="transparent")
                actions.pack(anchor="w", padx=14, pady=(0, 10))
                self._button(actions, "LICENSE DETAILS", lambda n=name, d=license_text, u=url:
                             self._open_license_details(n, d, u), 130).pack(side="left")
                self._button(actions, "OPEN PROJECT ↗", lambda link=url: webbrowser.open(link), 125).pack(
                    side="left", padx=(7, 0))

    def _open_license_details(self, name, description, url):
        base = self._credits_root().joinpath("CastorPollux-Licenses").resolve()
        parts = [name, description, url, ""]
        filenames = CREDIT_LICENSE_FILES.get(name, ())
        if not filenames:
            parts.append("This optional tool is installed separately. Its license is not bundled with CastorPollux; check its project for current terms.")
        else:
            try:
                for filename in filenames:
                    path = (base / filename).resolve()
                    if not path.is_relative_to(base) or not path.is_file() or path.stat().st_size > 2_000_000:
                        raise ValueError("Bundled license file is missing or unexpectedly large")
                    parts.extend((f"\n===== {filename} =====\n", path.read_text(encoding="utf-8", errors="replace")))
            except (OSError, ValueError) as error:
                messagebox.showerror("CastorPollux", f"Cannot read bundled license: {error}")
                return
        window = ctk.CTkToplevel(self)
        window.title(f"CastorPollux | {name} license details")
        window.geometry("1000x760")
        window.transient(self)
        self._label(window, name, 21, GREEN, "bold").pack(anchor="w", padx=20, pady=(16, 6))
        viewer = ctk.CTkTextbox(window, fg_color=SIDEBAR, text_color=TEXT,
                                 font=self._font(13, mono=True), wrap="word")
        viewer.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        viewer.insert("1.0", "\n".join(parts))
        viewer.configure(state="disabled")
        window.lift()
        window.focus_force()
        window.grab_set()

    def _browse_input(self):
        path = filedialog.askopenfilename(title="Choose a binary")
        if path:
            self._select_input_file(path)

    def _select_input_file(self, value):
        if self.busy:
            self.status_text.set("TASK RUNNING — FINISH OR CANCEL BEFORE SELECTING ANOTHER BINARY")
            return
        path = first_regular_file([value])
        if path is None:
            messagebox.showerror("CastorPollux", "Choose a regular binary file; folders cannot be scanned directly.")
            return
        self.input_path.set(str(path))
        self.scan_stage_text.set("Selected " + path.name + ". Choose Analyze when ready.")
        self.status_text.set("BINARY SELECTED")
        if self.page_name != "analyze":
            self.show_page("analyze")

    def _receive_dropped_files(self, paths):
        files = [Path(value).expanduser().resolve() for value in paths if Path(value).expanduser().is_file()]
        files = list(dict.fromkeys(files))
        if not files:
            self.status_text.set("DROP A FILE, NOT A FOLDER")
            return
        if len(files) > 1 or self.busy:
            self.batch_sources = list(dict.fromkeys([*self.batch_sources, *(str(path) for path in files)]))
            self._schedule_draft_save()
            self.status_text.set(f"{len(files)} FILE(S) ADDED TO BATCH QUEUE")
            self._log(f"Queued {len(files)} dropped binary file(s) for batch analysis.")
            if not self.busy:
                self.show_page("batch")
            elif self.page_name == "batch":
                self._render_batch_sources()
            return
        self._select_input_file(files[0])
        self._log(f"Selected dropped binary: {files[0].name}")

    def _install_file_drop(self):
        if getattr(self, "file_drop", None) is not None:
            return
        try:
            self.file_drop = WindowsFileDrop(self, [], self._receive_dropped_files)
        except Exception as error:
            self._log("Drag and drop is unavailable; BROWSE FILE remains available. " + str(error))

    def _poll_drop_hover(self):
        """Give shell drags a visual target while Explorer owns mouse capture."""
        if os.name == "nt" and self.page_name == "analyze" and hasattr(self, "drop_hint"):
            try:
                if self.drop_hint.winfo_exists():
                    class POINT(ctypes.Structure):
                        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
                    user = ctypes.WinDLL("user32", use_last_error=True)
                    point = POINT()
                    user.GetCursorPos(ctypes.byref(point))
                    down = bool(user.GetAsyncKeyState(1) & 0x8000)
                    x, y = self.drop_hint.winfo_rootx(), self.drop_hint.winfo_rooty()
                    inside = x <= point.x < x + self.drop_hint.winfo_width() and \
                             y <= point.y < y + self.drop_hint.winfo_height()
                    highlighted = bool(down and inside and not self.busy)
                    if highlighted != getattr(self, "_drop_highlighted", False):
                        self.drop_hint.configure(border_color=GREEN if highlighted else LINE,
                                                 fg_color=CARD if highlighted else FIELD)
                        self._drop_highlighted = highlighted
            except (OSError, tk.TclError):
                pass
        if self.winfo_exists():
            self.after(150, self._poll_drop_hover)

    def _load_bookmarks(self):
        try:
            rows = json.loads(self.bookmark_path.read_text(encoding="utf-8"))
            return [row for row in rows if isinstance(row, dict) and row.get("id") and row.get("text")][-500:]
        except (OSError, ValueError, TypeError):
            return []

    def _save_bookmarks(self):
        self.bookmark_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.bookmark_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.bookmarks[-500:], indent=2), encoding="utf-8")
        os.replace(temporary, self.bookmark_path)

    def _activity_panel(self, parent, height=240):
        controls = ctk.CTkFrame(parent, fg_color="transparent")
        controls.pack(fill="x", pady=(3, 6))
        search = ctk.CTkEntry(controls, textvariable=self.activity_search,
                              placeholder_text="Search activity", fg_color=FIELD, border_color=LINE,
                              text_color=TEXT, width=230)
        search.pack(side="left", fill="x", expand=True)
        search.bind("<KeyRelease>", lambda _event: self._render_activity())
        self.activity_search_box = search
        ctk.CTkOptionMenu(controls, variable=self.activity_filter,
                          values=["All", "Errors", "Warnings", "Stages", "Bookmarked"],
                          command=lambda _value: self._render_activity(), width=130,
                          fg_color=FIELD, button_color=LINE, text_color=TEXT).pack(side="left", padx=7)
        self._button(controls, "☆ BOOKMARK LINE", self._bookmark_selected_log, 155).pack(side="left")
        self.log_box = ctk.CTkTextbox(parent, height=height, fg_color=SIDEBAR,
                                      border_width=1, border_color=LINE, text_color=GREEN,
                                      font=self._font(11, mono=True), scrollbar_button_color=FIELD)
        self.log_box.pack(fill="both", expand=True)
        self._install_log_menu(self.log_box, bookmarks=True)
        self._render_activity()

    def _render_activity(self):
        if not getattr(self, "log_box", None) or not self.log_box.winfo_exists():
            return
        self.log_visible_records = filter_activity(self.log_records, self.activity_search.get(),
                                                    self.activity_filter.get())[-2000:]
        box = self.log_box
        box.delete("1.0", "end")
        if not self.log_visible_records:
            box.insert("end", "No matching activity.\n")
        else:
            for row in self.log_visible_records:
                mark = "★ " if row.get("bookmarked") else "  "
                box.insert("end", f"{mark}{row['time']}  {row['text']}\n")
        box.see("end")

    def _bookmark_selected_log(self):
        if not getattr(self, "log_box", None) or not self.log_box.winfo_exists():
            return
        index = int(self.log_box._textbox.index("insert").split(".")[0]) - 1
        if not 0 <= index < len(self.log_visible_records):
            return
        row = self.log_visible_records[index]
        bookmark_id = row["id"]
        if row.get("bookmarked"):
            row["bookmarked"] = False
            self.bookmarks = [item for item in self.bookmarks if item["id"] != bookmark_id]
        else:
            row["bookmarked"] = True
            self.bookmarks.append({key: row[key] for key in ("id", "time", "text", "source")})
        self._save_bookmarks()
        self._render_activity()

    def _install_log_menu(self, box, bookmarks=False):
        widget = box._textbox
        menu = tk.Menu(widget, tearoff=False, bg=FIELD, fg=TEXT,
                       activebackground=LINE, activeforeground=TEXT)
        selection = {"text": ""}
        def copy_selected():
            if selection["text"]:
                self.clipboard_clear()
                self.clipboard_append(selection["text"])
        def copy_all():
            self.clipboard_clear()
            self.clipboard_append(box.get("1.0", "end-1c"))
        def select_all():
            widget.tag_add("sel", "1.0", "end-1c")
            widget.focus_set()
        menu.add_command(label="Copy selected", command=copy_selected)
        menu.add_command(label="Copy all", command=copy_all)
        if bookmarks:
            menu.add_command(label="Bookmark / unbookmark line", command=self._bookmark_selected_log)
        menu.add_separator()
        menu.add_command(label="Select all", command=select_all)
        def open_menu(event):
            if bookmarks:
                widget.mark_set("insert", f"@{event.x},{event.y}")
            try:
                selection["text"] = box.get("sel.first", "sel.last")
            except tk.TclError:
                selection["text"] = ""
            menu.entryconfigure(0, state="normal" if selection["text"] else "disabled")
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
            return "break"
        widget.bind("<Button-3>", open_menu, add="+")
        box._castorpollux_context_menu = menu

    def _browse_symbols(self):
        path = filedialog.askopenfilename(title="Choose optional local PDB or DWARF debug file",
                                          filetypes=[("Debug symbols", "*.pdb *.debug *.dbg *.elf"), ("All files", "*.*")])
        if path:
            self.symbol_path.set(path)

    def _browse_output(self):
        path = filedialog.askdirectory(title="Choose output folder")
        if path:
            self.output_path.set(path)

    def _log(self, line):
        now = time.strftime("%H:%M:%S")
        source = str(self.current_folder) if self.current_folder else "session"
        added = []
        for part in str(line).splitlines() or [""]:
            row = {"id": uuid.uuid4().hex, "time": now, "text": part,
                   "kind": activity_kind(part), "source": source, "bookmarked": False}
            self.log_records.append(row)
            added.append(row)
        if len(self.log_records) > 10000:
            keep = [row for row in self.log_records if row.get("bookmarked")] + self.log_records[-7500:]
            self.log_records = list({row["id"]: row for row in keep}.values())
        if (getattr(self, "log_box", None) and self.log_box.winfo_exists() and
                self.activity_filter.get() == "All" and not self.activity_search.get().strip() and
                len(self.log_visible_records) + len(added) <= 2000):
            if not self.log_visible_records:
                self.log_box.delete("1.0", "end")
            for row in added:
                self.log_box.insert("end", f"  {row['time']}  {row['text']}\n")
            self.log_visible_records.extend(added)
            self.log_box.see("end")
        else:
            self._render_activity()

    def _set_scan_progress(self, percent, label):
        percent = max(0, min(100, int(percent)))
        if label != self.stage_name:
            self.stage_name = label
            self.stage_started = time.monotonic()
        self.stage_percent = percent
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(percent / 100)
        self.progress_text.set(f"{percent}%")
        if self.active_task_kind == "batch":
            self.status_text.set(f"BATCH SCAN • {percent}% — {label.upper()}")
            self.scan_percent_text.set(f"{percent}%")
            self.scan_stage_text.set(label)
            self._update_scan_timing()
            return
        self.scan_percent_text.set(f"{percent}%")
        self.scan_state_text.set("SCAN COMPLETE" if percent == 100 else "SCAN RUNNING")
        self.title(f"CastorPollux  |  {'Scan complete' if percent == 100 else f'Scanning {percent}%'}")
        self.scan_stage_text.set(label)
        self.status_text.set(("SCAN COMPLETE — " if percent == 100 else f"SCAN RUNNING • {percent}% — ") +
                             label.upper())
        if self.page_name == "analyze" and self.scan_progress_bar.winfo_exists():
            self.scan_progress_bar.set(percent / 100)
            self.scan_state_label.configure(text_color=GREEN if percent == 100 else CYAN)
            self.scan_progress_bar.configure(progress_color=GREEN if percent == 100 else CYAN)
        self._update_scan_timing()

    def _update_scan_timing(self):
        if not self.task_started:
            return
        elapsed = max(0, time.monotonic() - self.task_started)
        if not self.busy or self.scan_finished:
            self.scan_timing_text.set("Elapsed " + format_duration(elapsed) + "  •  Finished")
            return
        stage_elapsed = max(0, time.monotonic() - self.stage_started) if self.stage_started else 0
        progress, remaining = stage_estimate(self.stage_name, self.stage_percent,
                                             stage_elapsed, self.stage_history.get(self.stage_name))
        self.scan_timing_text.set(f"Elapsed {format_duration(elapsed)}  •  {progress}  •  Stage ETA {remaining}")

    def _tick_scan_clock(self):
        if self.busy and self.active_task_kind in {"scan", "batch"}:
            self._update_scan_timing()
        if self.winfo_exists():
            self.after(1000, self._tick_scan_clock)

    def _emit(self, kind, value):
        self.events.put((kind, value))

    def _drain(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "log":
                    self._log(value)
                    if str(value).startswith("CASTORPOLLUX_STAGE "):
                        parts = str(value).split(" ", 2)
                        percent = max(0, min(100, int(parts[1])))
                        label = parts[2]
                        if label.startswith("Agent review"):
                            if percent < 100:
                                self.progress_bar.configure(mode="indeterminate")
                                self.progress_bar.start()
                                self.progress_text.set("REVIEWING")
                                self.status_text.set("AGENT REVIEW RUNNING — LIVE OUTPUT BELOW")
                            else:
                                self.progress_bar.stop()
                                self.progress_bar.configure(mode="determinate")
                                self.progress_bar.set(1)
                                self.progress_text.set("100%")
                                self.status_text.set("AGENT REVIEW COMPLETE")
                        else:
                            self._set_scan_progress(percent, label)
                        continue
                    if str(value).startswith("Agent live: "):
                        self.status_text.set("AGENT REVIEW RUNNING — LIVE OUTPUT BELOW")
                        continue
                    if self.active_task_kind == "scan" and not self.scan_finished:
                        self.status_text.set("SCAN RUNNING • " + self.scan_percent_text.get() +
                                             " — " + self.scan_stage_text.get().upper())
                    else:
                        self.status_text.set(str(value)[:150].upper())
                    progress = re.search(r"REA decompilation: (\d+)/(\d+) processed", str(value))
                    if progress and self.busy:
                        self.progress_bar.stop()
                        self.progress_bar.configure(mode="determinate")
                        ratio = int(progress.group(1)) / max(1, int(progress.group(2)))
                        percent = 64 + int(30 * ratio)
                        self.progress_bar.set(percent / 100)
                        self.progress_text.set(f"{percent}%")
                        self._set_scan_progress(percent, "Decompiling with REA")
                elif kind == "output":
                    self.last_output = Path(value)
                    try:
                        self.library.add(self.last_output)
                        self.current_folder = self.last_output
                    except (OSError, ValueError):
                        pass
                    if self.page_name == "analyze":
                        self.open_button.configure(state="normal")
                elif kind == "analysis_incomplete":
                    self.task_error = True
                    self.scan_state_text.set("SCAN INCOMPLETE")
                    self.scan_stage_text.set("Some engine stages stopped. Open History for logs and saved output.")
                    self.status_text.set("ANALYSIS INCOMPLETE — SEE HISTORY LOGS")
                    if self.page_name == "analyze":
                        self.scan_state_label.configure(text_color=RED)
                        self.scan_progress_bar.configure(progress_color=RED)
                    self.title("CastorPollux  |  Scan incomplete")
                    self._log(value)
                elif kind == "analysis_complete":
                    self.scan_finished = True
                    self.scan_state_text.set("SCAN COMPLETE")
                    self.scan_stage_text.set("Static analysis saved. Results are available in History.")
                    self.scan_percent_text.set("100%")
                    self._update_scan_timing()
                    if self.page_name == "analyze" and self.scan_progress_bar.winfo_exists():
                        self.scan_progress_bar.set(1)
                        self.scan_state_label.configure(text_color=GREEN)
                        self.scan_progress_bar.configure(progress_color=GREEN)
                elif kind == "agent_usage":
                    self.agent_usage_text.set(usage_label(value))
                    self._log(usage_label(value))
                elif kind == "engine_compatibility":
                    self._show_text("Engine compatibility", json.dumps(value, indent=2))
                elif kind == "recovery_preview":
                    self._open_recovery_preview(*value)
                elif kind == "recovery_needs_user":
                    folder, outcome = value
                    reason = (outcome.get("decision") or {}).get("reason") or outcome.get("reason") or \
                             "The saved engine stage is still incomplete."
                    if messagebox.askyesno("CastorPollux | Recovery needs your input",
                        f"Automatic diagnosis ended: {outcome.get('status', 'unknown')}.\n\n"
                        f"{str(reason)[:350]}\n\nOpen History to inspect logs, dependencies, and stage recovery options?"):
                        self.current_folder = Path(folder)
                        self.show_page("history")
                elif kind == "results":
                    serial, category, rows = value
                    if self.page_name == "investigations" and serial == self.search_serial:
                        self._render_results(rows, category)
                elif kind == "comparison":
                    report, destination = value
                    self.compare_destination = Path(destination)
                    if self.page_name == "compare":
                        self.compare_box.delete("1.0", "end")
                        self.compare_box.insert("end", "Comparison saved to " + destination + "\n\n" +
                            f"Functions: {len(report['functions']['added'])} added, "
                            f"{len(report['functions']['removed'])} removed, "
                            f"{len(report['functions']['changed'])} changed; "
                            f"{len(report.get('anonymous_function_matches', []))} anonymous matches\n" +
                            f"Strings: {len(report['strings']['added'])} added, "
                            f"{len(report['strings']['removed'])} removed\n" +
                            f"Imports: {len(report['imports']['added'])} added, "
                            f"{len(report['imports']['removed'])} removed\n" +
                            f"Basic blocks: {report['basic_blocks']['procedure_count']} function map(s); " +
                            f"{report['basic_blocks']['counts']['changed']} changed block pair(s)\n" +
                            f"Inferred type signatures: {report.get('type_signatures', {}).get('count', 0)} changed\n")
                        for item in report.get("anonymous_function_matches", [])[:30]:
                            self.compare_box.insert("end", f"  {item['old_entry']} → {item['new_entry']} "
                                                    f"{item['similarity']:.0%} {item['confidence']}\n")
                        if report["findings"]["status"] == "complete":
                            tracked = report["findings"]
                            self.compare_box.insert("end", f"Findings: {len(tracked['new'])} new, "
                                f"{len(tracked['recurring'])} recurring, {len(tracked['resolved'])} absent\n")
                            impact = report.get("patch_impact", {})
                            affected = [item for item in impact.get("findings", [])
                                        if item["relation"] in {"cited function changed", "called function changed", "caller changed"}]
                            self.compare_box.insert("end", f"Patch impact: {len(affected)} finding(s) linked to changed functions\n")
                            for item in affected[:40]:
                                self.compare_box.insert("end", f"  {item['severity'].upper()} {item['title']}: {item['relation']}\n")
                        else:
                            self.compare_box.insert("end", "Finding tracking: " + report["findings"]["reason"] + "\n")
                elif kind == "advanced_refresh":
                    self.status_text.set(str(value).upper())
                    if self.page_name == "advanced":
                        self._advanced_draw()
                elif kind == "call_paths":
                    self.active_call_report = value
                    self.call_path_index = 0
                    if self.page_name == "callpaths":
                        self._draw_callpath()
                elif kind == "indirect_calls":
                    if self.page_name == "callpaths":
                        self.call_detail.delete("1.0", "end")
                        self.call_detail.insert("1.0", f"{len(value['resolved'])} inferred candidate edges; "
                                                f"{len(value['unresolved'])} unresolved sites.\n\n" +
                                                "Medium: Ghidra computed-call reference. Low: import/data pointer lead.\n" +
                                                "Use FIND PATHS to include labeled candidate edges.\n\n" +
                                                json.dumps(value['resolved'][:30], indent=2))
                elif kind == "consistency":
                    if self.page_name == "coverage":
                        self._render_coverage()
                elif kind == "flow":
                    if self.page_name == "flow":
                        self.flow_box.delete("1.0", "end")
                        self._show_flow()
                elif kind == "secret_scan":
                    if self.page_name == "secrets":
                        self._render_secrets()
                elif kind == "rule_trial":
                    self.rule_trial_sha256 = value["candidate_sha256"] if value["status"] == "passed" else ""
                    if self.page_name == "flow":
                        self.flow_box.delete("1.0", "end")
                        self.flow_box.insert("1.0", json.dumps(value, indent=2))
                elif kind == "rule_activated":
                    self.rule_trial_sha256 = ""
                    self.status_text.set("FLOW RULES ENABLED AFTER CORPUS GATE")
                    if self.page_name == "flow":
                        self.flow_box.delete("1.0", "end")
                        self.flow_box.insert("1.0", json.dumps(value, indent=2))
                elif kind == "unpacked":
                    if self.page_name == "unpack":
                        for child in self.unpack_results.winfo_children():
                            child.destroy()
                        self._label(self.unpack_results, f"{len(value['files'])} components, {value.get('unique_files', len(value['files']))} unique. {value.get('bytes_saved', 0):,} duplicate bytes saved. Click a PE or ELF candidate to analyze it.",
                                    12, GREEN).pack(anchor="w", pady=8)
                        for item in value["files"]:
                            label = f"{item['format']:5}  {item['bytes']:>10} B  {item['path']}" + ("  [DUPLICATE]" if item.get("duplicate_of") else "")
                            candidate = Path(self.unpack_output.get()) / item.get("stored_path", item["path"])
                            if item["format"] in ("PE", "ELF"):
                                self._button(self.unpack_results, label,
                                             lambda path=candidate: self._select_unpacked(path), 500).pack(fill="x", pady=2)
                            else:
                                self._label(self.unpack_results, label, 11, MUTED, mono=True).pack(anchor="w")
                elif kind == "similar":
                    if self.page_name == "similar":
                        self._render_similar(value)
                elif kind == "runtime_prepared":
                    if self.page_name == "runtime":
                        self.runtime_box.delete("1.0", "end")
                        self.runtime_box.insert("1.0", "Sandbox job prepared:\n" + value +
                                                "\n\nOpen CastorPolluxTrace.wsb to inspect the isolation settings.")
                elif kind == "bundle_result":
                    if self.page_name == "bundles":
                        self.bundle_box.delete("1.0", "end")
                        self.bundle_box.insert("1.0", json.dumps(value, indent=2))
                elif kind == "bundle_imported":
                    try:
                        self.library.add(Path(value))
                        self.current_folder = Path(value)
                    except (OSError, ValueError):
                        pass
                    if self.page_name == "bundles":
                        self.bundle_box.delete("1.0", "end")
                        self.bundle_box.insert("1.0", "Verified investigation imported:\n" + value)
                elif kind in ("rea_query", "rea_console"):
                    if self.page_name == ("queries" if kind == "rea_query" else "console"):
                        path = Path(value)
                        target_box = self.query_box if kind == "rea_query" else self.console_box
                        target_box.delete("1.0", "end")
                        target_box.insert("end", f"Saved: {path}\n\n" +
                            path.read_text(encoding="utf-8-sig", errors="replace")[:300_000])
                elif kind == "libraries":
                    self._render_libraries()
                elif kind == "codex_report":
                    report, folder = value
                    self._log(f"Saved {', '.join(report['formats'])} report(s) in {folder}.")
                elif kind == "local_models":
                    models = value
                    if models:
                        if self.page_name == "codex" and self.local_model_picker.winfo_exists():
                            self.local_model_picker.configure(values=models)
                        if self.local_model.get() not in models:
                            self.local_model.set(models[0])
                        self._log(f"Local Ollama ready: {len(models)} installed model(s).")
                    else:
                        self._log("Ollama is running but has no installed models.")
                elif kind == "findings":
                    self.findings = value["components"]
                    for key, error in value["errors"].items():
                        self._log(f"{key.upper()}: update check failed: {error}")
                    self._refresh_versions()
                elif kind == "done":
                    completed_kind = self.active_task_kind
                    elapsed = time.monotonic() - self.task_started if self.task_started else 0
                    self.busy = False
                    self.cancel_event.clear()
                    self.progress_bar.stop()
                    if not self.task_error:
                        self.progress_bar.set(1)
                        self.status_text.set("SCAN COMPLETE — RESULTS SAVED" if self.active_task_kind == "scan"
                                             else "TASK COMPLETE")
                        self.progress_text.set("100%")
                    else:
                        self.progress_text.set("STOPPED")
                        if self.active_task_kind == "scan":
                            if self.scan_finished:
                                self.scan_state_text.set("SCAN COMPLETE • REVIEW STOPPED")
                                self.scan_stage_text.set("Analysis is saved; the agent review did not complete. See History logs.")
                            elif self.scan_state_text.get() != "SCAN INCOMPLETE":
                                self.scan_state_text.set("SCAN STOPPED")
                                self.scan_stage_text.set("Check the activity log and History for the failure.")
                            if self.page_name == "analyze":
                                self.scan_state_label.configure(text_color=RED)
                                self.scan_progress_bar.configure(progress_color=RED)
                            self.title("CastorPollux  |  Scan or review stopped")
                    self.active_task_kind = "idle"
                    self._update_scan_timing()
                    self._refresh_controls()
                    self.progress_bar.configure(mode="determinate")
                    self.progress_bar.set(0)
                    self.progress_text.set("READY" if not self.task_error else "STOPPED")
                    if (completed_kind in {"scan", "batch"} and self.settings["desktop_notifications"] and
                            elapsed >= self.settings["notification_min_seconds"]):
                        outcome = ("finished" if not self.task_error else
                                   "saved; agent review stopped" if self.scan_finished else "stopped with an error")
                        if not notify_windows(self, "CastorPollux scan " + outcome,
                                              f"{completed_kind.title()} finished after {format_duration(elapsed)}. Open History for results."):
                            self._log("Windows desktop notification could not be shown.")
                elif kind == "cancelled":
                    self.task_error = True
                    self.status_text.set("SCAN CANCELLED" if self.active_task_kind == "scan" else "CANCELLED")
                    self._log(value)
                elif kind == "error":
                    self.task_error = True
                    self._log("ERROR: " + str(value))
                    self.status_text.set("SCAN OR REVIEW STOPPED — SEE ACTIVITY LOG")
                    summary = str(value).splitlines()[0][:360]
                    messagebox.showerror("CastorPollux", summary +
                                         ("\n\nFull details are in the activity log and History logs."
                                          if len(str(value)) > len(summary) else ""))
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _refresh_controls(self):
        if self.page_name == "analyze":
            self.run_button.configure(state="disabled" if self.busy else "normal")
            self.pipeline_button.configure(state="disabled" if self.busy else "normal")
            self.cancel_button.configure(state="normal" if self.busy else "disabled")
        elif self.page_name == "batch":
            self.batch_button.configure(state="disabled" if self.busy else "normal")
        elif self.page_name == "updates":
            self.check_button.configure(state="disabled" if self.busy else "normal")
            self.all_button.configure(state="disabled" if self.busy else "normal")
            self.update_cancel.configure(state="normal" if self.busy else "disabled")
            self._refresh_versions()
        elif self.page_name == "compare":
            self.compare_button.configure(state="disabled" if self.busy else "normal")
        elif self.page_name == "queries":
            for button in getattr(self, "query_buttons", ()):
                if button.winfo_exists():
                    button.configure(state="disabled" if self.busy else "normal")
        elif self.page_name == "console":
            self.console_button.configure(state="disabled" if self.busy else "normal")
        elif self.page_name == "codex":
            self.review_button.configure(state="disabled" if self.busy else "normal")

    def _refresh_versions(self):
        if self.page_name != "updates":
            return
        for key, (label, button, health, rollback) in self.update_rows.items():
            current = self.store.current_version(key)
            info = self.findings.get(key)
            latest = info["version"] if info else "not checked"
            held = bool(info and not compatible_update(key, latest))
            label.configure(text=f"Installed {current}    •    Latest {latest}" +
                            ("    •    HELD: REA supports Ghidra 12.1.x" if held else ""))
            can_update = info and newer(latest, current) and not held and not self.busy
            button.configure(state="normal" if can_update else "disabled")
            health.configure(state="disabled" if self.busy else "normal")
            rollback.configure(state="normal" if self.store.rollback_targets(key) and not self.busy else "disabled")

    def _start_task(self, task, kind="task"):
        if self.busy:
            return
        self.busy = True
        self.active_task_kind = kind
        self.task_started = time.monotonic()
        self.stage_started = self.task_started
        self.stage_name = "Preparing engines" if kind == "scan" else "Batch queue" if kind == "batch" else ""
        self.stage_percent = 0
        self.task_error = False
        self.cancel_event.clear()
        if kind == "scan":
            self.scan_finished = False
            self.scan_state_text.set("SCAN RUNNING")
            self.scan_stage_text.set("Preparing analysis engines…")
            self.scan_percent_text.set("0%")
            self.scan_timing_text.set("Elapsed 0s  •  Stage running  •  Stage ETA pending")
            if self.page_name == "analyze" and self.scan_progress_bar.winfo_exists():
                self.scan_progress_bar.set(0)
                self.scan_state_label.configure(text_color=CYAN)
                self.scan_progress_bar.configure(progress_color=CYAN)
            self.title("CastorPollux  |  Scanning 0%")
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate")
            self.progress_bar.set(0)
            self.progress_text.set("0%")
            self.status_text.set("SCAN RUNNING • 0% — PREPARING ENGINES")
        else:
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self.progress_text.set("RUNNING")
            if kind == "batch":
                self.scan_stage_text.set("Preparing batch queue")
                self.scan_percent_text.set("0%")
                self.scan_timing_text.set("Elapsed 0s  •  Stage ETA pending")
        self._refresh_controls()
        def worker():
            try:
                task()
            except InterruptedError as error:
                self._emit("cancelled", str(error))
            except Exception as error:
                record_error(str(error), self.current_folder, self.page_name, traceback.format_exc())
                self._emit("error", str(error))
            finally:
                self._emit("done", None)
        threading.Thread(target=worker, daemon=True).start()

    def _set_process(self, process):
        self.process = process

    def _signal_analysis_status(self, folder):
        manifest = read_manifest(folder)
        if engine_failures(manifest):
            self._emit("analysis_incomplete", "One or more analysis stages stopped. Open History → LOGS for details.")
        else:
            self._emit("analysis_complete", str(folder))

    def _capture_agent_usage(self, folder, selected_agent=None):
        items = [read_codex_usage(find_agent_cli("codex"))]
        for name in ("claude", "opencode"):
            log = Path(folder) / f"{name}-review.log" if folder else None
            items.append(read_other_usage(name, find_agent_cli(name), log))
        usage = {"agent": "all", "items": items, "selected_agent": selected_agent}
        if folder and Path(folder).is_dir():
            try:
                (Path(folder) / "agent-usage.json").write_text(json.dumps(usage, indent=2), encoding="utf-8")
            except OSError:
                pass
        self._emit("agent_usage", usage)

    def _diagnose_with_preview(self, runner, folder):
        if not engine_failures(read_manifest(folder)):
            return {"status": "not_needed"}
        preview = diagnostic_preview(folder)
        decision = {"run": False}
        ready = threading.Event()
        self._emit("recovery_preview", (preview, decision, ready))
        while not ready.wait(0.2):
            if self.cancel_event.is_set():
                raise InterruptedError("Analysis recovery cancelled")
        if not decision["run"]:
            self._emit("log", "Agent diagnosis skipped after diagnostic preview; resume from History when ready.")
            return {"status": "skipped"}
        result = attempt_agent_recovery(runner, folder, find_agent_cli("codex"),
                                        lambda m: self._emit("log", m), self.cancel_event.is_set, self._set_process)
        if result.get("status") not in {"recovered", "not_needed"}:
            self._emit("recovery_needs_user", (str(folder), result))
        return result

    def _open_recovery_preview(self, preview, decision, ready):
        window = ctk.CTkToplevel(self)
        window.title("CastorPollux | Inspect redacted diagnostics before agent diagnosis")
        window.geometry("900x650")
        self._label(window, "ENGINE ERROR  /  REDACTED AGENT PAYLOAD", 12, RED, "bold").pack(
            anchor="w", padx=14, pady=(12, 5))
        box = ctk.CTkTextbox(window, fg_color=SIDEBAR, text_color=TEXT, font=self._font(11, mono=True))
        box.pack(fill="both", expand=True, padx=14, pady=6)
        box.insert("1.0", Path(preview).read_text(encoding="utf-8"))
        row = ctk.CTkFrame(window, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(5, 14))
        def finish(run):
            decision["run"] = run
            ready.set()
            window.destroy()
        self._button(row, "SEND TO CODEX FOR DIAGNOSIS", lambda: finish(True), 265, True).pack(side="left")
        self._button(row, "SKIP DIAGNOSIS", lambda: finish(False), 170).pack(side="left", padx=8)
        window.protocol("WM_DELETE_WINDOW", lambda: finish(False))

    def _cancel(self):
        if not self.busy:
            return
        self.cancel_event.set()
        process = self.process
        if process and process.poll() is None:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self._log("Cancellation requested…")

    def _start_analysis(self):
        self._analyze(review_after=False)

    def _start_analyze_review(self):
        self._analyze(review_after=True)

    def _analyze(self, review_after=False):
        source = Path(self.input_path.get()).expanduser()
        target = Path(self.output_path.get()).expanduser()
        if not source.is_file():
            messagebox.showerror("CastorPollux", "Choose an existing binary file.")
            return
        if not target.is_dir():
            messagebox.showerror("CastorPollux", "Choose an existing output folder.")
            return
        if source.stat().st_size == 0:
            messagebox.showerror("CastorPollux", "The selected file is empty.")
            return
        symbols = Path(self.symbol_path.get()).expanduser() if self.symbol_path.get().strip() else None
        if symbols and not symbols.is_file():
            messagebox.showerror("CastorPollux", "Choose an existing PDB or DWARF debug file.")
            return
        if symbols and self.symbol_server_enabled.get():
            messagebox.showerror("CastorPollux", "Choose local symbols or online lookup, not both.")
            return
        agent = self.review_agent.get()
        daybreak = self.daybreak_blue.get()
        try:
            minimum_coverage = int(self.coverage_minimum.get())
            if not 0 <= minimum_coverage <= 100:
                raise ValueError
        except ValueError:
            messagebox.showerror("CastorPollux", "Minimum coverage must be a number from 0 to 100.")
            return
        redaction_terms = [term.strip() for term in self.redaction_terms.get().split(",") if term.strip()]
        redact_cloud = self.redact_cloud.get()
        secondary = self.secondary_decompiler.get()
        retdec = Path(self.retdec_path.get()) if self.retdec_path.get() else None
        executable = Path(self.codex_cli_path.get()) if agent != "ollama" else None
        formats = {name for name, variable in self.report_formats.items() if variable.get()}
        scope_mode, scope_selection, local_model = self.scope_mode.get(), self.scope_selection.get(), self.local_model.get()
        if review_after:
            if agent != "ollama":
                if not executable.is_file():
                    detected = find_agent_cli(agent)
                    if detected:
                        executable = detected
                        self.codex_cli_path.set(str(detected))
                if not executable.is_file():
                    messagebox.showerror("CastorPollux", f"Choose or locate an installed {agent} CLI on Agent Review first.")
                    return
            elif not local_model:
                messagebox.showerror("CastorPollux", "Choose a local Ollama model on Agent Review first.")
                return
            if not formats:
                messagebox.showerror("CastorPollux", "Select at least one report format on Agent Review.")
                return
        def task():
            if review_after and agent == "ollama" and local_model not in ollama_models():
                raise RuntimeError("The selected Ollama model is not available on 127.0.0.1")
            runner = AnalysisRunner(self.store, lambda m: self._emit("log", m),
                                    self.cancel_event.is_set, self._set_process)
            folder = None
            try:
                folder = runner.run(source, target, symbols=symbols,
                                    symbol_server=self.symbol_server.get().strip() if self.symbol_server_enabled.get() else None)
                self._diagnose_with_preview(runner, folder)
                self._emit("output", str(folder))
                self._signal_analysis_status(folder)
                if review_after:
                    review_readiness(folder)
                    self._emit("log", "REA source ready. Starting agent vulnerability review…")
                    self._emit("log", "CASTORPOLLUX_STAGE 0 Agent review in progress • live output below")
                    review = CodexReview(lambda m: self._emit("log", m),
                                         self.cancel_event.is_set, self._set_process)
                    try:
                        result = review.run(folder, daybreak, executable, formats, agent,
                                            scope_mode, scope_selection, local_model, minimum_coverage,
                                            redact_cloud, redaction_terms, secondary, retdec)
                    except Exception as error:
                        record_error(str(error), folder, "agent review", traceback.format_exc())
                        raise
                    self._emit("codex_report", (result, str(folder)))
                    self._emit("log", "CASTORPOLLUX_STAGE 100 Agent review complete")
            finally:
                self._capture_agent_usage(folder, agent)
        self._start_task(task, kind="scan")

    def _open_output(self):
        if self.last_output and self.last_output.is_dir():
            os.startfile(self.last_output)

    def _open_notices(self):
        bundled = self._credits_root()
        target = home() / "Notices"
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bundled / "CastorPollux-CREDITS.md", target / "CastorPollux-CREDITS.md")
        for item in (bundled / "CastorPollux-Licenses").iterdir():
            if item.is_file():
                shutil.copy2(item, target / item.name)
        os.startfile(target)

    def _credits_root(self):
        bundled = resource("credits")
        if (bundled / "CastorPollux-CREDITS.md").is_file():
            return bundled
        source = Path(__file__).resolve().parent.parent / "outputs"
        if (source / "CastorPollux-CREDITS.md").is_file():
            return source
        raise FileNotFoundError("Bundled credit and license notices are unavailable")

    def _check_updates(self):
        def task():
            self._emit("log", "Checking official release sources…")
            result = self.updater.check()
            self._emit("findings", result)
            self._emit("log", "Update check complete.")
        self._start_task(task)

    def _check_app_signature(self):
        target = Path(sys.executable if getattr(sys, "frozen", False) else __file__)
        status = authenticode_status(target)
        messagebox.showinfo("CastorPollux signature", f"File: {target}\nStatus: {status.get('status')}\n"
                            f"Signer: {status.get('subject', 'None')}")

    def _export_inventory(self):
        destination = filedialog.asksaveasfilename(title="Save software inventory",
                                                   defaultextension=".json",
                                                   initialfile="castorpollux-software-inventory.json",
                                                   filetypes=[("JSON", "*.json")])
        if not destination:
            return
        def task():
            path = write_inventory(Path(destination), self.store)
            self._emit("log", f"Software inventory saved: {path}")
        self._start_task(task)

    def _update_one(self, key):
        info = self.findings.get(key)
        if not info:
            return
        def task():
            self.updater.update(key, info, lambda m: self._emit("log", m),
                                self.cancel_event.is_set, self._set_process)
        self._start_task(task)

    def _health_component(self, key):
        def task():
            active = self.store.active_path(key)
            if active is None:
                bundled = bundled_component(key)
                if bundled is None:
                    self.store.analysis_paths(lambda m: self._emit("log", m), self.cancel_event.is_set)
                    bundled = bundled_component(key)
                if bundled is None:
                    raise RuntimeError(f"{key.upper()} is unavailable")
                version, active = bundled
            else:
                version = self.store.current_version(key)
            self._emit("log", check_component(key, active, version, self.store))
        self._start_task(task)

    def _rollback_component(self, key):
        targets = self.store.rollback_targets(key)
        if not targets:
            return
        target = targets[0]
        if not messagebox.askyesno("Roll back component", f"Activate {key.upper()} {target['version']}?"):
            return
        self._start_task(lambda: self.store.rollback(key, lambda m: self._emit("log", m)))

    def _update_all(self):
        def task():
            result = self.updater.check()
            self._emit("findings", result)
            for key in ("node", "rea", "jdk", "ghidra"):
                if self.cancel_event.is_set():
                    raise InterruptedError("Update cancelled")
                info = result["components"].get(key)
                if info and not compatible_update(key, info["version"]):
                    self._emit("log", f"Held {key.upper()} {info['version']}: outside REA's supported Windows line.")
                    continue
                if info and newer(info["version"], self.store.current_version(key)):
                    self._emit("log", f"Updating {key.upper()} to {info['version']}…")
                    self.updater.update(key, info, lambda m: self._emit("log", m),
                                        self.cancel_event.is_set, self._set_process)
            for key, error in result["errors"].items():
                self._emit("log", f"{key.upper()}: {error}")
            self._emit("log", "Component update pass complete.")
        self._start_task(task)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--batch":
        from castorpollux_batch import main as batch_main
        raise SystemExit(batch_main(sys.argv[2:]))
    CastorPollux().mainloop()
