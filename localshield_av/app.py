from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from localshield_av import __version__
from localshield_av.definitions import (
    export_active_definitions,
    install_definitions,
    load_definitions,
    reset_to_bundled_definitions,
)
from localshield_av.logger import append_log, read_log_tail
from localshield_av.models import ScanFinding, ScanSummary
from localshield_av.quarantine import delete_record, list_records, quarantine_file, restore_record
from localshield_av.scanner import LocalScanner
from localshield_av.storage import app_data_dir, ensure_app_dirs, load_settings, save_settings
from localshield_av.updater import DEFINITION_SOURCE_NAMES, DEFINITION_SOURCES, update_definitions_from_source


THEMES = {
    "Default": {
        "bg": "#f3f5f7",
        "panel": "#ffffff",
        "outline": "#c9ced6",
        "accent": "#1f6aa5",
        "text": "#17202a",
        "muted": "#5d6d7e",
    },
    "Blue": {
        "bg": "#eef6fb",
        "panel": "#ffffff",
        "outline": "#a8c4df",
        "accent": "#155f9c",
        "text": "#102033",
        "muted": "#4d657d",
    },
    "Red": {
        "bg": "#fff5f5",
        "panel": "#ffffff",
        "outline": "#e0b2b2",
        "accent": "#a83232",
        "text": "#2c1515",
        "muted": "#7a5555",
    },
}


class RoundedPanel(tk.Frame):
    def __init__(
        self,
        master: tk.Widget,
        colors: dict[str, str],
        title: str = "",
        padding: int = 10,
        radius: int = 16,
        height: int | None = None,
    ) -> None:
        super().__init__(master, bg=colors["bg"])
        self.colors = colors
        self.title = title
        self.padding = padding
        self.radius = radius
        self.title_height = 24 if title else 0
        self.canvas = tk.Canvas(
            self,
            bg=colors["bg"],
            borderwidth=0,
            highlightthickness=0,
            height=height or 80,
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.inner = ttk.Frame(self.canvas, padding=padding, style="Panel.TFrame")
        self.window = self.canvas.create_window(0, 0, anchor=tk.NW, window=self.inner)
        self.canvas.bind("<Configure>", self._redraw)
        self.inner.bind("<Configure>", self._sync_requested_size)

    def set_colors(self, colors: dict[str, str]) -> None:
        self.colors = colors
        self.configure(bg=colors["bg"])
        self.canvas.configure(bg=colors["bg"])
        self._redraw()

    def _sync_requested_size(self, _event: tk.Event | None = None) -> None:
        width = max(180, self.inner.winfo_reqwidth() + (self.padding * 2))
        height = max(70, self.inner.winfo_reqheight() + self.title_height + (self.padding * 2))
        self.canvas.configure(width=width, height=height)
        self._redraw()

    def _redraw(self, _event: tk.Event | None = None) -> None:
        width = max(2, self.canvas.winfo_width())
        height = max(2, self.canvas.winfo_height())
        self.canvas.delete("panel")
        self._rounded_rect(
            1,
            1,
            width - 2,
            height - 2,
            self.radius,
            fill=self.colors["panel"],
            outline=self.colors["outline"],
            width=1,
            tags="panel",
        )
        if self.title:
            self.canvas.create_text(
                self.padding + 2,
                self.padding,
                anchor=tk.NW,
                text=self.title,
                fill=self.colors["muted"],
                font=("Segoe UI Semibold", 9),
                tags="panel",
            )
        inner_y = self.padding + self.title_height
        self.canvas.coords(self.window, self.padding, inner_y)
        self.canvas.itemconfigure(
            self.window,
            width=max(20, width - (self.padding * 2)),
            height=max(20, height - inner_y - self.padding),
        )

    def _rounded_rect(self, x1: int, y1: int, x2: int, y2: int, radius: int, **kwargs) -> None:
        points = [
            x1 + radius,
            y1,
            x2 - radius,
            y1,
            x2,
            y1,
            x2,
            y1 + radius,
            x2,
            y2 - radius,
            x2,
            y2,
            x2 - radius,
            y2,
            x1 + radius,
            y2,
            x1,
            y2,
            x1,
            y2 - radius,
            x1,
            y1 + radius,
            x1,
            y1,
        ]
        self.canvas.create_polygon(points, smooth=True, **kwargs)


class LocalShieldApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        ensure_app_dirs()
        self.title("LocalShield AV")
        self.geometry("1120x720")
        self.minsize(960, 600)

        self.settings = load_settings()
        self.definitions = load_definitions()
        self.findings: list[ScanFinding] = []
        self.summary: ScanSummary | None = None
        self.scan_thread: threading.Thread | None = None
        self.update_thread: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.rounded_panels: list[RoundedPanel] = []

        self._create_vars()
        self._configure_style()
        self._build_layout()
        self._refresh_all()
        self.after(100, self._poll_events)
        append_log(f"Application started. Version {__version__}.")

    def _create_vars(self) -> None:
        home = Path.home()
        default_scan = home / "Downloads" if (home / "Downloads").exists() else home
        self.scan_path_var = tk.StringVar(value=str(default_scan))
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_text_var = tk.StringVar(value="No scan running")

        self.version_var = tk.StringVar()
        self.definitions_var = tk.StringVar()
        self.last_scan_var = tk.StringVar()
        self.quarantine_count_var = tk.StringVar()
        self.threat_count_var = tk.StringVar()

        self.max_size_var = tk.StringVar(value=str(self.settings.get("max_file_size_mb", 64)))
        self.heuristics_var = tk.BooleanVar(value=bool(self.settings.get("enable_heuristics", True)))
        saved_source = str(self.settings.get("definition_source", DEFINITION_SOURCE_NAMES[0]))
        if saved_source not in DEFINITION_SOURCES:
            saved_source = DEFINITION_SOURCE_NAMES[0]
        self.definition_source_var = tk.StringVar(value=saved_source)
        self.definition_source_note_var = tk.StringVar()
        self.app_url_var = tk.StringVar(value=str(self.settings.get("app_update_url", "")))
        saved_theme = str(self.settings.get("theme", "Default"))
        self.theme_var = tk.StringVar(value=saved_theme if saved_theme in THEMES else "Default")

    def _configure_style(self) -> None:
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.colors = THEMES.get(self.theme_var.get(), THEMES["Default"])
        bg = self.colors["bg"]
        panel = self.colors["panel"]
        accent = self.colors["accent"]
        text = self.colors["text"]
        muted = self.colors["muted"]

        self.configure(bg=bg)
        self.style.configure(".", font=("Segoe UI", 9), background=bg, foreground=text)
        self.style.configure("TFrame", background=bg)
        self.style.configure("Panel.TFrame", background=panel, relief="flat", borderwidth=0)
        self.style.configure("TLabel", background=bg, foreground=text)
        self.style.configure("Panel.TLabel", background=panel, foreground=text)
        self.style.configure("Muted.TLabel", background=bg, foreground=muted)
        self.style.configure("PanelMuted.TLabel", background=panel, foreground=muted)
        self.style.configure("Title.TLabel", font=("Segoe UI Semibold", 16), background=bg, foreground=text)
        self.style.configure("Metric.TLabel", font=("Segoe UI Semibold", 13), background=panel, foreground=text)
        self.style.configure("MetricCaption.TLabel", font=("Segoe UI", 9), background=panel, foreground=muted)
        self.style.configure("TButton", padding=(10, 6), background=panel)
        self.style.configure("Accent.TButton", background=accent, foreground="#ffffff")
        self.style.configure("Treeview", rowheight=24, font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))

    def _build_layout(self) -> None:
        root = ttk.Frame(self, padding=16)
        root.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(root)
        header.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(header, text="LocalShield AV", style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(header, textvariable=self.status_var, style="Muted.TLabel").pack(side=tk.RIGHT)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.dashboard_tab = ttk.Frame(self.notebook, padding=14)
        self.scan_tab = ttk.Frame(self.notebook, padding=14)
        self.quarantine_tab = ttk.Frame(self.notebook, padding=14)
        self.updates_tab = ttk.Frame(self.notebook, padding=14)
        self.logs_tab = ttk.Frame(self.notebook, padding=14)

        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.scan_tab, text="Scan")
        self.notebook.add(self.quarantine_tab, text="Quarantine")
        self.notebook.add(self.updates_tab, text="Updates")
        self.notebook.add(self.logs_tab, text="Logs")

        self._build_dashboard_tab()
        self._build_scan_tab()
        self._build_quarantine_tab()
        self._build_updates_tab()
        self._build_logs_tab()

    def _build_dashboard_tab(self) -> None:
        metrics = ttk.Frame(self.dashboard_tab)
        metrics.pack(fill=tk.X)
        for index in range(4):
            metrics.columnconfigure(index, weight=1, uniform="metric")

        self._metric(metrics, 0, "App Version", self.version_var)
        self._metric(metrics, 1, "Definitions", self.definitions_var)
        self._metric(metrics, 2, "Last Scan", self.last_scan_var)
        self._metric(metrics, 3, "Quarantine", self.quarantine_count_var)

        actions = ttk.Frame(self.dashboard_tab)
        actions.pack(fill=tk.X, pady=18)
        ttk.Button(actions, text="Quick Scan", command=self._quick_scan).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(actions, text="Custom Scan", command=lambda: self.notebook.select(self.scan_tab)).pack(side=tk.LEFT, padx=8)
        ttk.Button(actions, text="Open Data Folder", command=self._open_data_folder).pack(side=tk.LEFT, padx=8)

        latest_panel = self._section(self.dashboard_tab, "Current Findings")
        latest_panel.pack(fill=tk.BOTH, expand=True)
        self.dashboard_findings = self._create_results_tree(latest_panel.inner)

    def _metric(self, parent: ttk.Frame, column: int, label: str, value: tk.StringVar) -> None:
        panel = RoundedPanel(parent, self.colors, padding=12, radius=18, height=88)
        self.rounded_panels.append(panel)
        panel.grid(row=0, column=column, sticky="nsew", padx=6)
        ttk.Label(panel.inner, textvariable=value, style="Metric.TLabel", wraplength=240).pack(anchor=tk.W, fill=tk.X)
        ttk.Label(panel.inner, text=label, style="MetricCaption.TLabel").pack(anchor=tk.W, pady=(4, 0))

    def _section(self, parent: ttk.Frame, title: str) -> RoundedPanel:
        panel = RoundedPanel(parent, self.colors, title=title, padding=10, radius=16)
        self.rounded_panels.append(panel)
        return panel

    def _build_scan_tab(self) -> None:
        path_panel = self._section(self.scan_tab, "Scan Target")
        path_panel.pack(fill=tk.X)
        path_frame = path_panel.inner
        path_frame.columnconfigure(0, weight=1)
        ttk.Entry(path_frame, textvariable=self.scan_path_var).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(path_frame, text="Browse Folder", command=self._browse_scan_folder).grid(row=0, column=1, padx=4)
        ttk.Button(path_frame, text="Browse File", command=self._browse_scan_file).grid(row=0, column=2, padx=4)
        ttk.Button(path_frame, text="Start Scan", command=self._start_scan).grid(row=0, column=3, padx=4)
        ttk.Button(path_frame, text="Cancel", command=self._cancel_scan).grid(row=0, column=4, padx=(4, 0))

        progress = ttk.Frame(self.scan_tab)
        progress.pack(fill=tk.X, pady=12)
        ttk.Progressbar(progress, variable=self.progress_var, maximum=100).pack(fill=tk.X)
        ttk.Label(progress, textvariable=self.progress_text_var, style="Muted.TLabel").pack(anchor=tk.W, pady=(4, 0))

        results_panel = self._section(self.scan_tab, "Scan Results")
        results_panel.pack(fill=tk.BOTH, expand=True)
        results_frame = results_panel.inner
        self.results_tree = self._create_results_tree(results_frame)

        buttons = ttk.Frame(self.scan_tab)
        buttons.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(buttons, text="Quarantine Selected", command=self._quarantine_selected).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Clear Results", command=self._clear_results).pack(side=tk.LEFT)
        ttk.Label(buttons, textvariable=self.threat_count_var, style="Muted.TLabel").pack(side=tk.RIGHT)

    def _create_results_tree(self, parent: ttk.Frame) -> ttk.Treeview:
        container = ttk.Frame(parent)
        container.pack(fill=tk.BOTH, expand=True)
        columns = ("severity", "threat", "status", "file", "reason")
        tree = ttk.Treeview(container, columns=columns, show="headings", selectmode="extended")
        headings = {
            "severity": ("Severity", 90),
            "threat": ("Threat", 220),
            "status": ("Status", 110),
            "file": ("File", 360),
            "reason": ("Reason", 330),
        }
        for name, (text, width) in headings.items():
            tree.heading(name, text=text)
            tree.column(name, width=width, minwidth=70, stretch=name in {"file", "reason"})
        yscroll = ttk.Scrollbar(container, orient=tk.VERTICAL, command=tree.yview)
        xscroll = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        return tree

    def _build_quarantine_tab(self) -> None:
        table_panel = self._section(self.quarantine_tab, "Quarantined Files")
        table_panel.pack(fill=tk.BOTH, expand=True)
        table_frame = table_panel.inner
        container = ttk.Frame(table_frame)
        container.pack(fill=tk.BOTH, expand=True)
        columns = ("date", "severity", "threat", "file", "original")
        self.quarantine_tree = ttk.Treeview(container, columns=columns, show="headings", selectmode="extended")
        for name, text, width in (
            ("date", "Quarantined", 180),
            ("severity", "Severity", 90),
            ("threat", "Threat", 220),
            ("file", "File", 220),
            ("original", "Original Path", 480),
        ):
            self.quarantine_tree.heading(name, text=text)
            self.quarantine_tree.column(name, width=width, minwidth=80, stretch=name == "original")
        yscroll = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=yscroll.set)
        self.quarantine_tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        buttons = ttk.Frame(self.quarantine_tab)
        buttons.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(buttons, text="Refresh", command=self._refresh_quarantine).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Restore Selected", command=self._restore_selected).pack(side=tk.LEFT, padx=8)
        ttk.Button(buttons, text="Delete Selected", command=self._delete_selected_quarantine).pack(side=tk.LEFT, padx=8)

    def _build_updates_tab(self) -> None:
        definitions_panel = self._section(self.updates_tab, "Virus Definitions")
        definitions_panel.pack(fill=tk.X)
        definitions_frame = definitions_panel.inner
        ttk.Label(definitions_frame, textvariable=self.definitions_var).grid(row=0, column=0, sticky=tk.W, columnspan=4)
        ttk.Button(definitions_frame, text="Import Definitions", command=self._import_definitions).grid(row=1, column=0, sticky=tk.W, pady=(10, 0), padx=(0, 8))
        ttk.Button(definitions_frame, text="Export Active", command=self._export_definitions).grid(row=1, column=1, sticky=tk.W, pady=(10, 0), padx=8)
        ttk.Button(definitions_frame, text="Reset Bundled", command=self._reset_definitions).grid(row=1, column=2, sticky=tk.W, pady=(10, 0), padx=8)

        url_panel = self._section(self.updates_tab, "Network Update Settings")
        url_panel.pack(fill=tk.X, pady=14)
        url_frame = url_panel.inner
        url_frame.columnconfigure(1, weight=1)
        ttk.Label(url_frame, text="Definitions Source").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=4)
        source_combo = ttk.Combobox(
            url_frame,
            textvariable=self.definition_source_var,
            values=DEFINITION_SOURCE_NAMES,
            state="readonly",
        )
        source_combo.grid(row=0, column=1, sticky="ew", pady=4)
        source_combo.bind("<<ComboboxSelected>>", self._update_source_note)
        ttk.Button(url_frame, text="Update Definitions", command=self._update_definitions_from_network).grid(row=0, column=2, padx=(8, 0), pady=4)
        ttk.Label(url_frame, textvariable=self.definition_source_note_var, style="PanelMuted.TLabel", wraplength=780).grid(row=1, column=1, sticky="ew", pady=(0, 8))
        ttk.Label(url_frame, text="App Update URL").grid(row=2, column=0, sticky=tk.W, padx=(0, 8), pady=4)
        ttk.Entry(url_frame, textvariable=self.app_url_var).grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Button(url_frame, text="Save Settings", command=self._save_settings).grid(row=2, column=2, padx=(8, 0), pady=4)
        self._update_source_note()

        settings_panel = self._section(self.updates_tab, "Scanner Settings")
        settings_panel.pack(fill=tk.X)
        settings_frame = settings_panel.inner
        ttk.Label(settings_frame, text="Maximum file size MB").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=4)
        ttk.Entry(settings_frame, textvariable=self.max_size_var, width=12).grid(row=0, column=1, sticky=tk.W, pady=4)
        ttk.Checkbutton(settings_frame, text="Enable heuristic review findings", variable=self.heuristics_var).grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=4)
        ttk.Label(settings_frame, text="Theme").grid(row=2, column=0, sticky=tk.W, padx=(0, 8), pady=4)
        ttk.Combobox(settings_frame, textvariable=self.theme_var, values=tuple(THEMES), state="readonly", width=14).grid(row=2, column=1, sticky=tk.W, pady=4)

    def _build_logs_tab(self) -> None:
        buttons = ttk.Frame(self.logs_tab)
        buttons.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(buttons, text="Refresh Logs", command=self._refresh_logs).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Open Data Folder", command=self._open_data_folder).pack(side=tk.LEFT)

        self.log_text = tk.Text(self.logs_tab, wrap=tk.NONE, font=("Consolas", 10), height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state=tk.DISABLED)

    def _browse_scan_folder(self) -> None:
        selected = filedialog.askdirectory(title="Choose a folder to scan")
        if selected:
            self.scan_path_var.set(selected)

    def _browse_scan_file(self) -> None:
        selected = filedialog.askopenfilename(title="Choose a file to scan")
        if selected:
            self.scan_path_var.set(selected)

    def _quick_scan(self) -> None:
        home = Path.home()
        target = home / "Downloads" if (home / "Downloads").exists() else home
        self.scan_path_var.set(str(target))
        self.notebook.select(self.scan_tab)
        self._start_scan()

    def _start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan Running", "A scan is already running.")
            return

        try:
            self._save_settings(show_message=False)
        except ValueError as exc:
            messagebox.showerror("Invalid Settings", str(exc))
            return
        path = Path(self.scan_path_var.get()).expanduser()
        if not path.exists():
            messagebox.showerror("Invalid Path", f"The scan target does not exist:\n{path}")
            return

        self.findings = []
        self.summary = None
        self._populate_results()
        self.cancel_event.clear()
        self.progress_var.set(0)
        self.progress_text_var.set("Preparing scan...")
        self.status_var.set("Scanning")

        scanner = LocalScanner(
            definitions=self.definitions,
            max_file_size_mb=int(self.settings.get("max_file_size_mb", 64)),
            enable_heuristics=bool(self.settings.get("enable_heuristics", True)),
        )

        def run() -> None:
            try:
                append_log(f"Scan started: {path}")

                def progress(current_path: str, index: int, total: int) -> None:
                    self.events.put(("progress", (current_path, index, total)))

                summary = scanner.scan_path(path, cancel_event=self.cancel_event, progress=progress)
                self.events.put(("scan_complete", summary))
            except Exception as exc:
                self.events.put(("scan_error", exc))

        self.scan_thread = threading.Thread(target=run, daemon=True)
        self.scan_thread.start()

    def _cancel_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.cancel_event.set()
            self.status_var.set("Cancelling scan")

    def _poll_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "progress":
                    current_path, index, total = payload  # type: ignore[misc]
                    percent = (index / total * 100) if total else 0
                    self.progress_var.set(percent)
                    self.progress_text_var.set(f"{index} of {total}: {current_path}")
                elif event == "scan_complete":
                    self._scan_complete(payload)  # type: ignore[arg-type]
                elif event == "scan_error":
                    self._scan_error(payload)  # type: ignore[arg-type]
                elif event == "definitions_complete":
                    source, definitions = payload  # type: ignore[misc]
                    self._definitions_update_complete(str(source), definitions)
                elif event == "definitions_error":
                    source, exc = payload  # type: ignore[misc]
                    self._definitions_update_error(str(source), exc)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _scan_complete(self, summary: ScanSummary) -> None:
        self.summary = summary
        self.findings = summary.findings
        self.settings["last_scan"] = summary.completed_at
        save_settings(self.settings)
        self.progress_var.set(100 if not summary.cancelled else self.progress_var.get())
        state = "cancelled" if summary.cancelled else "completed"
        self.progress_text_var.set(
            f"Scan {state}. Files scanned: {summary.files_scanned}. Findings: {summary.threats_found}."
        )
        self.status_var.set("Ready")
        append_log(
            f"Scan {state}: {summary.root}; files={summary.files_scanned}; "
            f"skipped={summary.files_skipped}; findings={summary.threats_found}."
        )
        for error in summary.errors[:20]:
            append_log(f"Scan note: {error}")
        self._refresh_all()

    def _scan_error(self, exc: Exception) -> None:
        self.status_var.set("Ready")
        self.progress_text_var.set("Scan failed")
        append_log(f"Scan failed: {exc}")
        messagebox.showerror("Scan Failed", str(exc))
        self._refresh_logs()

    def _populate_results(self) -> None:
        for tree in (self.results_tree, self.dashboard_findings):
            tree.delete(*tree.get_children())
            for index, finding in enumerate(self.findings):
                tree.insert(
                    "",
                    tk.END,
                    iid=f"{id(tree)}:{index}",
                    values=(
                        finding.severity,
                        finding.threat_name,
                        finding.status,
                        finding.path,
                        finding.reason,
                    ),
                )
        self.threat_count_var.set(f"{len(self.findings)} current finding(s)")

    def _quarantine_selected(self) -> None:
        selected = self.results_tree.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Select one or more scan findings first.")
            return
        by_path: dict[str, ScanFinding] = {}
        for item in selected:
            index = int(item.split(":")[-1])
            finding = self.findings[index]
            by_path.setdefault(finding.path, finding)

        if not messagebox.askyesno(
            "Confirm Quarantine",
            f"Move {len(by_path)} selected file(s) to quarantine?\n\n"
            "This is a manual action. LocalShield does not quarantine scan findings automatically.",
        ):
            append_log("Quarantine cancelled by user.")
            return

        successes = 0
        failures: list[str] = []
        for finding in by_path.values():
            try:
                quarantine_file(finding)
                successes += 1
                append_log(f"Quarantined: {finding.path}")
            except Exception as exc:
                failures.append(f"{finding.path}: {exc}")
                append_log(f"Quarantine failed: {finding.path}: {exc}")

        self._refresh_all()
        if failures:
            messagebox.showwarning("Quarantine Complete", f"Quarantined {successes} file(s).\n\n" + "\n".join(failures[:5]))
        else:
            messagebox.showinfo("Quarantine Complete", f"Quarantined {successes} file(s).")

    def _clear_results(self) -> None:
        self.findings = []
        self.summary = None
        self.progress_var.set(0)
        self.progress_text_var.set("No scan running")
        self._populate_results()

    def _refresh_quarantine(self) -> None:
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        records = list_records()
        for record in records:
            self.quarantine_tree.insert(
                "",
                tk.END,
                iid=record.id,
                values=(
                    record.quarantined_at,
                    record.finding.severity,
                    record.finding.threat_name,
                    record.original_name,
                    record.original_path,
                ),
            )
        self.quarantine_count_var.set(str(len(records)))

    def _restore_selected(self) -> None:
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Select a quarantined file first.")
            return
        restored: list[str] = []
        failures: list[str] = []
        for record_id in selected:
            try:
                restored_path = restore_record(record_id)
                restored.append(str(restored_path))
                append_log(f"Restored quarantine item: {restored_path}")
            except FileExistsError as exc:
                failures.append(str(exc))
            except Exception as exc:
                failures.append(str(exc))
                append_log(f"Restore failed for {record_id}: {exc}")
        self._refresh_all()
        message = f"Restored {len(restored)} file(s)."
        if failures:
            message += "\n\n" + "\n".join(failures[:5])
            messagebox.showwarning("Restore Complete", message)
        else:
            messagebox.showinfo("Restore Complete", message)

    def _delete_selected_quarantine(self) -> None:
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Select a quarantined file first.")
            return
        if not messagebox.askyesno("Delete Quarantine Items", "Permanently delete the selected quarantined file(s)?"):
            return
        deleted = 0
        for record_id in selected:
            try:
                delete_record(record_id)
                deleted += 1
                append_log(f"Deleted quarantine item: {record_id}")
            except Exception as exc:
                append_log(f"Delete quarantine item failed for {record_id}: {exc}")
        self._refresh_all()
        messagebox.showinfo("Delete Complete", f"Deleted {deleted} quarantine item(s).")

    def _import_definitions(self) -> None:
        selected = filedialog.askopenfilename(
            title="Import definitions JSON",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if not selected:
            return
        try:
            self.definitions = install_definitions(Path(selected))
            append_log(f"Definitions imported from {selected}; version={self.definitions.version}.")
            self._refresh_all()
            messagebox.showinfo("Definitions Imported", f"Active definitions: {self.definitions.version}")
        except Exception as exc:
            messagebox.showerror("Import Failed", str(exc))

    def _export_definitions(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Export active definitions",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if not selected:
            return
        try:
            export_active_definitions(Path(selected))
            append_log(f"Definitions exported to {selected}.")
            messagebox.showinfo("Definitions Exported", selected)
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    def _reset_definitions(self) -> None:
        try:
            self.definitions = reset_to_bundled_definitions()
            append_log(f"Definitions reset to bundled version {self.definitions.version}.")
            self._refresh_all()
            messagebox.showinfo("Definitions Reset", f"Active definitions: {self.definitions.version}")
        except Exception as exc:
            messagebox.showerror("Reset Failed", str(exc))

    def _update_definitions_from_network(self) -> None:
        if self.update_thread and self.update_thread.is_alive():
            messagebox.showinfo("Update Running", "A definitions update is already running.")
            return
        source = self.definition_source_var.get().strip()
        try:
            self._save_settings(show_message=False)
        except ValueError as exc:
            messagebox.showerror("Invalid Settings", str(exc))
            return
        self.status_var.set("Updating definitions")
        self.progress_text_var.set(f"Updating definitions from {source}...")

        def run() -> None:
            try:
                definitions = update_definitions_from_source(source)
                self.events.put(("definitions_complete", (source, definitions)))
            except Exception as exc:
                self.events.put(("definitions_error", (source, exc)))

        self.update_thread = threading.Thread(target=run, daemon=True)
        self.update_thread.start()

    def _definitions_update_complete(self, source: str, definitions) -> None:
        self.definitions = definitions
        self.status_var.set("Ready")
        self.progress_text_var.set(f"Definitions updated from {source}.")
        append_log(f"Definitions updated from {source}; version={self.definitions.version}.")
        self._refresh_all()
        messagebox.showinfo("Definitions Updated", f"Active definitions: {self.definitions.version}")

    def _definitions_update_error(self, source: str, exc: Exception) -> None:
        self.status_var.set("Ready")
        self.progress_text_var.set("Definitions update failed.")
        append_log(f"Definitions update failed from {source}: {exc}")
        messagebox.showerror("Update Failed", str(exc))

    def _save_settings(self, show_message: bool = True) -> None:
        try:
            max_size = int(self.max_size_var.get())
            if max_size < 1:
                raise ValueError
        except ValueError:
            raise ValueError("Maximum file size must be a positive whole number.")

        self.settings["max_file_size_mb"] = max_size
        self.settings["enable_heuristics"] = bool(self.heuristics_var.get())
        self.settings["definition_source"] = self.definition_source_var.get().strip()
        self.settings["app_update_url"] = self.app_url_var.get().strip()
        self.settings["theme"] = self.theme_var.get()
        save_settings(self.settings)
        self._apply_theme()
        if show_message:
            append_log("Settings saved.")
            self._refresh_all()
            messagebox.showinfo("Settings Saved", "Scanner and update settings were saved.")

    def _apply_theme(self) -> None:
        self._configure_style()
        for panel in self.rounded_panels:
            panel.set_colors(self.colors)

    def _update_source_note(self, _event: tk.Event | None = None) -> None:
        source = DEFINITION_SOURCES.get(self.definition_source_var.get(), {})
        self.definition_source_note_var.set(source.get("note", ""))

    def _refresh_logs(self) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, read_log_tail())
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def _open_data_folder(self) -> None:
        path = app_data_dir()
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(path)  # type: ignore[attr-defined]

    def _refresh_all(self) -> None:
        self.version_var.set(__version__)
        self.definitions_var.set(
            f"{self.definitions.version} - {self.definitions.signature_count} sigs"
        )
        self.last_scan_var.set(str(self.settings.get("last_scan") or "Never"))
        self._populate_results()
        self._refresh_quarantine()
        self._refresh_logs()


def main() -> None:
    app = LocalShieldApp()
    app.mainloop()


if __name__ == "__main__":
    main()
