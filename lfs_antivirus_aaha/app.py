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

from lfs_antivirus_aaha import __version__
from lfs_antivirus_aaha.engine import (
    ClamAvInstallation,
    suggested_installation,
    validate_installation,
)
from lfs_antivirus_aaha.logger import append_log, read_log_tail
from lfs_antivirus_aaha.models import ScanFinding, ScanSummary, utc_now_iso
from lfs_antivirus_aaha.quarantine import list_records_with_errors
from lfs_antivirus_aaha.scanner import ClamAvScanner, validate_scan_target
from lfs_antivirus_aaha.storage import (
    app_data_dir,
    clamav_database_dir,
    ensure_app_dirs,
    load_settings,
    save_settings,
)
from lfs_antivirus_aaha.updater import (
    DatabaseStatus,
    FreshClamUpdater,
    UpdateControl,
    UpdateResult,
    database_status,
    recover_database_activation,
)


THEMES = {
    "Default": {"bg": "#f3f5f7", "panel": "#ffffff", "accent": "#1f6aa5", "text": "#17202a", "muted": "#5d6d7e"},
    "Blue": {"bg": "#eef6fb", "panel": "#ffffff", "accent": "#155f9c", "text": "#102033", "muted": "#4d657d"},
    "Red": {"bg": "#fff5f5", "panel": "#ffffff", "accent": "#a83232", "text": "#2c1515", "muted": "#7a5555"},
}


def scan_summary_is_accepted(summary: ScanSummary) -> bool:
    return (
        not summary.cancelled
        and not summary.errors
        and summary.exit_code in (0, 1)
    )


class LocalFirstAntivirusApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        ensure_app_dirs()
        self.startup_recovery_note: str | None = None
        self.startup_recovery_error: Exception | None = None
        try:
            self.startup_recovery_note = recover_database_activation()
        except Exception as exc:
            self.startup_recovery_error = exc
        self.title("Local-First Antivirus — AAHA Local-First Series")
        self.geometry("1120x740")
        self.minsize(980, 640)

        self.settings = load_settings()
        self.engine: ClamAvInstallation | None = None
        self.findings: list[ScanFinding] = []
        self.summary: ScanSummary | None = None
        self.scan_thread: threading.Thread | None = None
        self.update_thread: threading.Thread | None = None
        self.engine_thread: threading.Thread | None = None
        self.scan_cancel_event = threading.Event()
        self.update_control: UpdateControl | None = None
        self.engine_cancel_event = threading.Event()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._validation_token = 0
        self._synchronizing_engine_paths = False
        self._closing = False

        self._create_vars()
        self._configure_style()
        self._build_layout()
        self._prefill_standard_installation()
        self.clamscan_path_var.trace_add("write", self._engine_paths_changed)
        self.freshclam_path_var.trace_add("write", self._engine_paths_changed)
        self._refresh_all()
        self.after(100, self._poll_events)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        append_log(f"Application started. Version {__version__}; engine not yet validated.")
        if self.startup_recovery_note:
            append_log(self.startup_recovery_note)
            self.progress_text_var.set(self.startup_recovery_note)
        if self.startup_recovery_error:
            append_log(f"Database recovery needs attention: {self.startup_recovery_error}")
            self.after(
                0,
                lambda: messagebox.showerror(
                    "ClamAV Database Recovery",
                    f"The local database needs recovery before scanning:\n\n{self.startup_recovery_error}",
                ),
            )

    def _create_vars(self) -> None:
        home = Path.home()
        default_scan = home / "Downloads" if (home / "Downloads").exists() else home
        saved_theme = str(self.settings.get("theme", "Default"))
        self.theme_var = tk.StringVar(value=saved_theme if saved_theme in THEMES else "Default")
        self.scan_path_var = tk.StringVar(value=str(default_scan))
        self.clamscan_path_var = tk.StringVar(value=str(self.settings.get("clamscan_path", "")))
        self.freshclam_path_var = tk.StringVar(value=str(self.settings.get("freshclam_path", "")))
        self.status_var = tk.StringVar(value="Engine setup required")
        self.progress_text_var = tk.StringVar(value="No task running")
        self.version_var = tk.StringVar(value=__version__)
        self.engine_var = tk.StringVar(value="Not validated")
        self.database_var = tk.StringVar(value="Not ready")
        self.last_scan_var = tk.StringVar(
            value=str(self.settings.get("last_successful_scan") or "Never")
        )
        self.legacy_count_var = tk.StringVar(value="0")
        self.threat_count_var = tk.StringVar(value="0 ClamAV finding(s)")

    def _configure_style(self) -> None:
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        colors = THEMES[self.theme_var.get()]
        self.configure(bg=colors["bg"])
        self.style.configure(".", font=("Segoe UI", 9), background=colors["bg"], foreground=colors["text"])
        self.style.configure("TFrame", background=colors["bg"])
        self.style.configure("TLabel", background=colors["bg"], foreground=colors["text"])
        self.style.configure("Muted.TLabel", foreground=colors["muted"])
        self.style.configure("Title.TLabel", font=("Segoe UI Semibold", 17))
        self.style.configure("Banner.TLabel", background="#fff4ce", foreground="#5c4300", padding=10)
        self.style.configure("Metric.TLabel", font=("Segoe UI Semibold", 12))
        self.style.configure("TLabelframe", background=colors["panel"])
        self.style.configure("TLabelframe.Label", background=colors["bg"], font=("Segoe UI Semibold", 9))
        self.style.configure("TButton", padding=(10, 6))
        self.style.configure("Treeview", rowheight=24)
        self.style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))

    def _build_layout(self) -> None:
        root = ttk.Frame(self, padding=16)
        root.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(root)
        header.pack(fill=tk.X, pady=(0, 10))
        brand = ttk.Frame(header)
        brand.pack(side=tk.LEFT)
        ttk.Label(brand, text="Local-First Antivirus", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(brand, text="Adam And His Agents (AAHA) · Local-First Series", style="Muted.TLabel").pack(anchor=tk.W)
        ttk.Label(header, textvariable=self.status_var, style="Muted.TLabel").pack(side=tk.RIGHT)

        ttk.Label(
            root,
            text=(
                "Beta · On-demand scanning only · Requires a separately installed ClamAV engine · "
                "Not a replacement for Microsoft Defender or another supported security product"
            ),
            style="Banner.TLabel",
            wraplength=1040,
        ).pack(fill=tk.X, pady=(0, 10))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.dashboard_tab = ttk.Frame(self.notebook, padding=14)
        self.scan_tab = ttk.Frame(self.notebook, padding=14)
        self.legacy_tab = ttk.Frame(self.notebook, padding=14)
        self.engine_tab = ttk.Frame(self.notebook, padding=14)
        self.logs_tab = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.scan_tab, text="Scan")
        self.notebook.add(self.legacy_tab, text="Legacy Quarantine (read-only)")
        self.notebook.add(self.engine_tab, text="ClamAV Engine")
        self.notebook.add(self.logs_tab, text="Logs")

        self._build_dashboard_tab()
        self._build_scan_tab()
        self._build_legacy_tab()
        self._build_engine_tab()
        self._build_logs_tab()

    def _build_dashboard_tab(self) -> None:
        metrics = ttk.Frame(self.dashboard_tab)
        metrics.pack(fill=tk.X)
        for column in range(4):
            metrics.columnconfigure(column, weight=1, uniform="metric")
        self._metric(metrics, 0, "App version", self.version_var)
        self._metric(metrics, 1, "ClamAV engine", self.engine_var)
        self._metric(metrics, 2, "Definitions", self.database_var)
        self._metric(metrics, 3, "Last accepted scan", self.last_scan_var)

        actions = ttk.Frame(self.dashboard_tab)
        actions.pack(fill=tk.X, pady=14)
        self.quick_button = ttk.Button(actions, text="Quick Scan", command=self._quick_scan)
        self.quick_button.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(actions, text="Custom Scan", command=lambda: self.notebook.select(self.scan_tab)).pack(side=tk.LEFT, padx=8)
        ttk.Button(actions, text="Engine Setup", command=lambda: self.notebook.select(self.engine_tab)).pack(side=tk.LEFT, padx=8)
        ttk.Button(actions, text="Open Data Folder", command=self._open_data_folder).pack(side=tk.LEFT, padx=8)

        frame = ttk.LabelFrame(self.dashboard_tab, text="Current ClamAV Findings", padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        self.dashboard_findings = self._create_findings_tree(frame)

    def _metric(self, parent: ttk.Frame, column: int, label: str, value: tk.StringVar) -> None:
        frame = ttk.LabelFrame(parent, text=label, padding=12)
        frame.grid(row=0, column=column, sticky="nsew", padx=5)
        ttk.Label(frame, textvariable=value, style="Metric.TLabel", wraplength=230).pack(anchor=tk.W, fill=tk.X)

    def _build_scan_tab(self) -> None:
        target = ttk.LabelFrame(self.scan_tab, text="Local scan target", padding=10)
        target.pack(fill=tk.X)
        target.columnconfigure(0, weight=1)
        ttk.Entry(target, textvariable=self.scan_path_var).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(target, text="Browse Folder", command=self._browse_scan_folder).grid(row=0, column=1, padx=4)
        ttk.Button(target, text="Browse File", command=self._browse_scan_file).grid(row=0, column=2, padx=4)
        self.start_scan_button = ttk.Button(target, text="Start Scan", command=self._start_scan)
        self.start_scan_button.grid(row=0, column=3, padx=4)
        self.cancel_scan_button = ttk.Button(target, text="Cancel", command=self._cancel_scan)
        self.cancel_scan_button.grid(row=0, column=4, padx=(4, 0))

        progress = ttk.Frame(self.scan_tab)
        progress.pack(fill=tk.X, pady=12)
        self.progress = ttk.Progressbar(progress, mode="indeterminate")
        self.progress.pack(fill=tk.X)
        ttk.Label(progress, textvariable=self.progress_text_var, style="Muted.TLabel").pack(anchor=tk.W, pady=(4, 0))

        results = ttk.LabelFrame(self.scan_tab, text="ClamAV scan results", padding=10)
        results.pack(fill=tk.BOTH, expand=True)
        self.results_tree = self._create_findings_tree(results)

        buttons = ttk.Frame(self.scan_tab)
        buttons.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(buttons, text="Clear Results", command=self._clear_results).pack(side=tk.LEFT)
        ttk.Label(buttons, textvariable=self.threat_count_var, style="Muted.TLabel").pack(side=tk.RIGHT)

    def _create_findings_tree(self, parent: ttk.Widget) -> ttk.Treeview:
        container = ttk.Frame(parent)
        container.pack(fill=tk.BOTH, expand=True)
        columns = ("result", "threat", "file", "detail")
        tree = ttk.Treeview(container, columns=columns, show="headings")
        for name, text, width in (
            ("result", "Result", 90),
            ("threat", "ClamAV signature", 250),
            ("file", "Reported path", 430),
            ("detail", "Detail", 300),
        ):
            tree.heading(name, text=text)
            tree.column(name, width=width, minwidth=80, stretch=name in {"file", "detail"})
        yscroll = ttk.Scrollbar(container, orient=tk.VERTICAL, command=tree.yview)
        xscroll = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        return tree

    def _build_legacy_tab(self) -> None:
        ttk.Label(
            self.legacy_tab,
            text=(
                "Existing quarantine records and payloads are preserved for recovery. This beta displays them "
                "read-only because the earlier restore/delete workflow was not transactional. No file action is available here."
            ),
            style="Banner.TLabel",
            wraplength=1000,
        ).pack(fill=tk.X, pady=(0, 10))
        frame = ttk.LabelFrame(self.legacy_tab, text="Preserved legacy records", padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        columns = ("date", "threat", "file", "original")
        self.legacy_tree = ttk.Treeview(frame, columns=columns, show="headings")
        for name, text, width in (
            ("date", "Quarantined", 180),
            ("threat", "Recorded finding", 240),
            ("file", "File", 220),
            ("original", "Original path", 480),
        ):
            self.legacy_tree.heading(name, text=text)
            self.legacy_tree.column(name, width=width, minwidth=80, stretch=name == "original")
        self.legacy_tree.pack(fill=tk.BOTH, expand=True)
        buttons = ttk.Frame(self.legacy_tab)
        buttons.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(buttons, text="Refresh", command=self._refresh_legacy).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Open Data Folder", command=self._open_data_folder).pack(side=tk.LEFT)
        ttk.Label(buttons, textvariable=self.legacy_count_var, style="Muted.TLabel").pack(side=tk.RIGHT)

    def _build_engine_tab(self) -> None:
        boundary = ttk.LabelFrame(self.engine_tab, text="External ClamAV installation", padding=10)
        boundary.pack(fill=tk.X)
        boundary.columnconfigure(1, weight=1)
        ttk.Label(
            boundary,
            text=(
                "Install ClamAV separately from its official distribution, then select both executables below. "
                "AAHA does not bundle or modify ClamAV and never searches PATH or invokes a command shell."
            ),
            wraplength=980,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        ttk.Label(boundary, text="clamscan.exe").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(boundary, textvariable=self.clamscan_path_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(boundary, text="Browse", command=self._browse_clamscan).grid(row=1, column=2, padx=(8, 0), pady=4)
        ttk.Label(boundary, text="freshclam.exe").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(boundary, textvariable=self.freshclam_path_var).grid(row=2, column=1, sticky="ew", pady=4)
        ttk.Button(boundary, text="Browse", command=self._browse_freshclam).grid(row=2, column=2, padx=(8, 0), pady=4)
        self.validate_button = ttk.Button(boundary, text="Validate Exact Paths", command=self._validate_engine)
        self.validate_button.grid(row=3, column=1, sticky="w", pady=(10, 0))

        definitions = ttk.LabelFrame(self.engine_tab, text="Official definitions", padding=10)
        definitions.pack(fill=tk.X, pady=12)
        definitions.columnconfigure(0, weight=1)
        ttk.Label(definitions, textvariable=self.database_var).grid(row=0, column=0, sticky="w")
        ttk.Label(
            definitions,
            text=(
                "Update Definitions runs the selected freshclam.exe only when you request it. It downloads into "
                "AAHA's local data directory, validates the staged database, and keeps the previous database as a backup."
            ),
            style="Muted.TLabel",
            wraplength=900,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 10))
        self.update_button = ttk.Button(definitions, text="Update Definitions", command=self._update_definitions)
        self.update_button.grid(row=2, column=0, sticky="w")
        self.cancel_update_button = ttk.Button(definitions, text="Cancel Update", command=self._cancel_update)
        self.cancel_update_button.grid(row=2, column=1, sticky="w", padx=8)
        ttk.Label(definitions, text=f"Database directory: {clamav_database_dir()}", style="Muted.TLabel").grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(10, 0)
        )

        settings = ttk.LabelFrame(self.engine_tab, text="Display settings", padding=10)
        settings.pack(fill=tk.X)
        ttk.Label(settings, text="Theme").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Combobox(settings, textvariable=self.theme_var, values=tuple(THEMES), state="readonly", width=14).grid(row=0, column=1, sticky="w")
        ttk.Button(settings, text="Save Settings", command=self._save_settings).grid(row=0, column=2, padx=10)

    def _build_logs_tab(self) -> None:
        buttons = ttk.Frame(self.logs_tab)
        buttons.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(buttons, text="Refresh Logs", command=self._refresh_logs).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Open Data Folder", command=self._open_data_folder).pack(side=tk.LEFT)
        self.log_text = tk.Text(self.logs_tab, wrap=tk.NONE, font=("Consolas", 10), height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state=tk.DISABLED)

    def _prefill_standard_installation(self) -> None:
        if self.clamscan_path_var.get().strip() or self.freshclam_path_var.get().strip():
            return
        pair = suggested_installation()
        if pair:
            self.clamscan_path_var.set(str(pair[0]))
            self.freshclam_path_var.set(str(pair[1]))

    def _browse_scan_folder(self) -> None:
        selected = filedialog.askdirectory(title="Choose a local folder to scan")
        if selected:
            self.scan_path_var.set(selected)

    def _browse_scan_file(self) -> None:
        selected = filedialog.askopenfilename(title="Choose a local file to scan")
        if selected:
            self.scan_path_var.set(selected)

    def _browse_clamscan(self) -> None:
        selected = filedialog.askopenfilename(title="Choose clamscan.exe", filetypes=(("ClamAV scanner", "clamscan.exe"), ("Executables", "*.exe")))
        if selected:
            self.clamscan_path_var.set(selected)
            sibling = Path(selected).with_name("freshclam.exe")
            if sibling.is_file():
                self.freshclam_path_var.set(str(sibling))

    def _browse_freshclam(self) -> None:
        selected = filedialog.askopenfilename(title="Choose freshclam.exe", filetypes=(("ClamAV updater", "freshclam.exe"), ("Executables", "*.exe")))
        if selected:
            self.freshclam_path_var.set(selected)
            sibling = Path(selected).with_name("clamscan.exe")
            if sibling.is_file():
                self.clamscan_path_var.set(str(sibling))

    def _engine_path_key(self) -> tuple[str, str]:
        return (
            self.clamscan_path_var.get().strip(),
            self.freshclam_path_var.get().strip(),
        )

    def _engine_paths_changed(self, *_args: object) -> None:
        if self._synchronizing_engine_paths:
            return
        self._validation_token += 1
        if self.engine:
            self.engine = None
            self.engine_var.set("Not validated")
            self.status_var.set("Engine paths changed; validation required")
            self.progress_text_var.set(
                "The edited paths are drafts. Validate them before scan or update actions are enabled."
            )
        if hasattr(self, "start_scan_button"):
            self._refresh_actions()

    def _validate_engine(self) -> None:
        if self._closing or self._task_running():
            messagebox.showinfo("Task Running", "Wait for the current task to finish.")
            return
        request_paths = self._engine_path_key()
        clamscan, freshclam = request_paths
        self._validation_token += 1
        token = self._validation_token
        self.engine_cancel_event.clear()
        self.engine = None
        self.status_var.set("Validating ClamAV")
        self.progress_text_var.set("Validating exact executable paths and version responses...")
        self._start_progress()

        def run() -> None:
            try:
                installation = validate_installation(
                    clamscan,
                    freshclam,
                    cancel_event=self.engine_cancel_event,
                )
                self.events.put(
                    ("engine_complete", (token, request_paths, installation))
                )
            except Exception as exc:
                self.events.put(("engine_error", (token, exc)))

        self.engine_thread = threading.Thread(target=run, daemon=False)
        self.engine_thread.start()
        self._refresh_actions()

    def _quick_scan(self) -> None:
        home = Path.home()
        target = home / "Downloads" if (home / "Downloads").exists() else home
        self.scan_path_var.set(str(target))
        self.notebook.select(self.scan_tab)
        self._start_scan()

    def _start_scan(self) -> None:
        if self._closing:
            return
        if not self.engine:
            messagebox.showerror("Engine Setup Required", "Validate a separately installed ClamAV engine first.")
            self.notebook.select(self.engine_tab)
            return
        if not database_status().ready:
            messagebox.showerror("Definitions Required", "Run Update Definitions before scanning.")
            self.notebook.select(self.engine_tab)
            return
        if self._task_running():
            messagebox.showinfo("Task Running", "Wait for the current task to finish.")
            return
        try:
            target = validate_scan_target(self.scan_path_var.get().strip())
        except (OSError, ValueError) as exc:
            messagebox.showerror("Invalid Scan Target", str(exc))
            return

        self.scan_cancel_event.clear()
        self.status_var.set("Scanning")
        self.progress_text_var.set(f"ClamAV is scanning: {target}")
        self._start_progress()
        scanner = ClamAvScanner(self.engine.clamscan_path, clamav_database_dir(), self.engine.clamscan_version)

        def run() -> None:
            try:
                append_log(f"ClamAV scan started: {target}")
                self.events.put(("scan_complete", scanner.scan_path(target, cancel_event=self.scan_cancel_event)))
            except Exception as exc:
                self.events.put(("scan_error", exc))

        self.scan_thread = threading.Thread(target=run, daemon=False)
        self.scan_thread.start()
        self._refresh_actions()

    def _cancel_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_cancel_event.set()
            self.status_var.set("Cancelling scan")
            self.progress_text_var.set("Stopping the ClamAV process safely...")

    def _update_definitions(self) -> None:
        if self._closing:
            return
        if not self.engine:
            messagebox.showerror("Engine Setup Required", "Validate ClamAV before updating definitions.")
            return
        if self._task_running():
            messagebox.showinfo("Task Running", "Wait for the current task to finish.")
            return
        control = UpdateControl()
        self.update_control = control
        self.status_var.set("Updating definitions")
        self.progress_text_var.set("FreshClam is updating a staged official database...")
        self._start_progress()
        updater = FreshClamUpdater(self.engine.freshclam_path, self.engine.clamscan_path)

        def run() -> None:
            try:
                self.events.put(("update_complete", updater.update(control=control)))
            except Exception as exc:
                self.events.put(("update_error", exc))

        self.update_thread = threading.Thread(target=run, daemon=False)
        self.update_thread.start()
        self._refresh_actions()

    def _cancel_update(self) -> None:
        if self.update_thread and self.update_thread.is_alive() and self.update_control:
            if self.update_control.request_cancel():
                self.status_var.set("Cancelling update")
                self.progress_text_var.set(
                    "Stopping FreshClam; database activation has not started."
                )
            else:
                self.status_var.set("Finishing database activation")
                self.progress_text_var.set(
                    "The validated database is being committed and cannot be cancelled safely."
                )

    def _poll_events(self) -> None:
        try:
            while True:
                try:
                    event, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    if event == "engine_complete":
                        self._engine_complete(payload)  # type: ignore[arg-type]
                    elif event == "engine_error":
                        self._engine_error(payload)  # type: ignore[arg-type]
                    elif event == "scan_complete":
                        self._scan_complete(payload)  # type: ignore[arg-type]
                    elif event == "scan_error":
                        self._scan_error(payload)  # type: ignore[arg-type]
                    elif event == "update_complete":
                        self._update_complete(payload)  # type: ignore[arg-type]
                    elif event == "update_error":
                        self._update_error(payload)  # type: ignore[arg-type]
                except Exception as exc:
                    self._event_callback_failed(event, exc)
        except queue.Empty:
            pass
        finally:
            try:
                self._refresh_actions()
            except Exception as exc:
                self._event_callback_failed("action refresh", exc)
            if self.winfo_exists():
                self.after(100, self._poll_events)

    def _event_callback_failed(self, event: str, exc: Exception) -> None:
        self._stop_progress()
        self.status_var.set("Local UI error; review Logs")
        try:
            append_log(f"UI event callback failed ({event}): {exc}")
        except Exception:
            pass

    def _engine_complete(
        self,
        payload: tuple[int, tuple[str, str], ClamAvInstallation],
    ) -> None:
        token, request_paths, installation = payload
        if token != self._validation_token or request_paths != self._engine_path_key():
            self._stop_progress()
            self.status_var.set("Engine paths changed; validation required")
            self.progress_text_var.set("A stale validation result was discarded.")
            append_log("Discarded stale ClamAV validation result after path edits.")
            return
        self.engine = installation
        self._synchronizing_engine_paths = True
        try:
            self.clamscan_path_var.set(str(installation.clamscan_path))
            self.freshclam_path_var.set(str(installation.freshclam_path))
        finally:
            self._synchronizing_engine_paths = False
        self._save_settings(show_message=False)
        self._stop_progress()
        self.status_var.set("Ready" if database_status().ready else "Definitions required")
        self.progress_text_var.set("ClamAV executable paths validated for this session.")
        append_log(f"External ClamAV validated: {installation.clamscan_version}")
        self._refresh_all()

    def _engine_error(self, payload: tuple[int, Exception]) -> None:
        token, exc = payload
        if token != self._validation_token:
            self._stop_progress()
            append_log("Discarded stale ClamAV validation failure after path edits.")
            return
        self.engine = None
        self._stop_progress()
        self.status_var.set("Engine setup required")
        self.progress_text_var.set("ClamAV validation failed.")
        append_log(f"ClamAV validation failed: {exc}")
        self._refresh_all()
        if not self._closing:
            messagebox.showerror("ClamAV Validation Failed", str(exc))

    def _scan_complete(self, summary: ScanSummary) -> None:
        accepted = scan_summary_is_accepted(summary)
        if accepted:
            self.summary = summary
            self.findings = summary.findings
            self.settings["last_successful_scan"] = summary.completed_at
        outcome = "cancelled" if summary.cancelled else ("accepted" if accepted else "incomplete")
        self.settings["last_attempt"] = {
            "completed_at": summary.completed_at,
            "outcome": outcome,
            "exit_code": summary.exit_code,
            "findings": summary.threats_found,
            "errors": len(summary.errors),
        }
        self._save_settings(show_message=False)
        self._stop_progress()
        state = "cancelled" if summary.cancelled else "completed"
        self.progress_text_var.set(
            f"Scan {state}. ClamAV reported {summary.files_scanned} scanned file(s), "
            f"{summary.threats_found} finding(s), and {len(summary.errors)} error note(s)."
            + (" Prior accepted results were retained." if not accepted else "")
        )
        self.status_var.set("Ready")
        append_log(
            f"ClamAV scan {state}: {summary.root}; exit={summary.exit_code}; "
            f"scanned={summary.files_scanned}; findings={summary.threats_found}; errors={len(summary.errors)}."
        )
        for error in summary.errors[:20]:
            append_log(f"Scan note: {error}")
        self._refresh_all()
        if summary.errors and not summary.cancelled and not self._closing:
            messagebox.showwarning(
                "Scan Completed With Errors",
                "ClamAV reported scan errors. Review the local Logs tab before treating the result as complete.",
            )

    def _scan_error(self, exc: Exception) -> None:
        self.settings["last_attempt"] = {
            "completed_at": utc_now_iso(),
            "outcome": "failed",
            "error": str(exc)[:500],
        }
        self._save_settings(show_message=False)
        self._stop_progress()
        self.status_var.set("Ready")
        self.progress_text_var.set("Scan failed; no clean result was recorded.")
        append_log(f"ClamAV scan failed: {exc}")
        self._refresh_all()
        if not self._closing:
            messagebox.showerror("Scan Failed", str(exc))

    def _update_complete(self, result: UpdateResult) -> None:
        self.update_control = None
        self._stop_progress()
        self.status_var.set("Ready")
        self.progress_text_var.set("Official ClamAV definitions updated and staged database activated.")
        append_log(
            f"FreshClam update completed; files={result.database_status.file_count}; "
            f"newest={result.database_status.newest_at}."
        )
        if result.recovery_note:
            append_log(result.recovery_note)
        self._refresh_all()
        if not self._closing:
            if result.recovery_note:
                messagebox.showwarning(
                    "Definitions Activated",
                    "The new database is active, but backup cleanup remains pending. "
                    "The app will retry recovery at the next start.",
                )
            else:
                messagebox.showinfo(
                    "Definitions Updated",
                    "The staged official ClamAV database validated and is now active.",
                )

    def _update_error(self, exc: Exception) -> None:
        self.update_control = None
        self._stop_progress()
        self.status_var.set("Ready" if self.engine else "Engine setup required")
        self.progress_text_var.set(
            "Definitions update did not complete. Review the error and Logs; startup recovery will retry if needed."
        )
        append_log(f"FreshClam update failed: {exc}")
        self._refresh_all()
        if not self._closing:
            messagebox.showerror("Definitions Update Failed", str(exc))

    def _clear_results(self) -> None:
        self.findings = []
        self.summary = None
        self.progress_text_var.set("No task running")
        self._populate_results()

    def _populate_results(self) -> None:
        for tree in (self.results_tree, self.dashboard_findings):
            tree.delete(*tree.get_children())
            for index, finding in enumerate(self.findings):
                tree.insert(
                    "",
                    tk.END,
                    iid=f"{id(tree)}:{index}",
                    values=(finding.status, finding.threat_name, finding.path, finding.reason),
                )
        self.threat_count_var.set(f"{len(self.findings)} ClamAV finding(s)")

    def _refresh_legacy(self) -> None:
        self.legacy_tree.delete(*self.legacy_tree.get_children())
        records, read_errors = list_records_with_errors()
        for index, record in enumerate(records):
            self.legacy_tree.insert(
                "",
                tk.END,
                iid=f"legacy:{index}:{record.id}",
                values=(record.quarantined_at, record.finding.threat_name, record.original_name, record.original_path),
            )
        suffix = f" · {read_errors} unreadable record(s)" if read_errors else ""
        self.legacy_count_var.set(f"{len(records)} preserved record(s){suffix}")

    def _refresh_database(self) -> DatabaseStatus:
        status = database_status()
        if status.ready:
            newest = status.newest_at or "unknown time"
            self.database_var.set(f"Ready · {status.file_count} database file(s) · newest {newest}")
        else:
            self.database_var.set("Not ready · run Update Definitions")
        return status

    def _save_settings(self, show_message: bool = True) -> None:
        saved_clamscan = str(self.settings.get("clamscan_path", ""))
        saved_freshclam = str(self.settings.get("freshclam_path", ""))
        if self.engine:
            saved_clamscan = str(self.engine.clamscan_path)
            saved_freshclam = str(self.engine.freshclam_path)
        self.settings = {
            "clamscan_path": saved_clamscan,
            "freshclam_path": saved_freshclam,
            "theme": self.theme_var.get(),
            "last_successful_scan": self.settings.get("last_successful_scan"),
            "last_attempt": self.settings.get("last_attempt"),
        }
        save_settings(self.settings)
        self._configure_style()
        if show_message:
            append_log("Local display settings and previously validated engine paths saved.")
            messagebox.showinfo(
                "Settings Saved",
                "Display settings were saved. Draft engine paths are saved only after validation.",
            )

    def _refresh_logs(self) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, read_log_tail())
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def _open_data_folder(self) -> None:
        path = app_data_dir()
        path.mkdir(parents=True, exist_ok=True)
        if hasattr(os, "startfile"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            messagebox.showinfo("Application Data Folder", str(path))

    def _refresh_all(self) -> None:
        self.version_var.set(__version__)
        self.engine_var.set(self.engine.clamscan_version if self.engine else "Not validated")
        database = self._refresh_database()
        self.last_scan_var.set(
            str(self.settings.get("last_successful_scan") or "Never")
        )
        if self.engine and database.ready and not self._task_running():
            self.status_var.set("Ready")
        elif self.engine and not database.ready and not self._task_running():
            self.status_var.set("Definitions required")
        self._populate_results()
        self._refresh_legacy()
        self._refresh_logs()
        self._refresh_actions()

    def _refresh_actions(self) -> None:
        running = self._task_running()
        database_ready = database_status().ready
        scan_ready = bool(self.engine and database_ready and not running and not self._closing)
        self.start_scan_button.configure(state=tk.NORMAL if scan_ready else tk.DISABLED)
        self.quick_button.configure(state=tk.NORMAL if scan_ready else tk.DISABLED)
        self.cancel_scan_button.configure(
            state=tk.NORMAL if self.scan_thread and self.scan_thread.is_alive() else tk.DISABLED
        )
        self.validate_button.configure(
            state=tk.DISABLED if running or self._closing else tk.NORMAL
        )
        self.update_button.configure(
            state=tk.NORMAL if self.engine and not running and not self._closing else tk.DISABLED
        )
        self.cancel_update_button.configure(
            state=(
                tk.NORMAL
                if self.update_thread
                and self.update_thread.is_alive()
                and self.update_control
                and not self.update_control.commit_started.is_set()
                else tk.DISABLED
            )
        )

    def _task_running(self) -> bool:
        return any(
            thread and thread.is_alive()
            for thread in (self.scan_thread, self.update_thread, self.engine_thread)
        )

    def _start_progress(self) -> None:
        self.progress.stop()
        self.progress.start(12)

    def _stop_progress(self) -> None:
        self.progress.stop()

    def _on_close(self) -> None:
        self._closing = True
        if self._task_running():
            self.scan_cancel_event.set()
            update_can_cancel = True
            if self.update_control:
                update_can_cancel = self.update_control.request_cancel()
            self.engine_cancel_event.set()
            self.status_var.set(
                "Stopping external process"
                if update_can_cancel
                else "Finishing database activation before closing"
            )
            self.after(250, self._wait_to_close)
            return
        self.destroy()

    def _wait_to_close(self) -> None:
        if not self._task_running():
            self.destroy()
            return
        self.after(250, self._wait_to_close)


def main() -> None:
    app = LocalFirstAntivirusApp()
    app.mainloop()


if __name__ == "__main__":
    main()
