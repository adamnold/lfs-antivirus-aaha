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
from localshield_av.updater import update_definitions_from_url


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
        self.cancel_event = threading.Event()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()

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
        self.definition_url_var = tk.StringVar(value=str(self.settings.get("definition_update_url", "")))
        self.app_url_var = tk.StringVar(value=str(self.settings.get("app_update_url", "")))

    def _configure_style(self) -> None:
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        bg = "#f3f5f7"
        panel = "#ffffff"
        accent = "#1f6aa5"
        text = "#17202a"
        muted = "#5d6d7e"

        self.configure(bg=bg)
        self.style.configure(".", font=("Segoe UI", 10), background=bg, foreground=text)
        self.style.configure("TFrame", background=bg)
        self.style.configure("Panel.TFrame", background=panel, relief="solid", borderwidth=1)
        self.style.configure("TLabel", background=bg, foreground=text)
        self.style.configure("Panel.TLabel", background=panel, foreground=text)
        self.style.configure("Muted.TLabel", foreground=muted)
        self.style.configure("Title.TLabel", font=("Segoe UI Semibold", 18), background=bg, foreground=text)
        self.style.configure("Metric.TLabel", font=("Segoe UI Semibold", 17), background=panel, foreground=text)
        self.style.configure("MetricCaption.TLabel", font=("Segoe UI", 9), background=panel, foreground=muted)
        self.style.configure("TButton", padding=(10, 6))
        self.style.configure("Accent.TButton", background=accent, foreground="#ffffff")
        self.style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
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

        latest = ttk.LabelFrame(self.dashboard_tab, text="Current Findings", padding=10)
        latest.pack(fill=tk.BOTH, expand=True)
        self.dashboard_findings = self._create_results_tree(latest)

    def _metric(self, parent: ttk.Frame, column: int, label: str, value: tk.StringVar) -> None:
        frame = ttk.Frame(parent, padding=12, style="Panel.TFrame")
        frame.grid(row=0, column=column, sticky="nsew", padx=6)
        ttk.Label(frame, textvariable=value, style="Metric.TLabel").pack(anchor=tk.W)
        ttk.Label(frame, text=label, style="MetricCaption.TLabel").pack(anchor=tk.W, pady=(4, 0))

    def _build_scan_tab(self) -> None:
        path_frame = ttk.LabelFrame(self.scan_tab, text="Scan Target", padding=10)
        path_frame.pack(fill=tk.X)
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

        results_frame = ttk.LabelFrame(self.scan_tab, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
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
        table_frame = ttk.LabelFrame(self.quarantine_tab, text="Quarantined Files", padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True)
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
        definitions_frame = ttk.LabelFrame(self.updates_tab, text="Virus Definitions", padding=10)
        definitions_frame.pack(fill=tk.X)
        ttk.Label(definitions_frame, textvariable=self.definitions_var).grid(row=0, column=0, sticky=tk.W, columnspan=4)
        ttk.Button(definitions_frame, text="Import Definitions", command=self._import_definitions).grid(row=1, column=0, sticky=tk.W, pady=(10, 0), padx=(0, 8))
        ttk.Button(definitions_frame, text="Export Active", command=self._export_definitions).grid(row=1, column=1, sticky=tk.W, pady=(10, 0), padx=8)
        ttk.Button(definitions_frame, text="Reset Bundled", command=self._reset_definitions).grid(row=1, column=2, sticky=tk.W, pady=(10, 0), padx=8)

        url_frame = ttk.LabelFrame(self.updates_tab, text="Network Update Settings", padding=10)
        url_frame.pack(fill=tk.X, pady=14)
        url_frame.columnconfigure(1, weight=1)
        ttk.Label(url_frame, text="Definitions URL").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=4)
        ttk.Entry(url_frame, textvariable=self.definition_url_var).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(url_frame, text="Update Definitions", command=self._update_definitions_from_network).grid(row=0, column=2, padx=(8, 0), pady=4)
        ttk.Label(url_frame, text="App Update URL").grid(row=1, column=0, sticky=tk.W, padx=(0, 8), pady=4)
        ttk.Entry(url_frame, textvariable=self.app_url_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(url_frame, text="Save Settings", command=self._save_settings).grid(row=1, column=2, padx=(8, 0), pady=4)

        settings_frame = ttk.LabelFrame(self.updates_tab, text="Scanner Settings", padding=10)
        settings_frame.pack(fill=tk.X)
        ttk.Label(settings_frame, text="Maximum file size MB").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=4)
        ttk.Entry(settings_frame, textvariable=self.max_size_var, width=12).grid(row=0, column=1, sticky=tk.W, pady=4)
        ttk.Checkbutton(settings_frame, text="Enable heuristic review findings", variable=self.heuristics_var).grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=4)

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
        url = self.definition_url_var.get().strip()
        if not url:
            messagebox.showinfo("No URL", "Enter a definitions URL first.")
            return
        if not (url.startswith("https://") or url.startswith("http://")):
            messagebox.showerror("Invalid URL", "Definitions URL must start with http:// or https://.")
            return
        self._save_settings(show_message=False)
        try:
            self.status_var.set("Updating definitions")
            self.update()
            self.definitions = update_definitions_from_url(url)
            append_log(f"Definitions updated from network; version={self.definitions.version}.")
            self._refresh_all()
            messagebox.showinfo("Definitions Updated", f"Active definitions: {self.definitions.version}")
        except Exception as exc:
            append_log(f"Network definitions update failed: {exc}")
            messagebox.showerror("Update Failed", str(exc))
        finally:
            self.status_var.set("Ready")

    def _save_settings(self, show_message: bool = True) -> None:
        try:
            max_size = int(self.max_size_var.get())
            if max_size < 1:
                raise ValueError
        except ValueError:
            raise ValueError("Maximum file size must be a positive whole number.")

        self.settings["max_file_size_mb"] = max_size
        self.settings["enable_heuristics"] = bool(self.heuristics_var.get())
        self.settings["definition_update_url"] = self.definition_url_var.get().strip()
        self.settings["app_update_url"] = self.app_url_var.get().strip()
        save_settings(self.settings)
        if show_message:
            append_log("Settings saved.")
            self._refresh_all()
            messagebox.showinfo("Settings Saved", "Scanner and update settings were saved.")

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
            f"{self.definitions.version} ({self.definitions.signature_count} signatures)"
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
