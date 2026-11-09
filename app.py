#!/usr/bin/env python3
"""RepoSentry's Tkinter interface and desktop entry point."""

from __future__ import annotations

import csv
import queue
import sqlite3
import sys
import threading
import webbrowser
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

from reposentry.config import APP_DIR
from reposentry.domain import RepoSentryError
from reposentry.github import validate_github_url
from reposentry.scanner import scan_repository
from reposentry.storage import get_history, get_scan_findings, initialize_database


class RepoSentryApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("RepoSentry | GitHub Dependency Scanner")
        self.root.geometry("1180x760")
        self.root.minsize(900, 600)

        self.header_logo = tk.PhotoImage(file=str(APP_DIR / "assets" / "reposentry-mark-64.png"))
        self.window_icon = tk.PhotoImage(file=str(APP_DIR / "assets" / "reposentry-mark-32.png"))
        self.root.iconphoto(True, self.window_icon)

        self.worker_queue: queue.Queue = queue.Queue()
        self.result_links: dict[str, str] = {}
        self.current_findings: list[dict] = []

        style = ttk.Style()
        # Use a theme with explicit colors so the interface stays readable in
        # both light and dark macOS appearances.
        if "clam" in style.theme_names():
            style.theme_use("clam")
        root.configure(background="#F3F5F9")
        style.configure("TFrame", background="#F3F5F9")
        style.configure("TLabel", background="#F3F5F9", foreground="#172033", font=("Helvetica", 10))
        style.configure(
            "Title.TLabel",
            background="#F3F5F9",
            foreground="#14213D",
            font=("Helvetica", 24, "bold"),
        )
        style.configure("Sub.TLabel", background="#F3F5F9", foreground="#596579")
        style.configure("TEntry", fieldbackground="#FFFFFF", foreground="#172033", padding=8)
        style.configure(
            "TButton",
            background="#2457D6",
            foreground="#FFFFFF",
            padding=(14, 8),
            font=("Helvetica", 10, "bold"),
        )
        style.map(
            "TButton",
            background=[("active", "#1947BD"), ("disabled", "#AAB4C8")],
            foreground=[("disabled", "#FFFFFF")],
        )
        style.configure(
            "TNotebook",
            background="#F3F5F9",
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background="#E4E9F2",
            foreground="#24324A",
            padding=(14, 8),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#FFFFFF")],
            foreground=[("selected", "#14213D")],
        )
        style.configure(
            "Treeview",
            rowheight=30,
            background="#FFFFFF",
            fieldbackground="#FFFFFF",
            foreground="#172033",
            font=("Helvetica", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#E6EBF3",
            foreground="#24324A",
            font=("Helvetica", 10, "bold"),
            padding=7,
        )
        style.map("Treeview", background=[("selected", "#D8E5FF")], foreground=[("selected", "#14213D")])
        style.configure("TProgressbar", troughcolor="#E4E9F2", background="#2457D6")

        outer = ttk.Frame(root, padding=20)
        outer.pack(fill="both", expand=True)

        brand_row = ttk.Frame(outer)
        brand_row.pack(anchor="w", pady=(0, 4))
        ttk.Label(brand_row, image=self.header_logo).pack(side="left", padx=(0, 12))
        brand_text = ttk.Frame(brand_row)
        brand_text.pack(side="left", anchor="center")
        ttk.Label(brand_text, text="RepoSentry", style="Title.TLabel").pack(anchor="w")
        ttk.Label(brand_text, text="GITHUB DEPENDENCY SECURITY", style="Sub.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Check public GitHub repositories for known dependency vulnerabilities.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(3, 4))
        ttk.Label(
            outer,
            text="Supports exact requirements.txt and package.json pins, plus direct Maven dependencies. Repository code is never run.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(0, 14))

        scan_row = ttk.Frame(outer)
        scan_row.pack(fill="x", pady=(0, 10))
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(scan_row, textvariable=self.url_var)
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.url_entry.insert(0, "https://github.com/owner/repository")
        self.scan_button = ttk.Button(scan_row, text="Scan repository", command=self.start_scan)
        self.scan_button.pack(side="left", padx=(10, 0), ipadx=12, ipady=5)

        self.status_var = tk.StringVar(value="Ready. Public repositories only.")
        ttk.Label(outer, textvariable=self.status_var).pack(anchor="w", pady=(0, 8))
        self.summary_var = tk.StringVar(value="Scan history is stored locally in SQLite.")
        ttk.Label(outer, textvariable=self.summary_var, style="Sub.TLabel").pack(anchor="w", pady=(0, 8))
        self.progressbar = ttk.Progressbar(outer, mode="indeterminate")
        self.progressbar.pack_forget()

        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)

        findings_tab = ttk.Frame(self.tabs, padding=10)
        history_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(findings_tab, text="Findings")
        self.tabs.add(history_tab, text="Scan history")

        findings_tools = ttk.Frame(findings_tab)
        findings_tools.pack(fill="x", pady=(0, 6))
        ttk.Label(findings_tools, text="Search").pack(side="left", padx=(0, 6))
        self.search_var = tk.StringVar()
        ttk.Entry(findings_tools, textvariable=self.search_var, width=28).pack(side="left")
        self.search_var.trace_add("write", self.apply_findings_filter)
        ttk.Label(findings_tools, text="Severity").pack(side="left", padx=(14, 6))
        self.severity_var = tk.StringVar(value="All")
        severity_box = ttk.Combobox(
            findings_tools,
            textvariable=self.severity_var,
            values=("All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"),
            width=12,
            state="readonly",
        )
        severity_box.pack(side="left")
        severity_box.bind("<<ComboboxSelected>>", self.apply_findings_filter)
        self.export_button = ttk.Button(findings_tools, text="Export CSV", command=self.export_report)
        self.export_button.pack(side="right")
        self.results_note_var = tk.StringVar(value="Scan a repository or load a saved scan to view findings.")
        ttk.Label(findings_tab, textvariable=self.results_note_var, style="Sub.TLabel").pack(
            anchor="w", pady=(0, 6)
        )

        self.finding_tree = self.make_tree(
            findings_tab,
            (
                ("severity", "Severity", 90),
                ("package", "Package", 190),
                ("version", "Version", 100),
                ("ecosystem", "Ecosystem", 90),
                ("advisory", "Advisory", 160),
                ("summary", "Summary", 340),
                ("manifest", "Manifest", 220),
            ),
        )
        self.finding_tree.bind("<Double-1>", self.open_selected_advisory)
        for tag, color in (
            ("critical", "#B42318"),
            ("high", "#C2410C"),
            ("medium", "#9A6700"),
            ("low", "#176B45"),
            ("unknown", "#596579"),
        ):
            self.finding_tree.tag_configure(tag, foreground=color)

        history_actions = ttk.Frame(history_tab)
        history_actions.pack(fill="x", pady=(0, 8))
        ttk.Button(history_actions, text="Load selected scan", command=self.load_selected_scan).pack(side="left")
        self.history_tree = self.make_tree(
            history_tab,
            (
                ("scan_id", "Scan", 70),
                ("url", "Repository", 280),
                ("scanned_at", "Scanned at", 190),
                ("status", "Status", 90),
                ("dependencies", "Dependencies", 100),
                ("findings", "Findings", 80),
                ("commit", "Commit", 160),
            ),
        )
        self.refresh_history()
        saved_scans = self.history_tree.get_children()
        if saved_scans:
            self.history_tree.selection_set(saved_scans[0])
            self.load_selected_scan()

    @staticmethod
    def make_tree(parent: ttk.Frame, columns: tuple[tuple[str, str, int], ...]) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        names = [item[0] for item in columns]
        tree = ttk.Treeview(frame, columns=names, show="headings", height=18)
        for name, heading, width in columns:
            tree.heading(name, text=heading)
            tree.column(name, width=width, minwidth=65, anchor="w", stretch=True)
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    def start_scan(self) -> None:
        url = self.url_var.get().strip()
        try:
            validate_github_url(url)
        except RepoSentryError as error:
            messagebox.showerror("Invalid repository URL", str(error), parent=self.root)
            return

        self.scan_button.configure(state="disabled")
        self.status_var.set("Fetching the public repository and checking its dependencies…")
        self.summary_var.set("RepoSentry reads supported manifest files only; it does not run repository code.")
        self.current_findings = []
        self.finding_tree.delete(*self.finding_tree.get_children())
        self.result_links.clear()
        self.results_note_var.set("Scanning the repository. This can take a little while.")
        self.tabs.select(0)
        self.progressbar.pack(fill="x", pady=(0, 10))
        self.progressbar.start(10)

        worker = threading.Thread(target=self.scan_worker, args=(url,), daemon=True)
        worker.start()
        self.root.after(100, self.poll_worker)

    def scan_worker(self, url: str) -> None:
        try:
            self.worker_queue.put(("success", scan_repository(url)))
        except Exception as error:
            self.worker_queue.put(("error", str(error)))

    def poll_worker(self) -> None:
        try:
            result_type, payload = self.worker_queue.get_nowait()
        except queue.Empty:
            self.root.after(100, self.poll_worker)
            return

        self.scan_button.configure(state="normal")
        self.progressbar.stop()
        self.progressbar.pack_forget()
        if result_type == "error":
            self.status_var.set("Scan could not be completed.")
            self.results_note_var.set("No results are available for this scan.")
            messagebox.showerror("RepoSentry scan error", payload, parent=self.root)
            return

        dependencies = payload["dependencies"]
        findings = payload["findings"]
        self.show_findings(findings)
        self.refresh_history()
        if not dependencies:
            self.status_var.set(f"Scan #{payload['scan_id']} complete.")
            self.summary_var.set(
                "No supported pinned dependencies found. Check requirements.txt, package.json, or pom.xml files."
            )
            self.results_note_var.set("No supported dependency versions were found in this repository.")
        elif findings:
            self.status_var.set(f"Scan #{payload['scan_id']} complete.")
            self.summary_var.set(
                f"{len(findings)} known finding(s) across {len(dependencies)} parsed dependency version(s). "
                f"Commit {payload['commit_sha'][:10]}."
            )
        else:
            self.status_var.set(f"Scan #{payload['scan_id']} complete.")
            self.summary_var.set(
                f"No known findings for {len(dependencies)} parsed dependency version(s). "
                f"Commit {payload['commit_sha'][:10]}."
            )

    def show_findings(self, findings: list[dict | sqlite3.Row]) -> None:
        self.current_findings = [dict(finding) for finding in findings]
        self.search_var.set("")
        self.severity_var.set("All")
        self.apply_findings_filter()
        if not self.current_findings:
            self.results_note_var.set("No known findings were saved for this scan.")

    def apply_findings_filter(self, *_args) -> None:
        self.finding_tree.delete(*self.finding_tree.get_children())
        self.result_links.clear()
        query = self.search_var.get().strip().lower()
        selected_severity = self.severity_var.get()
        visible = 0

        for index, finding in enumerate(self.current_findings):
            severity = finding.get("severity", "UNKNOWN").upper()
            searchable = " ".join(
                str(finding.get(field, ""))
                for field in ("package_name", "version", "advisory_id", "summary", "manifest_path")
            ).lower()
            if selected_severity != "All" and severity != selected_severity:
                continue
            if query and query not in searchable:
                continue

            iid = f"finding-{index}"
            values = (
                severity,
                finding.get("package_name", ""),
                finding.get("version", ""),
                finding.get("ecosystem", ""),
                finding.get("advisory_id", ""),
                finding.get("summary", ""),
                finding.get("manifest_path", ""),
            )
            self.finding_tree.insert("", "end", iid=iid, values=values, tags=(severity.lower(),))
            self.result_links[iid] = finding.get("reference_url", "")
            visible += 1

        if self.current_findings:
            if visible == len(self.current_findings):
                self.results_note_var.set(
                    f"{visible} finding(s). Double-click a row to open its advisory."
                )
            else:
                self.results_note_var.set(
                    f"Showing {visible} of {len(self.current_findings)} findings."
                )

    def export_report(self) -> None:
        if not self.current_findings:
            messagebox.showinfo("Export findings", "There are no findings in the selected scan.", parent=self.root)
            return

        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export RepoSentry findings",
            defaultextension=".csv",
            filetypes=(("CSV spreadsheet", "*.csv"),),
            initialfile="reposentry-findings.csv",
        )
        if not destination:
            return

        fields = (
            "severity",
            "package_name",
            "version",
            "ecosystem",
            "advisory_id",
            "summary",
            "manifest_path",
            "reference_url",
        )
        try:
            with open(destination, "w", newline="", encoding="utf-8") as report:
                writer = csv.DictWriter(report, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(self.current_findings)
        except OSError as error:
            messagebox.showerror("Export failed", str(error), parent=self.root)
            return
        self.status_var.set(f"Exported {len(self.current_findings)} findings to CSV.")

    def open_selected_advisory(self, _event=None) -> None:
        selection = self.finding_tree.selection()
        if selection:
            url = self.result_links.get(selection[0])
            if url:
                webbrowser.open(url)

    def refresh_history(self) -> None:
        self.history_tree.delete(*self.history_tree.get_children())
        for row in get_history():
            self.history_tree.insert(
                "",
                "end",
                iid=str(row["id"]),
                values=(
                    row["id"],
                    row["url"],
                    row["scanned_at"],
                    row["status"],
                    row["dependency_count"],
                    row["finding_count"],
                    row["commit_sha"][:12],
                ),
            )

    def load_selected_scan(self) -> None:
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showinfo("Scan history", "Select a scan first.", parent=self.root)
            return
        scan_id = int(selection[0])
        findings = get_scan_findings(scan_id)
        self.show_findings(findings)
        self.tabs.select(0)
        self.status_var.set(f"Loaded scan #{scan_id} from local history.")
        self.summary_var.set(f"{len(findings)} known finding(s) saved for this scan.")



def main() -> None:
    if sys.platform == "darwin" and tk.TkVersion < 8.6:
        raise SystemExit(
            "RepoSentry needs Tk 8.6 or newer on macOS. "
            "Use a current Python.org macOS build; this Python is linked to Tk "
            f"{tk.TkVersion:.1f}."
        )
    initialize_database()
    root = tk.Tk()
    RepoSentryApp(root)
    root.mainloop()



if __name__ == "__main__":
    main()
