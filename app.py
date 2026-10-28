#!/usr/bin/env python3
"""RepoSentry: an educational GitHub dependency vulnerability checker."""

from __future__ import annotations

import csv
import io
import json
import queue
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import webbrowser
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


APP_DIR = Path(__file__).resolve().parent
JAVA_SOURCE = APP_DIR / "java" / "RepoScanner.java"
JAVA_BUILD = APP_DIR / "build"
DB_PATH = APP_DIR / "reposentry.db"

MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_FILES = 8000
MAX_MANIFEST_BYTES = 512 * 1024
MAX_MANIFESTS_PER_TYPE = 20
MAX_DEPENDENCIES = 50
USER_AGENT = "RepoSentry-Student-Project/1.0"


class RepoSentryError(Exception):
    """An error that is safe to show in the desktop UI."""


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str
    manifest: str


def db_connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    with db_connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS repositories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                owner TEXT NOT NULL,
                name TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository_id INTEGER NOT NULL REFERENCES repositories(id),
                commit_sha TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                status TEXT NOT NULL,
                dependency_count INTEGER NOT NULL DEFAULT 0,
                finding_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS dependencies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                manifest_path TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dependency_id INTEGER NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
                advisory_id TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity TEXT NOT NULL,
                reference_url TEXT NOT NULL
            );
            """
        )


def validate_github_url(url: str) -> tuple[str, str, str]:
    parsed = urlparse(url.strip())
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        raise RepoSentryError("Enter a full public GitHub URL, such as https://github.com/owner/repository.")

    if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        raise RepoSentryError("Please enter only the GitHub repository URL.")

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise RepoSentryError("Use the repository's main URL, not a branch, file, or folder link.")

    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]

    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repository):
        raise RepoSentryError("The GitHub owner or repository name contains unsupported characters.")

    canonical = f"https://github.com/{owner}/{repository}"
    return owner, repository, canonical


def read_json_url(url: str) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=25) as response:
            data = response.read(2 * 1024 * 1024 + 1)
    except HTTPError as error:
        if error.code == 404:
            raise RepoSentryError("GitHub could not find this public repository. Private repositories are not supported yet.") from error
        if error.code == 403:
            raise RepoSentryError("GitHub temporarily refused the request. Please wait a little and try again.") from error
        raise RepoSentryError(f"GitHub returned HTTP {error.code}.") from error
    except URLError as error:
        raise RepoSentryError(f"Could not reach GitHub: {error.reason}") from error

    if len(data) > 2 * 1024 * 1024:
        raise RepoSentryError("GitHub returned an unexpectedly large response.")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RepoSentryError("GitHub returned a response RepoSentry could not read.") from error


def download_archive(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    try:
        with urlopen(request, timeout=45) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_ARCHIVE_BYTES:
                raise RepoSentryError("This repository archive is over the 25 MB class-project limit.")
            data = response.read(MAX_ARCHIVE_BYTES + 1)
    except HTTPError as error:
        raise RepoSentryError(f"GitHub could not download this repository (HTTP {error.code}).") from error
    except URLError as error:
        raise RepoSentryError(f"Could not download the repository: {error.reason}") from error

    if len(data) > MAX_ARCHIVE_BYTES:
        raise RepoSentryError("This repository archive is over the 25 MB class-project limit.")
    return data


def parse_requirements(contents: bytes, path: str) -> list[Dependency]:
    text = contents.decode("utf-8", errors="replace")
    pattern = re.compile(
        r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*$"
    )
    dependencies: list[Dependency] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        match = pattern.match(line)
        if not match:
            continue
        package_name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        dependencies.append(Dependency("PyPI", package_name, match.group(2), path))
    return dependencies


def parse_npm_package_json(contents: bytes, path: str) -> list[Dependency]:
    try:
        package_data = json.loads(contents.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RepoSentryError(f"Could not parse package.json at {path}.") from error

    if not isinstance(package_data, dict):
        return []

    # The app checks exact semantic versions only. Ranges, tags, workspace
    # references, and git URLs need a lockfile resolver and are skipped.
    exact_version = re.compile(
        r"^v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
        r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
    )
    dependencies: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        entries = package_data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, version in entries.items():
            if (
                isinstance(name, str)
                and name.strip()
                and isinstance(version, str)
                and exact_version.fullmatch(version.strip())
            ):
                dependencies.append(Dependency("npm", name, version.strip(), path))
    return dependencies


def ensure_java_compiled() -> None:
    if not shutil.which("javac") or not shutil.which("java"):
        raise RepoSentryError("Java JDK is required to read Maven dependencies. Install a JDK with javac and java.")

    class_file = JAVA_BUILD / "RepoScanner.class"
    if class_file.exists() and class_file.stat().st_mtime >= JAVA_SOURCE.stat().st_mtime:
        return

    JAVA_BUILD.mkdir(parents=True, exist_ok=True)
    process = subprocess.run(
        ["javac", "-encoding", "UTF-8", "-d", str(JAVA_BUILD), str(JAVA_SOURCE)],
        capture_output=True,
        text=True,
        timeout=45,
    )
    if process.returncode != 0:
        message = process.stderr.strip() or "javac could not compile the Maven reader."
        raise RepoSentryError(message[-1200:])


def parse_maven_pom(contents: bytes, path: str) -> list[Dependency]:
    ensure_java_compiled()
    with tempfile.TemporaryDirectory(prefix="reposentry-") as temp_dir:
        pom_file = Path(temp_dir) / "pom.xml"
        pom_file.write_bytes(contents)
        process = subprocess.run(
            ["java", "-cp", str(JAVA_BUILD), "RepoScanner", str(pom_file)],
            capture_output=True,
            text=True,
            timeout=30,
        )

    if process.returncode != 0:
        message = process.stderr.strip() or "Java could not read this Maven file."
        raise RepoSentryError(message[-1200:])

    dependencies: list[Dependency] = []
    for line in process.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        group, artifact, version = (part.strip() for part in parts)
        if group and artifact and version:
            dependencies.append(Dependency("Maven", f"{group}:{artifact}", version, path))
    return dependencies


def read_manifest_dependencies(archive_data: bytes) -> list[Dependency]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_data))
    except zipfile.BadZipFile as error:
        raise RepoSentryError("GitHub's repository archive was not a valid ZIP file.") from error

    with archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise RepoSentryError("This repository contains too many files for the class-project limit.")

        requirements_files = []
        pom_files = []
        package_json_files = []
        for info in members:
            if info.is_dir() or info.file_size > MAX_MANIFEST_BYTES:
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                continue

            basename = PurePosixPath(info.filename).name.lower()
            if basename == "requirements.txt" and len(requirements_files) < MAX_MANIFESTS_PER_TYPE:
                requirements_files.append(info)
            elif basename == "pom.xml" and len(pom_files) < MAX_MANIFESTS_PER_TYPE:
                pom_files.append(info)
            elif basename == "package.json" and len(package_json_files) < MAX_MANIFESTS_PER_TYPE:
                package_json_files.append(info)

        dependencies: list[Dependency] = []
        for info in requirements_files:
            dependencies.extend(parse_requirements(archive.read(info), info.filename))

        for info in pom_files:
            dependencies.extend(parse_maven_pom(archive.read(info), info.filename))

        for info in package_json_files:
            dependencies.extend(parse_npm_package_json(archive.read(info), info.filename))

    deduplicated: dict[tuple[str, str, str], Dependency] = {}
    for dependency in dependencies:
        key = (dependency.ecosystem, dependency.name.lower(), dependency.version)
        if key in deduplicated:
            existing = deduplicated[key]
            if dependency.manifest not in existing.manifest.split(", "):
                existing.manifest = f"{existing.manifest}, {dependency.manifest}"
        else:
            deduplicated[key] = dependency

    result = list(deduplicated.values())
    if len(result) > MAX_DEPENDENCIES:
        raise RepoSentryError(
            f"RepoSentry found {len(result)} supported dependencies. The current demo limit is {MAX_DEPENDENCIES} per scan."
        )
    return result


def osv_query(dependency: Dependency) -> list[dict]:
    payload = {
        "package": {"name": dependency.name, "ecosystem": dependency.ecosystem},
        "version": dependency.version,
    }
    request = Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urlopen(request, timeout=25) as response:
            data = response.read(4 * 1024 * 1024 + 1)
    except HTTPError as error:
        raise RepoSentryError(f"The vulnerability lookup service returned HTTP {error.code}.") from error
    except URLError as error:
        raise RepoSentryError(f"Could not reach the vulnerability lookup service: {error.reason}") from error

    if len(data) > 4 * 1024 * 1024:
        raise RepoSentryError("The vulnerability service returned an unexpectedly large response.")
    try:
        result = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RepoSentryError("The vulnerability service returned a response RepoSentry could not read.") from error
    return result.get("vulns") or []


def severity_label(vulnerability: dict) -> str:
    database_specific = vulnerability.get("database_specific") or {}
    label = database_specific.get("severity")
    if isinstance(label, str) and label.strip():
        normalized = label.strip().upper()
        if normalized in {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"}:
            return "MEDIUM" if normalized == "MODERATE" else normalized

    for item in vulnerability.get("severity") or []:
        raw_score = str(item.get("score", "")).strip()
        try:
            score = float(raw_score)
        except (ValueError, TypeError):
            continue
        if score >= 9:
            return "CRITICAL"
        if score >= 7:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW"

    return "UNKNOWN"


def advisory_reference(vulnerability: dict) -> tuple[str, str]:
    advisory_id = vulnerability.get("id") or "Unknown advisory"
    references = vulnerability.get("references") or []
    for reference in references:
        url = reference.get("url", "")
        if url.startswith("https://"):
            return advisory_id, url
    return advisory_id, f"https://osv.dev/vulnerability/{quote(advisory_id, safe='')}"


def check_dependencies(dependencies: list[Dependency]) -> list[dict]:
    findings: list[dict] = []
    for dependency in dependencies:
        for vulnerability in osv_query(dependency):
            advisory_id, reference_url = advisory_reference(vulnerability)
            details = vulnerability.get("summary") or (vulnerability.get("details") or "").splitlines()[0]
            findings.append(
                {
                    "ecosystem": dependency.ecosystem,
                    "package_name": dependency.name,
                    "version": dependency.version,
                    "manifest_path": dependency.manifest,
                    "advisory_id": advisory_id,
                    "summary": details or "Known vulnerability record; open the advisory for details.",
                    "severity": severity_label(vulnerability),
                    "reference_url": reference_url,
                }
            )
    return findings


def save_scan(
    owner: str,
    repository: str,
    canonical_url: str,
    commit_sha: str,
    dependencies: list[Dependency],
    findings: list[dict],
) -> int:
    scanned_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    with db_connect() as connection:
        connection.execute(
            """
            INSERT INTO repositories(url, owner, name, added_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET owner = excluded.owner, name = excluded.name
            """,
            (canonical_url, owner, repository, scanned_at),
        )
        repo_row = connection.execute("SELECT id FROM repositories WHERE url = ?", (canonical_url,)).fetchone()
        cursor = connection.execute(
            """
            INSERT INTO scans(repository_id, commit_sha, scanned_at, status, dependency_count, finding_count)
            VALUES (?, ?, ?, 'complete', ?, ?)
            """,
            (repo_row["id"], commit_sha, scanned_at, len(dependencies), len(findings)),
        )
        scan_id = cursor.lastrowid

        dependency_ids: dict[tuple[str, str, str], int] = {}
        for dependency in dependencies:
            cursor = connection.execute(
                """
                INSERT INTO dependencies(scan_id, ecosystem, package_name, version, manifest_path)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    dependency.ecosystem,
                    dependency.name,
                    dependency.version,
                    dependency.manifest,
                ),
            )
            dependency_ids[(dependency.ecosystem, dependency.name, dependency.version)] = cursor.lastrowid

        for finding in findings:
            dependency_id = dependency_ids[
                (finding["ecosystem"], finding["package_name"], finding["version"])
            ]
            connection.execute(
                """
                INSERT INTO findings(dependency_id, advisory_id, summary, severity, reference_url)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    dependency_id,
                    finding["advisory_id"],
                    finding["summary"],
                    finding["severity"],
                    finding["reference_url"],
                ),
            )
    return int(scan_id)


def scan_repository(url: str) -> dict:
    owner, repository, canonical_url = validate_github_url(url)
    api_root = f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repository, safe='')}"

    metadata = read_json_url(api_root)
    branch = metadata.get("default_branch")
    if not branch:
        raise RepoSentryError("GitHub did not provide a default branch for this repository.")

    commit = read_json_url(f"{api_root}/commits/{quote(branch, safe='')}")
    commit_sha = commit.get("sha")
    if not commit_sha:
        raise RepoSentryError("GitHub did not provide a commit ID for the default branch.")

    archive_data = download_archive(f"{api_root}/zipball/{quote(commit_sha, safe='')}")
    dependencies = read_manifest_dependencies(archive_data)
    findings = check_dependencies(dependencies)
    scan_id = save_scan(owner, repository, canonical_url, commit_sha, dependencies, findings)

    return {
        "scan_id": scan_id,
        "url": canonical_url,
        "commit_sha": commit_sha,
        "dependencies": dependencies,
        "findings": findings,
    }


def get_history() -> list[sqlite3.Row]:
    with db_connect() as connection:
        return connection.execute(
            """
            SELECT scans.id, repositories.url, scans.commit_sha, scans.scanned_at,
                   scans.status, scans.dependency_count, scans.finding_count
            FROM scans
            JOIN repositories ON repositories.id = scans.repository_id
            ORDER BY scans.id DESC
            LIMIT 100
            """
        ).fetchall()


def get_scan_findings(scan_id: int) -> list[sqlite3.Row]:
    with db_connect() as connection:
        return connection.execute(
            """
            SELECT dependencies.package_name, dependencies.version, dependencies.ecosystem,
                   findings.severity, findings.advisory_id, findings.summary,
                   dependencies.manifest_path, findings.reference_url
            FROM dependencies
            JOIN findings ON findings.dependency_id = dependencies.id
            WHERE dependencies.scan_id = ?
            ORDER BY findings.severity, dependencies.package_name
            """,
            (scan_id,),
        ).fetchall()


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

