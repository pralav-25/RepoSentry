"""Persist complete scans and retrieve local scan history."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

from .config import DB_PATH
from .domain import Dependency


def db_connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database_connection() -> Iterator[sqlite3.Connection]:
    """Commit or roll back a unit of work, then always release its connection."""
    connection = db_connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    with database_connection() as connection:
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


def save_scan(
    owner: str,
    repository: str,
    canonical_url: str,
    commit_sha: str,
    dependencies: list[Dependency],
    findings: list[dict],
) -> int:
    scanned_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    with database_connection() as connection:
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


def get_history() -> list[sqlite3.Row]:
    with database_connection() as connection:
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
    with database_connection() as connection:
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
