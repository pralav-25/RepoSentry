"""Use a temporary database so tests never change the desktop scan history."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reposentry.domain import Dependency
from reposentry import storage


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        setting = patch.object(storage, "DB_PATH", Path(self.directory.name) / "history.db")
        setting.start()
        self.addCleanup(setting.stop)
        storage.initialize_database()
        self.dependency = Dependency("PyPI", "example", "1.2.3", "requirements.txt")
        self.finding = {
            "ecosystem": "PyPI", "package_name": "example", "version": "1.2.3",
            "advisory_id": "OSV-TEST", "summary": "Description", "severity": "HIGH",
            "reference_url": "https://example.com/advisory",
        }

    def save(self, findings):
        return storage.save_scan("owner", "repo", "https://github.com/owner/repo", "a" * 40, [self.dependency], findings)

    def test_complete_scan_round_trip(self):
        scan_id = self.save([self.finding])
        history = storage.get_history()
        findings = storage.get_scan_findings(scan_id)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["dependency_count"], 1)
        self.assertEqual(history[0]["finding_count"], 1)
        self.assertEqual(findings[0]["package_name"], "example")
        self.assertEqual(findings[0]["manifest_path"], "requirements.txt")
        self.assertEqual(findings[0]["advisory_id"], "OSV-TEST")

    def test_failed_write_rolls_back_the_whole_scan(self):
        invalid_finding = {**self.finding, "summary": None}
        with self.assertRaises(sqlite3.IntegrityError):
            self.save([invalid_finding])
        self.assertEqual(storage.get_history(), [])
        with storage.database_connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0], 0)

    def test_connection_is_closed_on_success_and_failure(self):
        with storage.database_connection() as connection:
            connection.execute("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        with self.assertRaisesRegex(RuntimeError, "example"):
            with storage.database_connection() as failed_connection:
                raise RuntimeError("example")
        with self.assertRaises(sqlite3.ProgrammingError):
            failed_connection.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
