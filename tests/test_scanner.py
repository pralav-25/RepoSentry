"""Exercise the complete scan path with local fixtures and mocked remote services."""

import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from reposentry import scanner, storage
from reposentry.domain import RepoSentryError


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        setting = patch.object(storage, "DB_PATH", Path(self.directory.name) / "history.db")
        setting.start()
        self.addCleanup(setting.stop)
        storage.initialize_database()

    def test_pinned_snapshot_is_parsed_checked_and_saved(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("repo/requirements.txt", "Example==1.2.3")
        sha = "a" * 40
        with patch.object(scanner, "read_json_url", side_effect=[{"default_branch": "main"}, {"sha": sha}]), \
             patch.object(scanner, "download_archive", return_value=data.getvalue()) as download, \
             patch("reposentry.advisories.osv_query", return_value=[{"id": "OSV-TEST"}]):
            result = scanner.scan_repository("https://github.com/owner/repo.git")
        self.assertEqual(result["url"], "https://github.com/owner/repo")
        self.assertEqual(result["commit_sha"], sha)
        download.assert_called_once_with(f"https://api.github.com/repos/owner/repo/zipball/{sha}")
        findings = storage.get_scan_findings(result["scan_id"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["package_name"], "example")
        self.assertEqual(findings[0]["advisory_id"], "OSV-TEST")

    def test_remote_failure_does_not_save_a_complete_scan(self):
        with patch.object(scanner, "read_json_url", side_effect=RepoSentryError("Unavailable")):
            with self.assertRaises(RepoSentryError):
                scanner.scan_repository("https://github.com/owner/repo")
        self.assertEqual(storage.get_history(), [])


if __name__ == "__main__":
    unittest.main()
