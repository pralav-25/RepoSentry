"""Advisory formatting must not turn an incomplete description into a failed scan."""

import unittest
from unittest.mock import patch

from reposentry.advisories import check_dependencies
from reposentry.domain import Dependency


class AdvisoryTests(unittest.TestCase):
    def findings_for(self, advisory):
        dependency = Dependency("PyPI", "example", "1.2.3", "requirements.txt")
        with patch("reposentry.advisories.osv_query", return_value=[advisory]):
            return check_dependencies([dependency])

    def test_missing_and_empty_descriptions_use_a_fallback(self):
        for fields in ({}, {"summary": "", "details": ""}, {"details": "\n  \n"}):
            with self.subTest(fields=fields):
                findings = self.findings_for({"id": "OSV-TEST", **fields})
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["summary"], "Known vulnerability record; open the advisory for details.")
                self.assertEqual(findings[0]["reference_url"], "https://osv.dev/vulnerability/OSV-TEST")

    def test_details_use_first_nonempty_line(self):
        findings = self.findings_for({
            "id": "OSV-TEST", "summary": "  ",
            "details": "\n  Useful description.\nMore details.",
        })
        self.assertEqual(findings[0]["summary"], "Useful description.")

    def test_summary_and_moderate_severity_are_preserved(self):
        findings = self.findings_for({
            "id": "OSV-TEST", "summary": "Short description", "details": "Long description",
            "database_specific": {"severity": "MODERATE"},
            "references": [{"url": "https://example.com/advisory"}],
        })
        self.assertEqual(findings[0]["summary"], "Short description")
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["reference_url"], "https://example.com/advisory")


if __name__ == "__main__":
    unittest.main()
