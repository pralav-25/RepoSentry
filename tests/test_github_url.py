"""Repository URL validation stays safe to display in the desktop UI."""

import unittest

from app import RepoSentryError, validate_github_url


class GitHubURLTests(unittest.TestCase):
    def test_valid_urls_are_canonicalized(self):
        for url in (
            "https://github.com/owner/repository",
            "  https://www.github.com/owner/repository.git/  ",
        ):
            with self.subTest(url=url):
                self.assertEqual(
                    validate_github_url(url),
                    ("owner", "repository", "https://github.com/owner/repository"),
                )

    def test_malformed_ports_raise_displayable_error(self):
        for port in ("abc", "99999"):
            with self.subTest(port=port):
                with self.assertRaises(RepoSentryError):
                    validate_github_url(f"https://github.com:{port}/owner/repository")

    def test_explicit_ports_are_rejected_including_zero(self):
        for port in ("0", "443"):
            with self.subTest(port=port):
                with self.assertRaises(RepoSentryError):
                    validate_github_url(f"https://github.com:{port}/owner/repository")

    def test_malformed_ipv6_raises_displayable_error(self):
        with self.assertRaises(RepoSentryError):
            validate_github_url("https://[github.com/owner/repository")

    def test_non_repository_urls_are_rejected(self):
        for url in (
            "http://github.com/owner/repository",
            "https://example.com/owner/repository",
            "https://github.com/owner/repository/tree/main",
            "https://user:password@github.com/owner/repository",
            "https://github.com/owner/repository?tab=readme",
            "https://github.com/owner/repository#readme",
        ):
            with self.subTest(url=url):
                with self.assertRaises(RepoSentryError):
                    validate_github_url(url)


if __name__ == "__main__":
    unittest.main()
