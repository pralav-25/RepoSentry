"""Offline manifest fixtures cover the scanner's supported-input boundaries."""

import io
import json
import shutil
import unittest
import zipfile
from unittest.mock import patch

from reposentry.domain import RepoSentryError
from reposentry.manifests import (
    parse_maven_pom, parse_npm_package_json, parse_requirements, read_manifest_dependencies,
)


def archive_bytes(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for name, contents in files.items():
            archive.writestr(name, contents)
    return data.getvalue()


class ManifestTests(unittest.TestCase):
    def test_requirements_normalize_names_and_skip_unresolved_versions(self):
        dependencies = parse_requirements(
            b"Some_Package[extra]==1.2.3 # pinned\nrequests>=2\n-e git+https://example.com/repo\n",
            "requirements.txt",
        )
        self.assertEqual([(d.ecosystem, d.name, d.version) for d in dependencies], [("PyPI", "some-package", "1.2.3")])

    def test_npm_reads_both_sections_and_skips_ranges_and_tags(self):
        contents = json.dumps({
            "dependencies": {"exact": "1.2.3", "range": "^1.2.3", "tag": "latest"},
            "devDependencies": {"preview": "2.0.0-beta.1"},
        }).encode()
        dependencies = parse_npm_package_json(contents, "package.json")
        self.assertEqual([(d.name, d.version) for d in dependencies], [("exact", "1.2.3"), ("preview", "2.0.0-beta.1")])

    def test_archive_combines_duplicate_pins_without_losing_manifest_paths(self):
        dependencies = read_manifest_dependencies(archive_bytes({
            "repo/requirements.txt": "Some_Package==1.2.3",
            "repo/service/requirements.txt": "some-package==1.2.3",
        }))
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0].manifest, "repo/requirements.txt, repo/service/requirements.txt")

    def test_invalid_archive_is_a_displayable_error(self):
        with self.assertRaises(RepoSentryError):
            read_manifest_dependencies(b"not a ZIP archive")

    def test_dependency_limit_rejects_a_partial_scan(self):
        data = archive_bytes({"repo/requirements.txt": "first==1.0\nsecond==2.0"})
        with patch("reposentry.manifests.MAX_DEPENDENCIES", 1):
            with self.assertRaisesRegex(RepoSentryError, "found 2 supported dependencies"):
                read_manifest_dependencies(data)

    @unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "Java JDK unavailable")
    def test_maven_only_reads_direct_literal_versions(self):
        contents = b"""<project xmlns="http://maven.apache.org/POM/4.0.0">
          <dependencyManagement><dependencies><dependency><groupId>managed</groupId>
            <artifactId>ignored</artifactId><version>1.0</version></dependency></dependencies></dependencyManagement>
          <dependencies>
            <dependency><groupId>org.example</groupId><artifactId>direct</artifactId><version>1.2.3</version></dependency>
            <dependency><groupId>org.example</groupId><artifactId>property</artifactId><version>${library.version}</version></dependency>
          </dependencies>
        </project>"""
        dependencies = parse_maven_pom(contents, "pom.xml")
        self.assertEqual([(d.name, d.version) for d in dependencies], [("org.example:direct", "1.2.3")])


if __name__ == "__main__":
    unittest.main()
