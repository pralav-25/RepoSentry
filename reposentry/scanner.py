"""Coordinate repository retrieval, parsing, lookup, and persistence."""

from urllib.parse import quote

from .domain import RepoSentryError
from .github import download_archive, read_json_url, validate_github_url
from .manifests import read_manifest_dependencies
from .advisories import check_dependencies
from .storage import save_scan


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
