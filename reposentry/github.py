"""Validate repository URLs and retrieve pinned GitHub snapshots."""

import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .config import MAX_ARCHIVE_BYTES, USER_AGENT
from .domain import RepoSentryError


def validate_github_url(url: str) -> tuple[str, str, str]:
    try:
        parsed = urlparse(url.strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise RepoSentryError("Enter a valid GitHub repository URL.") from error

    if parsed.scheme != "https" or hostname not in {"github.com", "www.github.com"}:
        raise RepoSentryError("Enter a full public GitHub URL, such as https://github.com/owner/repository.")

    if parsed.username or parsed.password or port is not None or parsed.query or parsed.fragment:
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
