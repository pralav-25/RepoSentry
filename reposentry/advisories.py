"""Look up dependency advisories and normalize their display fields."""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .config import USER_AGENT
from .domain import Dependency, RepoSentryError


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


def advisory_summary(vulnerability: dict) -> str:
    for field in ("summary", "details"):
        for line in (vulnerability.get(field) or "").splitlines():
            if line.strip():
                return line.strip()
    return "Known vulnerability record; open the advisory for details."


def check_dependencies(dependencies: list[Dependency]) -> list[dict]:
    findings: list[dict] = []
    for dependency in dependencies:
        for vulnerability in osv_query(dependency):
            advisory_id, reference_url = advisory_reference(vulnerability)
            findings.append(
                {
                    "ecosystem": dependency.ecosystem,
                    "package_name": dependency.name,
                    "version": dependency.version,
                    "manifest_path": dependency.manifest,
                    "advisory_id": advisory_id,
                    "summary": advisory_summary(vulnerability),
                    "severity": severity_label(vulnerability),
                    "reference_url": reference_url,
                }
            )
    return findings
