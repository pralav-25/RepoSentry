"""Read supported dependency manifests without executing repository code."""

import io
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from .config import (
    JAVA_BUILD, JAVA_SOURCE, MAX_ARCHIVE_FILES, MAX_DEPENDENCIES,
    MAX_MANIFEST_BYTES, MAX_MANIFESTS_PER_TYPE,
)
from .domain import Dependency, RepoSentryError


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
