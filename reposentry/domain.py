"""Shared scan data and displayable errors."""

from dataclasses import dataclass


class RepoSentryError(Exception):
    """An error that is safe to show in the desktop UI."""


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str
    manifest: str
