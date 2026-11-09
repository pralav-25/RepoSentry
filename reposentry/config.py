"""Application paths and bounded scan limits."""

from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
JAVA_SOURCE = APP_DIR / "java" / "RepoScanner.java"
JAVA_BUILD = APP_DIR / "build"
DB_PATH = APP_DIR / "reposentry.db"

MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_FILES = 8000
MAX_MANIFEST_BYTES = 512 * 1024
MAX_MANIFESTS_PER_TYPE = 20
MAX_DEPENDENCIES = 50
USER_AGENT = "RepoSentry-Student-Project/1.0"
