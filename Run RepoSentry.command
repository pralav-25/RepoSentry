#!/bin/zsh
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

FRAMEWORK_PYTHON=/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13
if [ -x "$FRAMEWORK_PYTHON" ]; then
  PYTHON_BIN="$FRAMEWORK_PYTHON"
elif command -v python3.13 >/dev/null 2>&1; then
  PYTHON_BIN=python3.13
else
  PYTHON_BIN=python3
fi

if ! "$PYTHON_BIN" -c 'import tkinter, sys; sys.exit(0 if tkinter.TkVersion >= 8.6 else 1)' 2>/dev/null; then
  echo "RepoSentry needs Tk 8.6 or newer for a working macOS interface."
  echo "This Mac's current Python uses Tk 8.5. Install a current Python from python.org, then run this launcher again."
  exit 1
fi

exec "$PYTHON_BIN" app.py

