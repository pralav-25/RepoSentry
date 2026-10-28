# RepoSentry

RepoSentry is a desktop application for checking supported dependencies in a public GitHub repository for known published vulnerabilities. It is built with Tkinter, Python, Java, and SQLite.

## Launch

On this Mac, double-click RepoSentry.app to launch the branded Mac app. Run RepoSentry.command is included as a terminal-friendly fallback. Both use the installed Python.org 3.13 interpreter with Tk 8.6.

You can also run:

    /Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 app.py

Requirements: Python 3 with Tkinter 8.6 or newer on macOS, Java JDK (javac and java), and an internet connection. The Xcode-bundled Python on this laptop uses Tk 8.5, which renders Tk windows blank here; use the included launcher.

If HTTPS calls fail with a certificate-verification error after installing Python from python.org, run the matching `Install Certificates.command` from `/Applications/Python 3.13/` once.

## What it does

1. Fetches a public GitHub repository snapshot pinned to a commit.
2. Reads supported dependency files as data.
3. Uses Java to read direct Maven dependencies and Python to read pinned Python requirements.
4. Checks package versions against OSV's public vulnerability service.
5. Saves scan history and findings in a local SQLite database.
6. Loads the latest saved scan at startup, shows results with search and severity filters, opens advisories on double-click, and exports findings to CSV.

## Supported input

- Python requirements.txt entries with exact versions, for example package==1.2.3.
- Direct Maven pom.xml dependencies with literal versions.

This first version skips unpinned Python entries, version ranges, Maven property versions, private repositories, and dependency formats outside those files. A scan is limited to 25 MB and 50 parsed dependency versions to keep the class demo manageable.

## Demo repository

Paste <https://github.com/pralav-25/reposentry-demo> into the app to try a scan. It contains intentionally outdated Python and Maven dependency versions chosen to return known OSV advisories. Keep these fixture versions for scanner demonstrations only; do not copy them into a real project.

## Project structure

- app.py: Tkinter interface, GitHub download, OSV lookup, SQLite operations, filtering, and CSV export.
- assets/: RepoSentry shield-and-check logo in SVG, PNG, and macOS app icon formats.
- RepoSentry.app/: Finder-launchable macOS app bundle with the RepoSentry icon; it uses the neighboring source files.
- java/RepoScanner.java: secure, read-only Maven XML dependency parser.
- build/: Java class output, compiled automatically when a Maven file is scanned.
- reposentry.db: local database, created at first launch.
- VIVA_NOTES.md: short project explanation and demo scope.

## Scope and safety

RepoSentry reports known dependency advisories. It is not a full source-code audit and cannot guarantee that a repository is secure. It does not execute repository code or install packages. Downloaded files are inspected as data and the ZIP archive is not extracted to disk.

