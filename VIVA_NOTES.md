# RepoSentry — quick viva notes

## One-line description

RepoSentry checks supported dependency files in a public GitHub repository for known published vulnerabilities and saves each scan locally. Its shield-and-check logo represents the repository security scan.

## Explain the stack

- Tkinter is the desktop interface.
- Python downloads the repository archive, reads exact Python and npm dependency pins, coordinates the scan, calls the vulnerability lookup service, and reads/writes SQLite.
- Java reads direct, fixed-version Maven dependencies from pom.xml. It prints each dependency as a tab-separated line; Python reads those lines.
- SQLite stores repositories, scans, dependencies, and findings.

## Explain the scan

1. Paste a public GitHub repository URL.
2. Python gets a snapshot pinned to the default branch's commit.
3. RepoSentry reads requirements.txt, package.json, and pom.xml files as data.
4. Java extracts Maven package names and versions; Python parses pinned Python requirements and exact package.json dependencies.
5. Python asks OSV whether each package version has a known advisory.
6. Findings and scan history are saved to SQLite and displayed in Tkinter.

## Explain the UI

The app has Findings and Scan History tabs. It opens the latest saved scan automatically. Findings can be searched or filtered by severity, double-clicking opens the advisory, and Export CSV saves a report.

## Important scope

This is a class-project dependency checker, not a full security audit. It supports exact Python requirements such as package==1.2.3, exact direct package.json versions, and direct Maven dependencies with literal versions. It does not resolve transitive npm packages or run repository code, install packages, or detect every flaw in source code.

## Database tables

- repositories: canonical GitHub URL, owner, repository name
- scans: repository, commit ID, time, status, dependency and finding counts
- dependencies: package, version, ecosystem, and manifest path
- findings: advisory ID, summary, severity, and reference link

SQLite is enough because this is a local desktop app and does not need a separate database server.

## Team split suggestion

- Teammate 1: Tkinter screens and results/history display
- Teammate 2: Python GitHub/OSV workflow and SQLite
- Teammate 3: Java Maven parser and integration

Agree on the Java tab-separated output format before splitting implementation work.

## Demo

On macOS, double-click RepoSentry.app. Run RepoSentry.command is available as a terminal-friendly fallback. For a fresh demo, scan https://github.com/pralav-25/reposentry-demo. To show the npm scanner, scan https://github.com/pralav-25/interleave. Advisory counts can change as OSV data changes. The demo fixture's old dependency versions are only for scanner demonstrations.

The app requires internet access for GitHub and OSV lookups, and a Java JDK for Maven scans. Use Python with Tk 8.6 or newer.

