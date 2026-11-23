# PROCESS WATCHTOWER — Linux Process Inventory Auditor

A read-only Python utility that inventories processes from Linux procfs and optionally compares process names with an administrator-maintained allowlist.

## What it reports

- PID, parent PID, process name, state, and UID.
- Processes whose names are absent from a supplied allowlist.
- Optional truncated command lines, with common `key=value` secret assignments redacted.
- Entries skipped because a process exited or became inaccessible during collection.

## Requirements

- Python 3.10+
- Linux with `/proc` mounted for live collection.
- Python standard library only.

## Run

```bash
python main.py
python main.py --allowlist sample/approved-processes.txt
python main.py --include-cmdline --output process-report.json
```

The allowlist file contains one approved process name per line. Lines beginning with `#` are ignored. Use `--include-cmdline` only when needed: process arguments can contain sensitive information, and redaction is best-effort rather than a guarantee.

## Tests

```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Safe interpretation

This is a local inventory, not an EDR product. An unknown process name is a triage lead, not proof of compromise. Validate binary path, package ownership, parent process, UID, command arguments, service configuration, and approved change records. The tool does not kill processes, change system settings, or send data to a remote service.

## Portfolio context

Built for Anike-Moses Melie Jesse's defensive cybersecurity portfolio to demonstrate Linux process inspection, procfs parsing, allowlist-based triage, safe data handling, and Python automation.
