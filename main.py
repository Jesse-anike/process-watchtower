from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


SECRET_ASSIGNMENT = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|access[_-]?key)=([^\s]+)"
)


def redact_command_line(raw: bytes, limit: int = 300) -> str:
    """Render a process cmdline with obvious key=value secrets redacted."""
    text = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    text = SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    return text[:limit]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").strip()


def _uid_from_status(status_text: str) -> int | None:
    for line in status_text.splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) >= 2:
                try:
                    return int(fields[1])
                except ValueError:
                    return None
    return None


def inventory_processes(
    proc_root: Path = Path("/proc"),
    allowlist: set[str] | None = None,
    include_cmdline: bool = False,
) -> dict:
    """Create a read-only process inventory from a Linux procfs tree."""
    if not proc_root.exists() or not proc_root.is_dir():
        raise FileNotFoundError(f"procfs directory not found: {proc_root}")

    allowed = {name.strip() for name in (allowlist or set()) if name.strip()}
    processes: list[dict] = []
    skipped = 0

    for entry in proc_root.iterdir():
        if not entry.name.isdigit() or not entry.is_dir():
            continue
        try:
            pid = int(entry.name)
            name = _read_text(entry / "comm")
            stat_text = _read_text(entry / "stat")
            # /proc/PID/stat: pid (comm) state ppid ...; comm can include spaces.
            match = re.match(r"^\d+ \((.*)\) (\S) (\d+)", stat_text)
            state = match.group(2) if match else None
            parent_pid = int(match.group(3)) if match else None
            uid = _uid_from_status(_read_text(entry / "status"))
            item = {
                "pid": pid,
                "parent_pid": parent_pid,
                "name": name,
                "state": state,
                "uid": uid,
            }
            if allowed:
                item["not_in_allowlist"] = name not in allowed
            if include_cmdline:
                item["command_line"] = redact_command_line((entry / "cmdline").read_bytes())
            processes.append(item)
        except (OSError, PermissionError, ValueError):
            # Processes can exit while procfs is being read. Skip transient entries.
            skipped += 1

    processes.sort(key=lambda item: item["pid"])
    flagged = [item for item in processes if item.get("not_in_allowlist") is True]
    return {
        "process_count": len(processes),
        "allowlist_loaded": bool(allowed),
        "not_in_allowlist_count": len(flagged),
        "processes": processes,
        "skipped_or_raced_entries": skipped,
        "note": (
            "Read-only inventory. An unlisted process is not automatically malicious; "
            "verify host role, package ownership, command path, parent process, and change history."
        ),
    }


def load_allowlist(path: str | None) -> set[str]:
    if not path:
        return set()
    values = set()
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        cleaned = line.strip()
        if cleaned and not cleaned.startswith("#"):
            values.add(cleaned)
    return values


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a read-only Linux process inventory from /proc and optionally compare names with an allowlist."
    )
    parser.add_argument("--proc-root", default="/proc", help="procfs root (default: /proc; mainly useful for controlled tests)")
    parser.add_argument("--allowlist", help="Text file containing approved process names, one per line")
    parser.add_argument("--include-cmdline", action="store_true", help="Include a truncated command line with common key=value secrets redacted")
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args()

    try:
        report = inventory_processes(Path(args.proc_root), load_allowlist(args.allowlist), args.include_cmdline)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
