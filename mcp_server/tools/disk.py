"""Disk and timeline analysis wrappers using plaso/log2timeline and TSK tools."""
from __future__ import annotations
import subprocess
import tempfile
import os
import re
from pathlib import Path

from mcp_server.models import (
    TimelineEvent, Finding, Confidence, Severity, IOC, MITRE_MAP,
)

TIMEOUT_TIMELINE = 600  # timeline creation can take a while
TIMEOUT_SHORT = 60

# Use Python 3.12 venv for plaso if available (plaso doesn't build on 3.14)
import shutil as _shutil
_VENV312 = Path(__file__).parent.parent.parent / ".venv312" / "bin"
LOG2TIMELINE = str(_VENV312 / "log2timeline.py") if (_VENV312 / "log2timeline.py").exists() else "log2timeline.py"
PSORT = str(_VENV312 / "psort.py") if (_VENV312 / "psort.py").exists() else "psort.py"

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr"}
SUSPICIOUS_PATHS = [
    re.compile(r"\\temp\\", re.I),
    re.compile(r"\\tmp\\", re.I),
    re.compile(r"\\appdata\\local\\temp\\", re.I),
    re.compile(r"\\users\\public\\", re.I),
    re.compile(r"\\programdata\\", re.I),
    re.compile(r"\\windows\\temp\\", re.I),
]
KNOWN_GOOD_HASHES: set[str] = set()  # populated from NSRL in production


def _run(cmd: list[str], timeout: int = TIMEOUT_SHORT) -> tuple[str, str | None]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, None if r.returncode == 0 else r.stderr.strip() or None
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s: {' '.join(cmd[:3])}"


def build_timeline(disk_image: str, output_plaso: str) -> str | None:
    """Run log2timeline to build a plaso storage file. Returns error or None."""
    _, err = _run(
        [LOG2TIMELINE, "--quiet", output_plaso, disk_image],
        timeout=TIMEOUT_TIMELINE,
    )
    return err


def extract_timeline_events(
    plaso_file: str,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 2000,
) -> tuple[list[TimelineEvent], list[Finding]]:
    """Convert plaso storage to sorted timeline events."""
    findings: list[Finding] = []
    events: list[TimelineEvent] = []

    psort_cmd = [PSORT, "-o", "dynamic", plaso_file]
    if start_time:
        psort_cmd.extend(["--slice", start_time])

    stdout, err = _run(psort_cmd, timeout=TIMEOUT_SHORT)
    if err:
        findings.append(Finding(
            category="tool_error",
            description=f"psort failed: {err}",
            confidence=Confidence.HIGH,
            severity=Severity.INFORMATIONAL,
        ))
        return events, findings

    lines = stdout.splitlines()
    headers: list[str] = []
    for i, line in enumerate(lines):
        if line.startswith("datetime"):
            headers = [h.strip() for h in line.split(",")]
            data_lines = lines[i + 1: i + 1 + limit]
            break

    if not headers:
        return events, findings

    for line in data_lines:
        cols = line.split(",", len(headers) - 1)
        if len(cols) < len(headers):
            continue
        row = dict(zip(headers, cols))
        event = TimelineEvent(
            timestamp=row.get("datetime", ""),
            macb=row.get("MACB", ""),
            source=row.get("source", ""),
            source_type=row.get("source_long", ""),
            type=row.get("type", ""),
            user=row.get("user", ""),
            filename=row.get("filename", ""),
            description=row.get("message", ""),
        )
        events.append(event)
        _check_event_suspicious(event, findings)

    return events, findings


def _check_event_suspicious(event: TimelineEvent, findings: list[Finding]) -> None:
    filename = event.filename.lower()
    ext = Path(filename).suffix.lower()

    in_suspicious_path = any(p.search(event.filename) for p in SUSPICIOUS_PATHS)
    is_suspicious_ext = ext in SUSPICIOUS_EXTENSIONS

    if in_suspicious_path and is_suspicious_ext:
        findings.append(Finding(
            category="suspicious_file_activity",
            description=f"Executable activity in suspicious path: {event.filename} at {event.timestamp}",
            confidence=Confidence.MEDIUM,
            severity=Severity.HIGH,
            mitre=MITRE_MAP.get("suspicious_prefetch"),
            iocs=[IOC(type="file_path", value=event.filename, context=f"activity at {event.timestamp}")],
            source_tools=["log2timeline", "psort"],
            raw_evidence=f"{event.timestamp} | {event.macb} | {event.filename}",
        ))


def extract_deleted_files(disk_image: str, partition_offset: int = 0) -> tuple[list[str], list[Finding]]:
    """Use fls to find deleted files."""
    findings: list[Finding] = []
    deleted: list[str] = []

    cmd = ["fls", "-r", "-d"]
    if partition_offset:
        cmd.extend(["-o", str(partition_offset)])
    cmd.append(disk_image)

    stdout, err = _run(cmd, timeout=TIMEOUT_SHORT)
    if err:
        findings.append(Finding(
            category="tool_error",
            description=f"fls failed: {err}",
            confidence=Confidence.HIGH,
            severity=Severity.INFORMATIONAL,
        ))
        return deleted, findings

    for line in stdout.splitlines():
        # fls output: "r/r * <inode>:	<path>"
        if "* " in line:
            path = line.split(":\t")[-1].strip() if ":\t" in line else line
            deleted.append(path)
            ext = Path(path).suffix.lower()
            if ext in SUSPICIOUS_EXTENSIONS:
                findings.append(Finding(
                    category="deleted_executable",
                    description=f"Deleted executable found: {path}",
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    mitre=MITRE_MAP.get("suspicious_prefetch"),
                    iocs=[IOC(type="file_path", value=path, context="deleted file")],
                    source_tools=["fls"],
                    raw_evidence=line,
                ))

    return deleted, findings
