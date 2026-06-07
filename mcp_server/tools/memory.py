"""Volatility 3 wrappers for memory image analysis."""
from __future__ import annotations
import subprocess
import time
import re
from pathlib import Path

from mcp_server.models import (
    ProcessEntry, NetworkConnection, InjectedRegion,
    Finding, Confidence, Severity, IOC, MITRE_MAP,
)

VOLATILITY_CMD = "vol"
TIMEOUT = 300  # 5 minutes per volatility plugin


def _run_vol(memory_image: str, plugin: str, extra_args: list[str] | None = None) -> tuple[str, str | None]:
    """Run a Volatility 3 plugin. Returns (stdout, error_or_none)."""
    cmd = [VOLATILITY_CMD, "-f", memory_image, plugin]
    if extra_args:
        cmd.extend(extra_args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TIMEOUT
        )
        if result.returncode != 0 and not result.stdout:
            return "", f"volatility error: {result.stderr.strip()}"
        return result.stdout, None
    except FileNotFoundError:
        return "", f"{VOLATILITY_CMD} not found — ensure Volatility 3 is installed on SIFT"
    except subprocess.TimeoutExpired:
        return "", f"volatility timed out after {TIMEOUT}s on plugin {plugin}"


def _parse_vol_tsv(output: str, skip_rows: int = 2) -> list[dict[str, str]]:
    """Parse Volatility TSV output into list of dicts."""
    lines = [l for l in output.splitlines() if l.strip() and not l.startswith("Volatility") and not l.startswith("Progress")]
    if len(lines) <= skip_rows:
        return []
    headers = [h.strip() for h in lines[0].split("\t")]
    rows = []
    for line in lines[1:]:
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) >= len(headers):
            rows.append(dict(zip(headers, cols)))
    return rows


SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "meterpreter", "cobalt", "beacon",
    "psexec.exe", "wce.exe", "fgdump.exe", "pwdump",
}

# csrss.exe and wininit.exe are spawned by smss.exe instances which then exit,
# leaving orphan PPIDs — this is normal Windows behavior, not suspicious.
SYSTEM_PROC_PARENTS = {
    "smss.exe": [4],
    "services.exe": [752, 828, 0],  # wininit or its PID variants
    "lsass.exe": [752, 828, 0],
    "svchost.exe": [828, 664, 0],
    "explorer.exe": [0],
}


def analyze_processes(memory_image: str) -> tuple[list[ProcessEntry], list[Finding]]:
    stdout, err = _run_vol(memory_image, "windows.pslist.PsList")
    findings: list[Finding] = []
    processes: list[ProcessEntry] = []

    if err:
        findings.append(Finding(
            category="tool_error",
            description=f"pslist failed: {err}",
            confidence=Confidence.HIGH,
            severity=Severity.INFORMATIONAL,
        ))
        return processes, findings

    rows = _parse_vol_tsv(stdout)
    pid_map: dict[int, ProcessEntry] = {}

    for row in rows:
        try:
            entry = ProcessEntry(
                pid=int(row.get("PID", 0)),
                ppid=int(row.get("PPID", 0)),
                name=row.get("ImageFileName", "unknown"),
                create_time=row.get("CreateTime"),
            )
        except (ValueError, KeyError):
            continue

        reasons: list[str] = []
        name_lower = entry.name.lower()

        if name_lower in SUSPICIOUS_PROCESS_NAMES:
            reasons.append(f"known malicious tool name: {entry.name}")

        if name_lower in SYSTEM_PROC_PARENTS:
            expected_parents = SYSTEM_PROC_PARENTS[name_lower]
            if entry.ppid not in expected_parents and entry.ppid not in pid_map:
                reasons.append(f"unexpected parent PID {entry.ppid} for {entry.name}")

        if re.search(r'[^a-zA-Z0-9._\-\s]', entry.name):
            reasons.append(f"unusual characters in process name: {entry.name}")

        if reasons:
            entry.suspicious = True
            entry.suspicious_reasons = reasons
            findings.append(Finding(
                category="suspicious_process",
                description=f"Suspicious process: {entry.name} (PID {entry.pid}): {'; '.join(reasons)}",
                confidence=Confidence.MEDIUM,
                severity=Severity.HIGH,
                mitre=MITRE_MAP.get("process_injection"),
                iocs=[IOC(type="process", value=entry.name, context=f"PID {entry.pid}, PPID {entry.ppid}")],
                source_tools=["volatility:windows.pslist"],
                raw_evidence=str(row),
            ))

        pid_map[entry.pid] = entry
        processes.append(entry)

    return processes, findings


def analyze_network(memory_image: str) -> tuple[list[NetworkConnection], list[Finding]]:
    stdout, err = _run_vol(memory_image, "windows.netscan.NetScan")
    findings: list[Finding] = []
    connections: list[NetworkConnection] = []

    if err:
        findings.append(Finding(
            category="tool_error",
            description=f"netscan failed: {err}",
            confidence=Confidence.HIGH,
            severity=Severity.INFORMATIONAL,
        ))
        return connections, findings

    rows = _parse_vol_tsv(stdout)
    private_ranges = [
        re.compile(r"^10\."), re.compile(r"^192\.168\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
        re.compile(r"^127\."), re.compile(r"^0\.0\.0\.0"),
        re.compile(r"^\*"),
    ]

    for row in rows:
        try:
            local_parts = row.get("LocalAddr", ":0").rsplit(":", 1)
            foreign_parts = row.get("ForeignAddr", ":0").rsplit(":", 1)
            conn = NetworkConnection(
                proto=row.get("Proto", ""),
                local_addr=local_parts[0] if len(local_parts) > 1 else "",
                local_port=int(local_parts[-1]) if local_parts[-1].isdigit() else 0,
                foreign_addr=foreign_parts[0] if len(foreign_parts) > 1 else "",
                foreign_port=int(foreign_parts[-1]) if foreign_parts[-1].isdigit() else 0,
                state=row.get("State", ""),
                pid=int(row.get("PID", 0)),
                owner=row.get("Owner", ""),
            )
        except (ValueError, KeyError):
            continue

        foreign = conn.foreign_addr
        is_private = any(p.match(foreign) for p in private_ranges)
        is_established = conn.state == "ESTABLISHED"

        if is_established and not is_private and foreign not in ("", "*"):
            conn.suspicious = True
            conn.suspicious_reason = f"established external connection to {foreign}:{conn.foreign_port}"
            findings.append(Finding(
                category="external_connection",
                description=f"External ESTABLISHED connection from {conn.owner} (PID {conn.pid}) to {foreign}:{conn.foreign_port}",
                confidence=Confidence.MEDIUM,
                severity=Severity.HIGH,
                mitre=MITRE_MAP.get("suspicious_network"),
                iocs=[IOC(type="ip", value=foreign, context=f"port {conn.foreign_port}, owner {conn.owner}")],
                source_tools=["volatility:windows.netscan"],
                raw_evidence=str(row),
            ))

        connections.append(conn)

    return connections, findings


def analyze_injections(memory_image: str) -> tuple[list[InjectedRegion], list[Finding]]:
    stdout, err = _run_vol(memory_image, "windows.malfind.Malfind")
    findings: list[Finding] = []
    regions: list[InjectedRegion] = []

    if err:
        findings.append(Finding(
            category="tool_error",
            description=f"malfind failed: {err}",
            confidence=Confidence.HIGH,
            severity=Severity.INFORMATIONAL,
        ))
        return regions, findings

    rows = _parse_vol_tsv(stdout)

    for row in rows:
        try:
            region = InjectedRegion(
                pid=int(row.get("PID", 0)),
                process=row.get("Process", "unknown"),
                start_vpn=row.get("Start VPN", ""),
                end_vpn=row.get("End VPN", ""),
                protection=row.get("Protection", ""),
                hexdump_snippet=row.get("Hexdump", "")[:200],
            )
        except (ValueError, KeyError):
            continue

        # PAGE_EXECUTE_READWRITE is the classic injection signature
        rwx = "PAGE_EXECUTE_READWRITE" in region.protection or "0x40" in region.protection
        if rwx:
            findings.append(Finding(
                category="memory_injection",
                description=f"RWX memory region in {region.process} (PID {region.pid}) at {region.start_vpn} — likely code injection",
                confidence=Confidence.HIGH,
                severity=Severity.CRITICAL,
                mitre=MITRE_MAP.get("process_injection"),
                iocs=[IOC(type="process", value=region.process, context=f"PID {region.pid}, region {region.start_vpn}-{region.end_vpn}")],
                source_tools=["volatility:windows.malfind"],
                raw_evidence=str(row),
            ))

        regions.append(region)

    return regions, findings
