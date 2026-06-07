"""Windows artifact parsers: prefetch, registry (regripper), shimcache, amcache."""
from __future__ import annotations
import subprocess
import re
import struct
from pathlib import Path

from mcp_server.models import (
    PrefetchEntry, RegistryFinding,
    Finding, Confidence, Severity, IOC, MITRE_MAP,
)

TIMEOUT = 60

REGRIPPER_PATH = Path(__file__).parent.parent.parent / "regripper_src" / "rip.pl"
REGRIPPER_PLUGINS_PATH = Path(__file__).parent.parent.parent / "regripper_src" / "plugins"


def _run(cmd: list[str]) -> tuple[str, str | None]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return r.stdout, None if r.returncode == 0 else r.stderr.strip() or None
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return "", f"timed out: {' '.join(cmd[:3])}"


KNOWN_MALICIOUS_PREFETCH = {
    # Credential theft
    "MIMIKATZ.EXE", "WCE.EXE", "FGDUMP.EXE", "PWDUMP.EXE",
    "DUMPERT.EXE", "NANODUMP.EXE", "SAFETYKATZ.EXE",
    # Remote access / C2
    "METERPRETER.EXE", "NC.EXE", "NETCAT.EXE", "NCAT.EXE",
    "PSEXEC.EXE", "PSEXESVC.EXE",
    # Memory / process tools
    "PROCDUMP.EXE", "PROCDUMP64.EXE",
    # Forensic imaging tools (on a victim machine = attacker collecting evidence)
    "FTKIMAGER.EXE", "FTK IMAGER.EXE", "ACCESSDATA.EXE",
    "WINPMEM.EXE", "WINPMEM_MINI.EXE", "DUMPIT.EXE",
    "RAMMAP.EXE", "WINHEX.EXE", "X-WAYS.EXE",
    # Anti-forensic / wiping tools
    "SDELETE.EXE", "SDELETE64.EXE", "ERASER.EXE",
    "CIPHER.EXE",  # only suspicious if run with /W flag but flag anyway
    "MSHTA.EXE",   # often used for dropper execution
    # Recon
    "NMAP.EXE", "NMAP",
    "SHARPHOUND.EXE", "BLOODHOUND.EXE",
    "ADFIND.EXE", "ADRECON.EXE",
}

SUSPICIOUS_PREFETCH_PATHS = [
    re.compile(r"\\TEMP\\", re.I),
    re.compile(r"\\TMP\\", re.I),
    re.compile(r"\\USERS\\PUBLIC\\", re.I),
    re.compile(r"\\APPDATA\\LOCAL\\TEMP\\", re.I),
]


def parse_prefetch_directory(prefetch_dir: str) -> tuple[list[PrefetchEntry], list[Finding]]:
    """Parse .pf files in a prefetch directory using pecmd or direct parsing."""
    findings: list[Finding] = []
    entries: list[PrefetchEntry] = []

    pf_dir = Path(prefetch_dir)
    if not pf_dir.exists():
        findings.append(Finding(
            category="tool_error",
            description=f"Prefetch directory not found: {prefetch_dir}",
            confidence=Confidence.HIGH,
            severity=Severity.INFORMATIONAL,
        ))
        return entries, findings

    pf_files = list(pf_dir.glob("*.pf")) + list(pf_dir.glob("*.PF"))
    if not pf_files:
        return entries, findings

    # Try pecmd first, fall back to basic parsing
    stdout, err = _run(["pecmd", "lep", prefetch_dir])
    if not err and stdout:
        entries, findings = _parse_pecmd_output(stdout)
    else:
        entries, findings = _parse_pf_files_basic(pf_files)

    return entries, findings


def _parse_pecmd_output(output: str) -> tuple[list[PrefetchEntry], list[Finding]]:
    findings: list[Finding] = []
    entries: list[PrefetchEntry] = []

    for line in output.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        # pecmd format: Executable | RunCount | LastRun | Path
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2:
            continue
        try:
            entry = PrefetchEntry(
                executable=parts[0] if parts else "",
                run_count=int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                last_run=parts[2] if len(parts) > 2 else None,
                path=parts[3] if len(parts) > 3 else "",
            )
        except Exception:
            continue

        _check_prefetch_suspicious(entry, findings)
        entries.append(entry)

    return entries, findings


def _parse_pf_files_basic(pf_files: list[Path]) -> tuple[list[PrefetchEntry], list[Finding]]:
    """
    Parse .pf filenames for executable name and attempt run-count extraction.

    Windows 10 prefetch files are MAM/Xpress-compressed — binary parsing of
    run counts is unreliable without decompression. Derive the executable name
    from the filename (format: EXECNAME.EXT-HASH.pf) which is always accurate,
    and mark run_count=0 for compressed files to avoid billion-value artifacts.
    """
    findings: list[Finding] = []
    entries: list[PrefetchEntry] = []

    for pf_path in pf_files:
        try:
            # Filename format: EXECUTABLE.EXT-HASH8CHARS.pf
            # stem = "EXECUTABLE.EXT-HASH8CHARS"
            stem = pf_path.stem  # e.g. "FTKIMAGER.EXE-913F398E"
            name_part = stem.rsplit("-", 1)[0]  # e.g. "FTKIMAGER.EXE"

            data = pf_path.read_bytes()
            if len(data) < 8:
                continue

            # Detect compression: Win10 MAM files start with 0x4D 0x41 0x4D 0x4A ("MAMJ")
            # or have a signature at offset 0 that differs from "SCCA" (0x53434341)
            sig = data[4:8]
            is_compressed = sig != b'SCCA'

            run_count = 0
            if not is_compressed and len(data) > 0x14:
                # Uncompressed (XP/Vista/7/8): run count at offset 0x10 (v17) or 0xD0 (v23/26)
                version = struct.unpack_from("<I", data, 0)[0]
                if version == 17:
                    run_count = struct.unpack_from("<I", data, 0x10)[0]
                elif version in (23, 26):
                    run_count = struct.unpack_from("<I", data, 0x98)[0]
                # Sanity check — values over 100k are parser artifacts
                if run_count > 100_000:
                    run_count = 0

            entry = PrefetchEntry(
                executable=name_part,
                run_count=run_count,
                last_run=None,
                path=str(pf_path),
            )
            _check_prefetch_suspicious(entry, findings)
            entries.append(entry)
        except Exception:
            continue

    return entries, findings


def _check_prefetch_suspicious(entry: PrefetchEntry, findings: list[Finding]) -> None:
    name_upper = entry.executable.upper()
    reason: str | None = None

    if name_upper in KNOWN_MALICIOUS_PREFETCH:
        reason = f"known malicious tool: {entry.executable}"
    elif any(p.search(entry.path) for p in SUSPICIOUS_PREFETCH_PATHS):
        reason = f"executed from suspicious path: {entry.path}"
    elif entry.run_count > 50:
        reason = f"unusually high run count: {entry.run_count}"

    if reason:
        entry.suspicious = True
        entry.suspicious_reason = reason
        findings.append(Finding(
            category="suspicious_execution",
            description=f"Suspicious prefetch entry: {entry.executable} — {reason}",
            confidence=Confidence.HIGH if "known malicious" in reason else Confidence.MEDIUM,
            severity=Severity.HIGH,
            mitre=MITRE_MAP.get("suspicious_prefetch"),
            iocs=[IOC(type="file_path", value=entry.path, context=f"run count: {entry.run_count}, last run: {entry.last_run}")],
            source_tools=["prefetch_parser"],
            raw_evidence=f"{entry.executable} | runs={entry.run_count} | last={entry.last_run}",
        ))


REGRIPPER_PERSISTENCE_PLUGINS = [
    "run",       # HKCU/HKLM Run keys
    "runonce",
    "services",
    "userassist",
    "shellbags",
    "appcompat",
    "shimcache",
]

REGRIPPER_SYSTEM_PLUGINS = [
    "services",
    "timezone",
    "compname",
    "nic2",
]


def run_regripper(hive_path: str, plugins: list[str]) -> tuple[list[RegistryFinding], list[Finding]]:
    findings: list[Finding] = []
    reg_findings: list[RegistryFinding] = []

    hive = Path(hive_path)
    if not hive.exists():
        findings.append(Finding(
            category="tool_error",
            description=f"Registry hive not found: {hive_path}",
            confidence=Confidence.HIGH,
            severity=Severity.INFORMATIONAL,
        ))
        return reg_findings, findings

    for plugin in plugins:
        stdout, err = _run(["perl", str(REGRIPPER_PATH), "-r", hive_path, "-p", plugin, "-d", str(REGRIPPER_PLUGINS_PATH)])
        if err or not stdout:
            continue
        parsed = _parse_regripper_output(stdout, plugin)
        for rf in parsed:
            reg_findings.append(rf)
            if rf.suspicious:
                findings.append(Finding(
                    category="registry_persistence",
                    description=f"Registry persistence: [{plugin}] {rf.key} = {rf.data}",
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    mitre=MITRE_MAP.get("persistence_run_key"),
                    iocs=[IOC(type="registry_key", value=rf.key, context=rf.data or "")],
                    source_tools=[f"regripper:{plugin}"],
                    raw_evidence=f"{rf.key} | {rf.value} | {rf.data}",
                ))

    return reg_findings, findings


def _parse_regripper_output(output: str, plugin: str) -> list[RegistryFinding]:
    results: list[RegistryFinding] = []
    current_key: str = ""

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("Software\\") or line.startswith("SYSTEM\\") or "\\" in line and "=" not in line:
            current_key = line
            continue

        if "=" in line:
            parts = line.split("=", 1)
            value_name = parts[0].strip()
            value_data = parts[1].strip() if len(parts) > 1 else ""

            KNOWN_GOOD_RUN_PATHS = (
                "program files", "windows\\system32", "windows\\syswow64",
                "onedrive", "microsoft\\teams", "google\\chrome", "mozilla",
            )
            data_lower = value_data.lower()
            is_suspicious = any(
                p in data_lower
                for p in ["temp\\", "tmp\\", "appdata\\local\\temp", "%temp%",
                          "users\\public", "powershell -enc", "cmd /c", "wscript", "cscript"]
            ) and not any(good in data_lower for good in KNOWN_GOOD_RUN_PATHS)

            results.append(RegistryFinding(
                key=current_key,
                value=value_name,
                data=value_data,
                type=plugin,
                suspicious=is_suspicious,
                suspicious_reason="suspicious autorun entry" if is_suspicious else None,
            ))

    return results


def extract_shimcache(system_hive: str) -> tuple[list[dict], list[Finding]]:
    """Extract shimcache entries to find evidence of execution."""
    findings: list[Finding] = []
    entries: list[dict] = []

    stdout, err = _run(["perl", str(REGRIPPER_PATH), "-r", system_hive, "-p", "shimcache", "-d", str(REGRIPPER_PLUGINS_PATH)])
    if err or not stdout:
        return entries, findings

    for line in stdout.splitlines():
        if ".exe" in line.lower() or ".dll" in line.lower():
            path = line.strip()
            entry = {"path": path}
            entries.append(entry)
            if any(p.search(path) for p in SUSPICIOUS_PREFETCH_PATHS):
                findings.append(Finding(
                    category="shimcache_suspicious",
                    description=f"Shimcache entry from suspicious path: {path}",
                    confidence=Confidence.MEDIUM,
                    severity=Severity.HIGH,
                    mitre=MITRE_MAP.get("suspicious_prefetch"),
                    iocs=[IOC(type="file_path", value=path, context="shimcache evidence of execution")],
                    source_tools=["regripper:shimcache"],
                    raw_evidence=line,
                ))

    return entries, findings
