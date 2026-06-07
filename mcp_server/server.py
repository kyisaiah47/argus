"""
Find Evil MCP Server — typed, read-only forensics tools for autonomous IR.

The agent physically cannot run destructive commands because this server
does not expose them. All tool outputs are structured JSON — no raw text dumps.
"""
from __future__ import annotations
import json
import time
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from mcp_server.models import (
    MemoryAnalysisResult, DiskTimelineResult, ArtifactResult,
    ToolCallRecord, CorroborationResult, Confidence,
)
from mcp_server.tools import memory as mem_tools
from mcp_server.tools import disk as disk_tools
from mcp_server.tools import artifacts as art_tools

AUDIT_DIR = Path(__file__).parent.parent / "audit"
AUDIT_DIR.mkdir(exist_ok=True)
AUDIT_LOG = AUDIT_DIR / f"session_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"

mcp = FastMCP(
    "find-evil",
    instructions=(
        "You are a senior DFIR analyst. Use these tools to investigate case data. "
        "All tools are READ-ONLY. Original evidence is never modified. "
        "After producing findings, attempt corroboration via a second tool before "
        "assigning HIGH confidence. Flag discrepancies explicitly."
    ),
)


def _log(record: ToolCallRecord) -> None:
    with open(AUDIT_LOG, "a") as f:
        f.write(record.model_dump_json() + "\n")


def _result_hash(data: str) -> str:
    return "sha256:" + hashlib.sha256(data.encode()).hexdigest()[:16]


@mcp.tool()
def analyze_memory(memory_image: str) -> dict:
    """
    Full memory triage: process list, network connections, and memory injection scan.
    Returns structured findings — no raw volatility output in the response.

    Args:
        memory_image: Absolute path to raw memory image (.raw, .mem, .dmp)
    """
    call_id = str(uuid.uuid4())[:12]
    t0 = time.time()

    processes, proc_findings = mem_tools.analyze_processes(memory_image)
    connections, net_findings = mem_tools.analyze_network(memory_image)
    injections, inj_findings = mem_tools.analyze_injections(memory_image)

    all_findings = proc_findings + net_findings + inj_findings
    result = MemoryAnalysisResult(
        call_id=call_id,
        processes=processes,
        network_connections=connections,
        injected_regions=injections,
        findings=all_findings,
    )

    serialized = result.model_dump_json()
    record = ToolCallRecord(
        call_id=call_id,
        tool="analyze_memory",
        params={"memory_image": memory_image},
        duration_ms=int((time.time() - t0) * 1000),
        findings_produced=[f.id for f in all_findings],
    )
    _log(record)

    return result.model_dump()


@mcp.tool()
def analyze_disk_timeline(
    disk_image: str,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict:
    """
    Build a timeline from a disk image and return suspicious events.
    Uses log2timeline + psort. Read-only mount — original image never written to.

    Args:
        disk_image: Absolute path to disk image (.dd, .E01, .vmdk, etc.)
        start_time: Optional ISO timestamp to filter from (e.g. '2024-01-01T00:00:00')
        end_time: Optional ISO timestamp to filter to
    """
    call_id = str(uuid.uuid4())[:12]
    t0 = time.time()
    import tempfile

    findings = []
    events = []
    errors = []

    with tempfile.TemporaryDirectory() as tmp:
        plaso_file = f"{tmp}/timeline.plaso"
        build_err = disk_tools.build_timeline(disk_image, plaso_file)
        if build_err:
            errors.append(build_err)
        else:
            events, timeline_findings = disk_tools.extract_timeline_events(
                plaso_file, start_time, end_time
            )
            findings.extend(timeline_findings)

    result = DiskTimelineResult(
        call_id=call_id,
        events=events[:500],
        suspicious_events=[e for e in events if any(f.category == "suspicious_file_activity" for f in findings)],
        findings=findings,
        tool_errors=errors,
    )

    record = ToolCallRecord(
        call_id=call_id,
        tool="analyze_disk_timeline",
        params={"disk_image": disk_image, "start_time": start_time, "end_time": end_time},
        duration_ms=int((time.time() - t0) * 1000),
        findings_produced=[f.id for f in findings],
        error=errors[0] if errors else None,
    )
    _log(record)
    return result.model_dump()


@mcp.tool()
def analyze_persistence(
    prefetch_dir: str | None = None,
    ntuser_hive: str | None = None,
    software_hive: str | None = None,
    system_hive: str | None = None,
) -> dict:
    """
    Check persistence mechanisms: prefetch execution history, registry Run keys,
    shimcache. Provide any combination of paths available in the case.

    Args:
        prefetch_dir: Path to Windows\\Prefetch directory extracted from disk image
        ntuser_hive: Path to NTUSER.DAT hive file
        software_hive: Path to SOFTWARE hive file
        system_hive: Path to SYSTEM hive file
    """
    call_id = str(uuid.uuid4())[:12]
    t0 = time.time()

    all_prefetch = []
    all_reg_findings = []
    all_findings = []
    all_errors = []

    if prefetch_dir:
        pf_entries, pf_findings = art_tools.parse_prefetch_directory(prefetch_dir)
        all_prefetch.extend(pf_entries)
        all_findings.extend(pf_findings)

    for hive_path, plugins in [
        (ntuser_hive, ["run", "runonce", "userassist"]),
        (software_hive, ["run", "runonce", "appcompat"]),
        (system_hive, ["services", "shimcache"]),
    ]:
        if hive_path:
            rf, rf_findings = art_tools.run_regripper(hive_path, plugins)
            all_reg_findings.extend(rf)
            all_findings.extend(rf_findings)

    if system_hive:
        shim, shim_findings = art_tools.extract_shimcache(system_hive)
        all_findings.extend(shim_findings)

    result = ArtifactResult(
        call_id=call_id,
        prefetch_entries=all_prefetch,
        registry_findings=all_reg_findings,
        findings=all_findings,
        tool_errors=all_errors,
    )

    record = ToolCallRecord(
        call_id=call_id,
        tool="analyze_persistence",
        params={
            "prefetch_dir": prefetch_dir,
            "ntuser_hive": ntuser_hive,
            "software_hive": software_hive,
            "system_hive": system_hive,
        },
        duration_ms=int((time.time() - t0) * 1000),
        findings_produced=[f.id for f in all_findings],
    )
    _log(record)
    return result.model_dump()


@mcp.tool()
def correlate_findings(
    memory_findings: list[dict],
    disk_findings: list[dict],
) -> dict:
    """
    Cross-reference memory and disk findings. Flags discrepancies where
    sources disagree — these are either high-confidence IOCs or hallucinations
    to investigate further.

    Args:
        memory_findings: Finding dicts from analyze_memory
        disk_findings: Finding dicts from analyze_disk_timeline or analyze_persistence
    """
    call_id = str(uuid.uuid4())[:12]
    t0 = time.time()

    corroborations: list[dict] = []
    discrepancies: list[dict] = []

    mem_iocs: dict[str, list[dict]] = {}
    for f in memory_findings:
        for ioc in f.get("iocs", []):
            mem_iocs.setdefault(ioc["value"].lower(), []).append(f)

    for disk_f in disk_findings:
        for ioc in disk_f.get("iocs", []):
            key = ioc["value"].lower()
            if key in mem_iocs:
                corroborations.append({
                    "ioc": ioc["value"],
                    "memory_finding_ids": [f["id"] for f in mem_iocs[key]],
                    "disk_finding_id": disk_f["id"],
                    "verdict": "CORROBORATED",
                    "note": "Same IOC observed in both memory and disk artifacts",
                })
            else:
                discrepancies.append({
                    "ioc": ioc["value"],
                    "source": "disk_only",
                    "disk_finding_id": disk_f["id"],
                    "verdict": "DISK_ONLY",
                    "note": "Found on disk but not in memory — possible indicator of prior activity or cleaned traces",
                })

    for mem_f in memory_findings:
        for ioc in mem_f.get("iocs", []):
            key = ioc["value"].lower()
            disk_iocs = {
                i["value"].lower()
                for df in disk_findings
                for i in df.get("iocs", [])
            }
            if key not in disk_iocs:
                discrepancies.append({
                    "ioc": ioc["value"],
                    "source": "memory_only",
                    "memory_finding_id": mem_f["id"],
                    "verdict": "MEMORY_ONLY",
                    "note": "In memory but not on disk — possible fileless malware or live attack",
                })

    record = ToolCallRecord(
        call_id=call_id,
        tool="correlate_findings",
        params={"memory_finding_count": len(memory_findings), "disk_finding_count": len(disk_findings)},
        duration_ms=int((time.time() - t0) * 1000),
    )
    _log(record)

    return {
        "call_id": call_id,
        "corroborated_count": len(corroborations),
        "discrepancy_count": len(discrepancies),
        "corroborations": corroborations,
        "discrepancies": discrepancies,
        "summary": (
            f"{len(corroborations)} IOCs corroborated across memory+disk. "
            f"{len(discrepancies)} discrepancies require analyst review."
        ),
    }


@mcp.tool()
def score_severity(findings: list[dict]) -> dict:
    """
    Score overall incident severity based on findings. Returns risk level,
    top findings, and recommended next steps.

    Args:
        findings: List of Finding dicts from any analysis tool
    """
    call_id = str(uuid.uuid4())[:12]
    t0 = time.time()

    severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
    confidence_weights = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3, "UNVERIFIED": 0.1}

    score = 0.0
    critical_count = 0
    high_count = 0

    for f in findings:
        sev = f.get("severity", "LOW")
        conf = f.get("confidence", "LOW")
        w = severity_weights.get(sev, 1) * confidence_weights.get(conf, 0.3)
        score += w
        if sev == "CRITICAL":
            critical_count += 1
        elif sev == "HIGH":
            high_count += 1

    if critical_count > 0 or score > 30:
        risk = "CRITICAL"
        recommended = ["Isolate system immediately", "Preserve memory image", "Escalate to IR team", "Check for lateral movement"]
    elif high_count > 2 or score > 15:
        risk = "HIGH"
        recommended = ["Isolate from network", "Preserve artifacts", "Begin root cause analysis"]
    elif score > 5:
        risk = "MEDIUM"
        recommended = ["Monitor closely", "Collect additional artifacts", "Review user activity"]
    else:
        risk = "LOW"
        recommended = ["Continue monitoring", "Document baseline"]

    top_findings = sorted(
        findings,
        key=lambda f: severity_weights.get(f.get("severity", "LOW"), 0),
        reverse=True,
    )[:5]

    record = ToolCallRecord(
        call_id=call_id,
        tool="score_severity",
        params={"finding_count": len(findings)},
        duration_ms=int((time.time() - t0) * 1000),
    )
    _log(record)

    return {
        "call_id": call_id,
        "risk_level": risk,
        "score": round(score, 2),
        "critical_findings": critical_count,
        "high_findings": high_count,
        "top_findings": top_findings,
        "recommended_actions": recommended,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
