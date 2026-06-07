from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
import uuid
from datetime import datetime, timezone


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class MitreAttack(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str


MITRE_MAP: dict[str, MitreAttack] = {
    "process_injection": MitreAttack(
        technique_id="T1055",
        technique_name="Process Injection",
        tactic="Defense Evasion / Privilege Escalation",
    ),
    "persistence_run_key": MitreAttack(
        technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
        tactic="Persistence",
    ),
    "persistence_service": MitreAttack(
        technique_id="T1543.003",
        technique_name="Create or Modify System Process: Windows Service",
        tactic="Persistence",
    ),
    "suspicious_network": MitreAttack(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        tactic="Command and Control",
    ),
    "lateral_movement_smb": MitreAttack(
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        tactic="Lateral Movement",
    ),
    "credential_dumping": MitreAttack(
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        tactic="Credential Access",
    ),
    "suspicious_prefetch": MitreAttack(
        technique_id="T1204",
        technique_name="User Execution",
        tactic="Execution",
    ),
    "scheduled_task": MitreAttack(
        technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        tactic="Persistence / Execution",
    ),
}


class IOC(BaseModel):
    type: str  # ip, domain, hash, process, registry_key, file_path
    value: str
    context: str


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: str
    description: str
    confidence: Confidence
    severity: Severity
    mitre: Optional[MitreAttack] = None
    iocs: list[IOC] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    corroborated: bool = False
    corroboration_detail: Optional[str] = None
    raw_evidence: str = ""
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ProcessEntry(BaseModel):
    pid: int
    ppid: int
    name: str
    path: Optional[str] = None
    cmdline: Optional[str] = None
    create_time: Optional[str] = None
    suspicious: bool = False
    suspicious_reasons: list[str] = Field(default_factory=list)


class NetworkConnection(BaseModel):
    proto: str
    local_addr: str
    local_port: int
    foreign_addr: str
    foreign_port: int
    state: str
    pid: int
    owner: str
    suspicious: bool = False
    suspicious_reason: Optional[str] = None


class InjectedRegion(BaseModel):
    pid: int
    process: str
    start_vpn: str
    end_vpn: str
    protection: str
    suspicious: bool = True
    hexdump_snippet: str = ""


class TimelineEvent(BaseModel):
    timestamp: str
    macb: str
    source: str
    source_type: str
    type: str
    user: str
    filename: str
    description: str


class PrefetchEntry(BaseModel):
    executable: str
    run_count: int
    last_run: Optional[str]
    path: str
    suspicious: bool = False
    suspicious_reason: Optional[str] = None


class RegistryFinding(BaseModel):
    key: str
    value: Optional[str]
    data: Optional[str]
    type: str
    suspicious: bool = False
    suspicious_reason: Optional[str] = None


class ToolCallRecord(BaseModel):
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    tool: str
    params: dict
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_ms: int = 0
    findings_produced: list[str] = Field(default_factory=list)
    error: Optional[str] = None


class MemoryAnalysisResult(BaseModel):
    call_id: str
    processes: list[ProcessEntry] = Field(default_factory=list)
    network_connections: list[NetworkConnection] = Field(default_factory=list)
    injected_regions: list[InjectedRegion] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)


class DiskTimelineResult(BaseModel):
    call_id: str
    events: list[TimelineEvent] = Field(default_factory=list)
    suspicious_events: list[TimelineEvent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)


class ArtifactResult(BaseModel):
    call_id: str
    prefetch_entries: list[PrefetchEntry] = Field(default_factory=list)
    registry_findings: list[RegistryFinding] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)


class CorroborationResult(BaseModel):
    finding_id: str
    corroborated: bool
    method: str
    detail: str
    updated_confidence: Confidence
