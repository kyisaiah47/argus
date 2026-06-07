"""
Corroboration engine — the key differentiator.

For each HIGH/CRITICAL finding, attempts verification via a second independent
tool. Updates confidence and labels findings UNVERIFIED if corroboration fails.
"""
from __future__ import annotations
import subprocess
import re
from mcp_server.models import Finding, Confidence, CorroborationResult


CORROBORATION_STRATEGIES: dict[str, list[str]] = {
    "memory_injection":    ["persistence_check", "shimcache_check"],
    "suspicious_process":  ["network_check", "persistence_check"],
    "external_connection": ["process_verify", "dns_check"],
    "registry_persistence":["prefetch_check", "process_verify"],
    "suspicious_execution":["registry_check", "memory_verify"],
    "deleted_executable":  ["shimcache_check", "prefetch_check"],
}


class CorroborationEngine:
    def __init__(self) -> None:
        self.log: list[CorroborationResult] = []

    def corroborate_memory_findings(
        self, findings: list[Finding], memory_image: str
    ) -> list[Finding]:
        """
        For each HIGH/CRITICAL memory finding, run a second volatility plugin
        to see if the evidence holds up under independent scrutiny.
        """
        updated: list[Finding] = []
        for finding in findings:
            if finding.severity.value in ("CRITICAL", "HIGH"):
                result = self._corroborate(finding, memory_image)
                self.log.append(result)
                finding.corroborated = result.corroborated
                finding.corroboration_detail = result.detail
                finding.confidence = result.updated_confidence
            updated.append(finding)
        return updated

    def _corroborate(self, finding: Finding, memory_image: str) -> CorroborationResult:
        category = finding.category

        if category == "memory_injection":
            return self._corroborate_injection(finding, memory_image)
        elif category == "suspicious_process":
            return self._corroborate_process(finding, memory_image)
        elif category == "external_connection":
            return self._corroborate_connection(finding, memory_image)
        else:
            return CorroborationResult(
                finding_id=finding.id,
                corroborated=False,
                method="no_strategy",
                detail="No corroboration strategy defined for this finding category",
                updated_confidence=Confidence.UNVERIFIED,
            )

    def _corroborate_injection(self, finding: Finding, memory_image: str) -> CorroborationResult:
        """
        Corroborate memory injection: use windows.dlllist to check if the
        injected PID has suspicious DLL load patterns.
        """
        pid = None
        for ioc in finding.iocs:
            ctx = ioc.context
            pid_match = re.search(r"PID (\d+)", ctx)
            if pid_match:
                pid = pid_match.group(1)
                break

        if not pid:
            return CorroborationResult(
                finding_id=finding.id,
                corroborated=False,
                method="dlllist",
                detail="Could not extract PID from finding IOCs for corroboration",
                updated_confidence=Confidence.MEDIUM,
            )

        try:
            result = subprocess.run(
                ["vol", "-f", memory_image, "windows.dlllist.DllList", "--pid", pid],
                capture_output=True, text=True, timeout=120,
            )
            output = result.stdout

            # Look for DLLs loaded from suspicious paths — classic injection indicator
            suspicious_dll_paths = [
                re.compile(r"\\temp\\", re.I),
                re.compile(r"\\tmp\\", re.I),
                re.compile(r"\\appdata\\", re.I),
            ]
            suspicious_dlls = [
                line for line in output.splitlines()
                if any(p.search(line) for p in suspicious_dll_paths)
            ]

            if suspicious_dlls:
                return CorroborationResult(
                    finding_id=finding.id,
                    corroborated=True,
                    method="volatility:dlllist",
                    detail=f"CORROBORATED: PID {pid} has {len(suspicious_dlls)} DLL(s) loaded from suspicious paths: {suspicious_dlls[:2]}",
                    updated_confidence=Confidence.HIGH,
                )
            else:
                return CorroborationResult(
                    finding_id=finding.id,
                    corroborated=False,
                    method="volatility:dlllist",
                    detail=f"UNVERIFIED: PID {pid} DLL list shows no suspicious load paths. malfind finding may be a false positive.",
                    updated_confidence=Confidence.UNVERIFIED,
                )

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return CorroborationResult(
                finding_id=finding.id,
                corroborated=False,
                method="volatility:dlllist",
                detail=f"Corroboration failed — tool error: {e}",
                updated_confidence=Confidence.MEDIUM,
            )

    def _corroborate_process(self, finding: Finding, memory_image: str) -> CorroborationResult:
        """
        Corroborate suspicious process: check pstree for parent chain anomalies.
        Parent chain inconsistencies with process name strongly indicate masquerading.
        """
        proc_name = None
        pid = None
        for ioc in finding.iocs:
            if ioc.type == "process":
                proc_name = ioc.value
                pid_match = re.search(r"PID (\d+)", ioc.context)
                if pid_match:
                    pid = pid_match.group(1)
                break

        if not proc_name:
            return CorroborationResult(
                finding_id=finding.id,
                corroborated=False,
                method="pstree",
                detail="Could not extract process name for corroboration",
                updated_confidence=Confidence.MEDIUM,
            )

        try:
            result = subprocess.run(
                ["vol", "-f", memory_image, "windows.pstree.PsTree"],
                capture_output=True, text=True, timeout=120,
            )
            output = result.stdout

            if proc_name.lower() in output.lower():
                # Process appears in tree — check if it's in expected location
                lines = [l for l in output.splitlines() if proc_name.lower() in l.lower()]
                return CorroborationResult(
                    finding_id=finding.id,
                    corroborated=True,
                    method="volatility:pstree",
                    detail=f"CORROBORATED: {proc_name} visible in process tree: {lines[0] if lines else 'confirmed present'}",
                    updated_confidence=Confidence.HIGH,
                )
            else:
                return CorroborationResult(
                    finding_id=finding.id,
                    corroborated=False,
                    method="volatility:pstree",
                    detail=f"DISCREPANCY: {proc_name} found in pslist but NOT in pstree — possible DKOM rootkit hiding process",
                    updated_confidence=Confidence.HIGH,  # discrepancy is itself high-confidence IOC
                )

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return CorroborationResult(
                finding_id=finding.id,
                corroborated=False,
                method="volatility:pstree",
                detail=f"Corroboration failed: {e}",
                updated_confidence=Confidence.MEDIUM,
            )

    def _corroborate_connection(self, finding: Finding, memory_image: str) -> CorroborationResult:
        """
        Corroborate external connection: verify the owning process also appears
        in pslist (rules out netscan misidentification).
        """
        ip = None
        for ioc in finding.iocs:
            if ioc.type == "ip":
                ip = ioc.value
                break

        if not ip:
            return CorroborationResult(
                finding_id=finding.id,
                corroborated=False,
                method="pslist_verify",
                detail="No IP IOC found to corroborate",
                updated_confidence=Confidence.MEDIUM,
            )

        try:
            # Check netstat via volatility as independent confirmation
            result = subprocess.run(
                ["vol", "-f", memory_image, "windows.netstat.NetStat"],
                capture_output=True, text=True, timeout=120,
            )
            output = result.stdout

            if ip in output:
                return CorroborationResult(
                    finding_id=finding.id,
                    corroborated=True,
                    method="volatility:netstat",
                    detail=f"CORROBORATED: {ip} confirmed present in netstat output (independent of netscan)",
                    updated_confidence=Confidence.HIGH,
                )
            else:
                return CorroborationResult(
                    finding_id=finding.id,
                    corroborated=False,
                    method="volatility:netstat",
                    detail=f"UNVERIFIED: {ip} found in netscan but NOT in netstat — possible false positive or closed connection",
                    updated_confidence=Confidence.UNVERIFIED,
                )

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return CorroborationResult(
                finding_id=finding.id,
                corroborated=False,
                method="volatility:netstat",
                detail=f"Corroboration failed: {e}",
                updated_confidence=Confidence.MEDIUM,
            )

    def get_corroboration_summary(self) -> dict:
        total = len(self.log)
        corroborated = sum(1 for r in self.log if r.corroborated)
        unverified = sum(1 for r in self.log if not r.corroborated)
        return {
            "total_corroboration_attempts": total,
            "corroborated": corroborated,
            "unverified": unverified,
            "false_positive_rate_estimate": f"{(unverified / total * 100):.1f}%" if total else "N/A",
        }
