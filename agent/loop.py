"""
Find Evil autonomous agent loop.

Phases:
  1. Initial triage (memory + persistence)
  2. Corroboration (each HIGH/CRITICAL finding verified by a second tool)
  3. Deep analysis (disk timeline focused on suspicious timestamps)
  4. Cross-source correlation
  5. Severity scoring + report
"""
from __future__ import annotations
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

from agent.corroborate import CorroborationEngine
from agent.report import generate_report

MODEL = "claude-opus-4-7"
MAX_ITERATIONS = 12
AUDIT_DIR = Path(__file__).parent.parent / "audit"

SYSTEM_PROMPT = """You are an autonomous senior DFIR (Digital Forensics and Incident Response) analyst.
Your goal: investigate case data, produce a structured incident report, and catch your own mistakes.

## Methodology
1. Memory first — volatile artifacts disappear. Run analyze_memory first.
2. Persistence second — attackers establish footholds. Run analyze_persistence.
3. Corroborate every HIGH/CRITICAL finding with a second independent tool.
4. Timeline analysis — anchor suspicious artifacts to timestamps.
5. Cross-correlate — memory_only findings suggest fileless attacks. disk_only suggests cleaned traces.
6. Score severity — produce final risk assessment with recommended actions.

## Evidence integrity rules
- Never assume a finding is confirmed without corroboration.
- If two tools disagree, explicitly state the discrepancy. Do not choose one silently.
- Distinguish CONFIRMED from INFERRED from UNVERIFIED in your reasoning.
- All findings must cite the specific tool that produced them.

## Self-correction protocol
After initial triage, ask yourself:
- "Does this finding make sense given what else I've seen?"
- "Could this be a false positive? What would corroborate or refute it?"
- "Are there gaps in my analysis? What haven't I checked?"

When you identify a gap, fill it before writing the report.

## Termination
When you have:
  a) Analyzed all available case data
  b) Corroborated all HIGH/CRITICAL findings
  c) Produced a severity score
  d) Written the final report via generate_incident_report
...respond with ANALYSIS_COMPLETE and stop calling tools."""


TOOLS = [
    {
        "name": "analyze_memory",
        "description": "Full memory triage: process list, network connections, injection scan. Run this first.",
        "input_schema": {
            "type": "object",
            "properties": {
                "memory_image": {
                    "type": "string",
                    "description": "Absolute path to raw memory image (.raw, .mem, .dmp)",
                }
            },
            "required": ["memory_image"],
        },
    },
    {
        "name": "analyze_disk_timeline",
        "description": "Build timeline from disk image. Filter by time window if you have suspicious timestamps from memory analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "disk_image": {"type": "string"},
                "start_time": {"type": "string", "description": "ISO timestamp filter start"},
                "end_time": {"type": "string", "description": "ISO timestamp filter end"},
            },
            "required": ["disk_image"],
        },
    },
    {
        "name": "analyze_persistence",
        "description": "Check persistence: prefetch execution history, registry Run keys, shimcache.",
        "input_schema": {
            "type": "object",
            "properties": {
                "prefetch_dir": {"type": "string"},
                "ntuser_hive": {"type": "string"},
                "software_hive": {"type": "string"},
                "system_hive": {"type": "string"},
            },
        },
    },
    {
        "name": "correlate_findings",
        "description": "Cross-reference memory and disk findings. Call this after both memory and disk analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "memory_findings": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Findings list from analyze_memory",
                },
                "disk_findings": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Findings list from disk/persistence analysis",
                },
            },
            "required": ["memory_findings", "disk_findings"],
        },
    },
    {
        "name": "score_severity",
        "description": "Score overall incident severity. Call this after all analysis is complete.",
        "input_schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "All findings accumulated from all tools",
                }
            },
            "required": ["findings"],
        },
    },
    {
        "name": "generate_incident_report",
        "description": "Write the final structured incident report to disk. Call this last.",
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "all_findings": {"type": "array", "items": {"type": "object"}},
                "severity_score": {"type": "object"},
                "correlation_result": {"type": "object"},
                "analyst_summary": {"type": "string", "description": "2-3 sentence plain-English summary of what happened"},
                "timeline_of_attack": {"type": "string", "description": "Chronological narrative of attacker actions"},
                "recommended_actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["case_id", "all_findings", "analyst_summary"],
        },
    },
]


def _call_mcp_tool(tool_name: str, tool_input: dict, corroborate_engine: CorroborationEngine) -> Any:
    """Route tool call to the actual MCP server functions."""
    import importlib

    if tool_name == "generate_incident_report":
        return generate_report(tool_input, AUDIT_DIR)

    # Import server module and call the underlying tool functions
    from mcp_server.tools import memory as mem_tools
    from mcp_server.tools import disk as disk_tools
    from mcp_server.tools import artifacts as art_tools
    import uuid, time as _time

    call_id = str(uuid.uuid4())[:12]
    t0 = _time.time()

    if tool_name == "analyze_memory":
        memory_image = tool_input["memory_image"]
        processes, proc_findings = mem_tools.analyze_processes(memory_image)
        connections, net_findings = mem_tools.analyze_network(memory_image)
        injections, inj_findings = mem_tools.analyze_injections(memory_image)
        all_findings = proc_findings + net_findings + inj_findings

        # Run corroboration on HIGH/CRITICAL findings
        all_findings = corroborate_engine.corroborate_memory_findings(all_findings, memory_image)

        from mcp_server.models import MemoryAnalysisResult
        result = MemoryAnalysisResult(
            call_id=call_id,
            processes=processes,
            network_connections=connections,
            injected_regions=injections,
            findings=all_findings,
        )
        return result.model_dump()

    elif tool_name == "analyze_disk_timeline":
        import tempfile
        disk_image = tool_input["disk_image"]
        start_time = tool_input.get("start_time")
        end_time = tool_input.get("end_time")
        events = []
        findings = []
        errors = []
        with tempfile.TemporaryDirectory() as tmp:
            plaso_file = f"{tmp}/timeline.plaso"
            err = disk_tools.build_timeline(disk_image, plaso_file)
            if err:
                errors.append(err)
            else:
                events, findings = disk_tools.extract_timeline_events(plaso_file, start_time, end_time)
        from mcp_server.models import DiskTimelineResult
        return DiskTimelineResult(call_id=call_id, events=events[:500], findings=findings, tool_errors=errors).model_dump()

    elif tool_name == "analyze_persistence":
        pf_entries, reg_findings_list, all_findings = [], [], []
        if pfd := tool_input.get("prefetch_dir"):
            e, f = art_tools.parse_prefetch_directory(pfd)
            pf_entries.extend(e); all_findings.extend(f)
        for hive_key, plugins in [
            ("ntuser_hive", ["run", "runonce", "userassist"]),
            ("software_hive", ["run", "runonce"]),
            ("system_hive", ["services", "shimcache"]),
        ]:
            if hpath := tool_input.get(hive_key):
                rf, f = art_tools.run_regripper(hpath, plugins)
                reg_findings_list.extend(rf); all_findings.extend(f)
        from mcp_server.models import ArtifactResult
        return ArtifactResult(call_id=call_id, prefetch_entries=pf_entries, registry_findings=reg_findings_list, findings=all_findings).model_dump()

    elif tool_name == "correlate_findings":
        from mcp_server.server import correlate_findings
        return correlate_findings(tool_input["memory_findings"], tool_input["disk_findings"])

    elif tool_name == "score_severity":
        from mcp_server.server import score_severity
        return score_severity(tool_input["findings"])

    return {"error": f"unknown tool: {tool_name}"}


def _log_iteration(case_dir: Path, iteration: int, tool_name: str, result_summary: str) -> None:
    log_path = AUDIT_DIR / "iterations.jsonl"
    with open(log_path, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iteration": iteration,
            "tool_called": tool_name,
            "result_summary": result_summary[:500],
        }) + "\n")


def run_agent(case_description: str, case_dir: str) -> dict:
    """
    Run the autonomous DFIR agent on a case.

    Args:
        case_description: Free-text description of available artifacts and case context
        case_dir: Directory containing case artifacts
    """
    client = anthropic.Anthropic()
    corroborate_engine = CorroborationEngine()
    messages: list[dict] = [
        {
            "role": "user",
            "content": f"Investigate this case:\n\n{case_description}\n\nCase directory: {case_dir}\n\nBegin autonomous investigation.",
        }
    ]

    AUDIT_DIR.mkdir(exist_ok=True)
    print(f"\n[find-evil] Starting investigation | case_dir={case_dir}", flush=True)
    print(f"[find-evil] Audit log: {AUDIT_DIR}", flush=True)
    print(f"[find-evil] Max iterations: {MAX_ITERATIONS}\n", flush=True)

    iteration = 0
    accumulated_findings: list[dict] = []
    final_report: dict = {}

    while iteration < MAX_ITERATIONS:
        iteration += 1
        print(f"[iter {iteration}/{MAX_ITERATIONS}] Calling Claude...", flush=True)

        response = client.messages.create(
            model=MODEL,
            max_tokens=8096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            last_text = next((b.text for b in response.content if hasattr(b, "text")), "")
            print(f"[iter {iteration}] Agent stopped: {last_text[:200]}", flush=True)
            if "ANALYSIS_COMPLETE" in last_text:
                break
            # Agent thinks it's done but didn't use the terminal keyword — let it finish
            break

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_name = block.name
            tool_input = block.input
            print(f"[iter {iteration}] Tool: {tool_name} | params: {list(tool_input.keys())}", flush=True)

            t0 = time.time()
            try:
                result = _call_mcp_tool(tool_name, tool_input, corroborate_engine)
            except Exception as exc:
                result = {"error": str(exc), "tool": tool_name}

            duration_ms = int((time.time() - t0) * 1000)
            print(f"[iter {iteration}] {tool_name} completed in {duration_ms}ms", flush=True)

            # Accumulate findings for corroboration tracking
            if isinstance(result, dict) and "findings" in result:
                new_findings = result.get("findings", [])
                accumulated_findings.extend(new_findings)
                print(f"[iter {iteration}] +{len(new_findings)} findings (total: {len(accumulated_findings)})", flush=True)

            if tool_name == "generate_incident_report":
                final_report = result

            _log_iteration(Path(case_dir), iteration, tool_name, json.dumps(result)[:500])

            # Truncate large results before sending back to model to prevent context overflow
            truncated_result = _truncate_result(result)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(truncated_result),
            })

        if tool_results:
            messages.append({"role": "user", "content": tool_results})

    print(f"\n[find-evil] Investigation complete | {iteration} iterations | {len(accumulated_findings)} total findings", flush=True)
    return {
        "iterations": iteration,
        "total_findings": len(accumulated_findings),
        "report": final_report,
        "audit_log": str(AUDIT_DIR),
    }


def _truncate_result(result: dict) -> dict:
    """Prevent context window overflow by truncating large lists."""
    if not isinstance(result, dict):
        return result
    truncated = {}
    for k, v in result.items():
        if isinstance(v, list) and len(v) > 50:
            truncated[k] = v[:50]
            truncated[f"{k}_truncated"] = f"(showing 50 of {len(v)})"
        else:
            truncated[k] = v
    return truncated
