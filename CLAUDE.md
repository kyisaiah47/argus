# Find Evil — Claude Code Integration

## What This Is
Find Evil connects Claude Code to SIFT Workstation forensics tools via MCP.
All tools are READ-ONLY. You cannot modify case evidence.

## Available MCP Tools
- `analyze_memory(memory_image)` — Volatility: pslist + netscan + malfind
- `analyze_disk_timeline(disk_image, start_time?, end_time?)` — log2timeline + psort
- `analyze_persistence(prefetch_dir?, ntuser_hive?, software_hive?, system_hive?)` — regripper + prefetch
- `correlate_findings(memory_findings, disk_findings)` — cross-source discrepancy detection
- `score_severity(findings)` — risk scoring + recommended actions
- `generate_incident_report(...)` — write structured report to disk

## Investigation Methodology

**Always follow this order:**

1. `analyze_memory` first — volatile artifacts disappear
2. `analyze_persistence` — attackers establish footholds
3. **Corroborate every HIGH/CRITICAL finding** — run a second tool before calling it confirmed
4. `analyze_disk_timeline` — anchor suspicious timestamps, filter with start/end time from step 1-2
5. `correlate_findings` — pass memory_findings and disk_findings together
6. `score_severity` — pass ALL accumulated findings
7. `generate_incident_report` — write final report

## Evidence Integrity Rules

- NEVER modify original images. All tools mount read-only.
- Label findings explicitly: CONFIRMED (2+ sources) vs INFERRED (1 source) vs UNVERIFIED (corroboration failed)
- If two tools disagree → state the discrepancy explicitly. Do NOT silently pick one.
- Cite the specific tool + call_id for every claim.

## Self-Correction Checklist

After initial triage, ask:
- "Does this finding make sense given what else I've seen?"
- "Could this be a false positive? What second tool would corroborate or refute it?"
- "What haven't I checked yet? What gaps exist?"

If you identify a gap, fill it before writing the report.

## Corroboration Strategies by Finding Type

| Finding | Primary Tool | Corroboration Tool |
|---|---|---|
| Process injection (malfind) | windows.malfind | windows.dlllist for that PID |
| Suspicious process | windows.pslist | windows.pstree (DKOM check) |
| External connection | windows.netscan | windows.netstat |
| Registry persistence | regripper:run | prefetch (was the binary executed?) |
| Suspicious prefetch | prefetch parser | shimcache (was it on disk?) |

## Termination

When you have:
- Analyzed all available case artifacts
- Attempted corroboration on all HIGH/CRITICAL findings
- Called `score_severity`
- Called `generate_incident_report`

...stop. Do not keep running tools after the report is written.
