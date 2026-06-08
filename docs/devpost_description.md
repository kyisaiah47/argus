# ARGUS

**Hackathon:** Find Evil! — SANS SIFT Workstation Track

**Repo:** [github.com/kyisaiah47/find-evil](https://github.com/kyisaiah47/find-evil)

---

## Inspiration

Digital forensics investigations follow the same sequence every time: triage memory, check persistence, correlate artifacts, write the report. A senior analyst does it from muscle memory. Junior analysts miss steps or jump to conclusions. I wanted to encode that senior-analyst methodology into an autonomous agent — one that not only follows the right sequence but actively tries to disprove its own findings before reporting them.

---

## What It Does

Given a case directory, ARGUS runs the full DFIR investigation without human intervention:

- **Memory Triage** — Volatility 3 running pslist, netscan, and malfind simultaneously, parsed into structured findings before the model ever sees them
- **Persistence Analysis** — regripper across Run keys, shimcache, and prefetch to identify attacker footholds
- **Disk Timeline** — log2timeline anchored to suspicious timestamps from memory triage
- **Corroboration Engine** — after every HIGH or CRITICAL finding, a second independent tool runs automatically. Findings that survive are labeled CONFIRMED. Findings that don't are labeled UNVERIFIED, never silently promoted
- **Severity Scoring** — MITRE ATT&CK auto-mapped, risk level calculated across all findings
- **Structured Incident Report** — every claim traceable to the specific tool call that produced it, written to disk as `.txt` and `.json`

On the ROCBA-2020 case: ARGUS identified FTK Imager and SDelete execution from prefetch, mapped the attack to T1005 and T1070.004, and produced 8 concrete recommended actions — including acquiring USBSTOR registry keys to identify the physical exfiltration device.

---

## How I Built It

### Architecture

```
ANALYST / OPERATOR
  python find_evil.py investigate --case-dir ... --memory ...
            │
            ▼
  ARGUS AGENT LOOP (agent/loop.py)
  Claude Opus via Anthropic API
  12-iteration hard cap
  Corroboration engine after every HIGH/CRITICAL finding
            │  MCP protocol — typed function calls only
            │  No raw shell. No file writes.
            ▼
  ARGUS MCP SERVER (mcp_server/server.py)
  ┌─────────────────────────────────────┐
  │  SECURITY BOUNDARY (ARCHITECTURAL) │
  │  No execute_shell_cmd()            │
  │  No write_file()                   │
  │  No delete_file()                  │
  └─────────────────────────────────────┘
  analyze_memory()           → Volatility 3
  analyze_disk_timeline()    → log2timeline + psort
  analyze_persistence()      → regripper + prefetch
  correlate_findings()       → cross-source discrepancy engine
  score_severity()           → MITRE ATT&CK + risk score
  generate_incident_report() → .txt + .json to disk
            │  subprocess (read-only)
            ▼
  SANS SIFT WORKSTATION TOOLS
  Volatility 3 / log2timeline / regripper / fls
            │
            ▼
  CASE ARTIFACTS (never written to)
  memory.raw  disk.dd  NTUSER.DAT  SOFTWARE  SYSTEM  Prefetch\
```

Claude doesn't run a fixed script. It reads the case context, decides which artifacts to examine first, adjusts based on what each tool returns, and only writes the report when it has exhausted the available evidence — exactly like a trained analyst would.

### Tech Stack

| Layer | Technology |
|---|---|
| AI Model | Claude Opus (Anthropic API) |
| Agent Framework | Anthropic Tool Use API (agentic loop) |
| Forensics Integration | Custom MCP Server (FastMCP) |
| Backend | Python 3.10+, Pydantic v2 |
| Memory Analysis | Volatility 3 |
| Disk Timeline | log2timeline + psort |
| Registry/Prefetch | regripper + custom prefetch parser |
| Platform | SANS SIFT Workstation |

---

## Challenges

**Context window management.** Volatility output can be tens of thousands of lines. Passing raw output to the model would overflow the context window and degrade analysis quality. The MCP server parses every tool output before returning it — the agent receives structured JSON with `suspicious: bool` flags and pre-extracted IOCs, not raw text dumps.

**False positive rate.** Early versions flagged nearly every Run key as suspicious. Built a known-good path allowlist covering Program Files, Windows\System32, OneDrive, and Chrome — only flagging entries with suspicious path patterns AND no known-good indicators. The corroboration step filters further before anything reaches the report.

**Corroboration strategy per finding type.** There's no universal second check — what corroborates a memory injection is different from what corroborates a network connection. Mapped each finding category to a specific second tool. A pslist/pstree discrepancy is not a failed corroboration — it's a higher-confidence finding, a direct indicator of DKOM rootkit behavior.

**Termination conditions.** Without a hard stop, agent loops drift into redundant tool calls. Capped at 12 iterations with an `ANALYSIS_COMPLETE` signal. Every iteration is logged to `audit/iterations.jsonl` so the agent's reasoning is fully traceable.

---

## What I Learned

The most important design decision was architectural guardrails over prompt-based restrictions. When I prototyped with raw shell access, the agent would run `grep -r` across the entire filesystem and overflow both the context window and the timeline. Typed MCP functions with pre-parsed output made ARGUS faster, more accurate, and genuinely incapable of breaking evidence.

The corroboration engine is most valuable not when it confirms a finding, but when it disagrees. A process in `windows.pslist` that's absent from `windows.pstree` is a more important finding than either tool produces alone — it's a direct indicator of Direct Kernel Object Manipulation used by rootkits to hide processes. That kind of discrepancy-as-signal is the senior-analyst reasoning the baseline doesn't do.

---

## What's Next

- **NSRL integration** — cross-reference file hashes against the National Software Reference Library to eliminate known-good binaries automatically
- **YARA scanning** — add a `scan_yara(memory_image, rules_dir)` MCP tool for signature-based detection alongside behavioral analysis
- **Live endpoint support** — MCP server extension for remote triage via WinRM/SSH instead of offline images
- **Accuracy benchmarking** — run ARGUS against CFReDS Project known-answer datasets for objective FP/FN rates
- **Multi-case correlation** — track IOCs across cases to identify attacker infrastructure reuse

---

## Team

Built solo by **@kyisaiah47** for the Find Evil! Hackathon.
