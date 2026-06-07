# Architecture Diagram

## Pattern: Custom MCP Server (Approach #2)

```
╔══════════════════════════════════════════════════════════════════════════╗
║                         FIND EVIL ARCHITECTURE                          ║
╚══════════════════════════════════════════════════════════════════════════╝

  ┌─────────────────────────────────────────────────┐
  │              ANALYST / OPERATOR                  │
  │                                                  │
  │  python find_evil.py investigate                 │
  │    --case-dir /cases/001                         │
  │    --memory memory.raw --disk disk.dd            │
  └──────────────────────┬──────────────────────────┘
                         │ CLI invocation
                         ▼
  ┌─────────────────────────────────────────────────┐   ┌─────────────────┐
  │            FIND EVIL AGENT LOOP                  │   │  AUDIT SYSTEM   │
  │           agent/loop.py                          │   │                 │
  │                                                  │◄──│ session.jsonl   │
  │  • Claude Opus (claude-opus-4-7)                 │   │ iterations.jsonl│
  │  • System prompt: senior analyst methodology     │   │                 │
  │  • Max 12 iterations (hard cap)                  │   │ Every tool call │
  │  • Corroboration engine runs after               │   │ logged with:    │
  │    every HIGH/CRITICAL finding                   │   │ - timestamp     │
  │  • Truncates large results before                │   │ - params        │
  │    returning to model (context protection)       │   │ - duration_ms   │
  └──────────────────────┬──────────────────────────┘   │ - findings[]    │
                         │                               └─────────────────┘
                         │ MCP protocol (stdio)
                         │ TYPED FUNCTION CALLS ONLY
                         │ No raw shell. No file writes.
                         ▼
  ╔═════════════════════════════════════════════════╗
  ║           FIND EVIL MCP SERVER                  ║
  ║           mcp_server/server.py                  ║
  ║                                                 ║
  ║  ┌─────────────────────────────────────────┐   ║
  ║  │  SECURITY BOUNDARY (ARCHITECTURAL)      │   ║
  ║  │                                         │   ║
  ║  │  The server exposes NO:                 │   ║
  ║  │    ✗ execute_shell_cmd()                │   ║
  ║  │    ✗ write_file()                       │   ║
  ║  │    ✗ delete_file()                      │   ║
  ║  │    ✗ mount_readwrite()                  │   ║
  ║  │                                         │   ║
  ║  │  Agent physically cannot spoliate       │   ║
  ║  │  evidence — not by prompt, by design.   │   ║
  ║  └─────────────────────────────────────────┘   ║
  ║                                                 ║
  ║  EXPOSED TOOLS (read-only, typed, pre-parsed):  ║
  ║                                                 ║
  ║  analyze_memory(memory_image)                   ║
  ║    └─► ProcessList + NetworkConns + Injections  ║
  ║        Returns structured JSON, not raw text    ║
  ║                                                 ║
  ║  analyze_disk_timeline(disk_image, start?, end?)║
  ║    └─► TimelineEvents (filtered, structured)    ║
  ║                                                 ║
  ║  analyze_persistence(prefetch?, hives?)         ║
  ║    └─► PrefetchEntries + RegistryFindings       ║
  ║                                                 ║
  ║  correlate_findings(mem_findings, disk_findings)║
  ║    └─► Corroborations + Discrepancies           ║
  ║                                                 ║
  ║  score_severity(findings)                       ║
  ║    └─► RiskLevel + MITRE ATT&CK + Actions       ║
  ║                                                 ║
  ║  generate_incident_report(...)                  ║
  ║    └─► .txt + .json to audit/reports/           ║
  ╚═════════════════════════════════════════════════╝
                         │
                         │ subprocess (read-only)
                         ▼
  ┌─────────────────────────────────────────────────┐
  │           SIFT WORKSTATION TOOLS                │
  │                                                 │
  │  Volatility 3      log2timeline    psort        │
  │  regripper         fls             pecmd        │
  │                                                 │
  │  Output parsed BEFORE returning to LLM:         │
  │  • No context window overflow                   │
  │  • Structured findings, not raw text dumps      │
  │  • Suspicious flags pre-computed                │
  └──────────────────────┬──────────────────────────┘
                         │ read-only subprocess
                         ▼
  ┌─────────────────────────────────────────────────┐
  │              CASE ARTIFACTS                     │
  │           (NEVER WRITTEN TO)                    │
  │                                                 │
  │  memory.raw    disk.dd    NTUSER.DAT            │
  │  SOFTWARE      SYSTEM     Windows\Prefetch\     │
  └─────────────────────────────────────────────────┘


╔══════════════════════════════════════════════════════════════════════════╗
║                     CORROBORATION ENGINE                                 ║
║                    (key differentiator)                                  ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  For every HIGH or CRITICAL finding:                                     ║
║                                                                          ║
║  ┌──────────────┐    PASS     ┌──────────────────┐    CONFIRMED          ║
║  │ Primary Tool ├────────────►│ Corroboration    ├──────────────────►    ║
║  │ (finding)    │             │ Tool (2nd check) │                       ║
║  └──────────────┘             └────────┬─────────┘    UNVERIFIED         ║
║                                        │ FAIL    ──────────────────►    ║
║                                                                          ║
║  Finding Type          Primary              Corroboration               ║
║  ─────────────────────────────────────────────────────────────────────  ║
║  Memory injection      malfind              dlllist (RWX DLL paths)     ║
║  Suspicious process    pslist               pstree (DKOM rootkit check) ║
║  External connection   netscan              netstat (independent scan)  ║
║  Registry persistence  regripper:run        prefetch (was it run?)      ║
║  Suspicious prefetch   prefetch parser      shimcache (was it on disk?) ║
║                                                                          ║
║  DISCREPANCY = higher confidence, not lower.                             ║
║  pslist shows process, pstree does not → DKOM rootkit indicator.        ║
╚══════════════════════════════════════════════════════════════════════════╝


╔══════════════════════════════════════════════════════════════════════════╗
║                    GUARDRAIL CLASSIFICATION                              ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  ARCHITECTURAL (cannot be bypassed by model):                            ║
║  • MCP server exposes no shell, no write, no destructive commands        ║
║  • All SIFT tools run as read-only subprocesses                          ║
║  • Hard iteration cap (12) in agent loop code — not in prompt            ║
║  • Output truncation prevents context overflow — enforced in code        ║
║                                                                          ║
║  PROMPT-BASED (instructed, can be instructed otherwise):                 ║
║  • "Volatile artifacts first" investigation order                        ║
║  • "Corroborate before concluding" methodology                           ║
║  • "Label discrepancies explicitly" reporting standard                   ║
║                                                                          ║
║  Bypass test: model ignoring prompt rules → still cannot write files     ║
║  or run shell commands. Evidence integrity survives prompt injection.    ║
╚══════════════════════════════════════════════════════════════════════════╝
```
