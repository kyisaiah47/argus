# ARGUS

**Autonomous DFIR agent on the SANS SIFT Workstation — built for the Find Evil! hackathon.**

ARGUS connects Claude Opus to SIFT's 200+ forensics tools through a purpose-built MCP server with typed, read-only functions. The agent investigates disk images and memory captures, corroborates every HIGH/CRITICAL finding with a second independent tool, and produces a structured incident report with full audit trail.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       ARGUS Agent                           │
│              (Claude Opus via Anthropic API)                │
│                                                             │
│  System prompt: senior analyst methodology                  │
│  Self-correction loop: max 12 iterations                    │
│  Corroboration engine: every finding verified independently │
└──────────────────────┬──────────────────────────────────────┘
                       │ MCP (typed function calls)
                       │ NO raw shell access
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    ARGUS MCP Server                         │
│           (read-only, typed tool wrappers)                  │
│                                                             │
│  analyze_memory()        → Volatility 3                     │
│  analyze_disk_timeline() → log2timeline + psort             │
│  analyze_persistence()   → regripper + prefetch             │
│  correlate_findings()    → cross-source discrepancy engine  │
│  score_severity()        → risk scoring + MITRE ATT&CK      │
│  generate_incident_report() → structured .txt + .json       │
└──────────────────────┬──────────────────────────────────────┘
                       │ subprocess (read-only)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              SANS SIFT Workstation                          │
│                                                             │
│  Volatility 3   log2timeline   psort   regripper   fls      │
│  (200+ tools — agent has access only to what MCP exposes)   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Case Artifacts                            │
│         (read-only mount — never modified)                  │
│                                                             │
│  memory.raw   disk.dd   NTUSER.DAT   SOFTWARE   SYSTEM      │
└─────────────────────────────────────────────────────────────┘
```

**Security boundary:** The MCP server exposes no shell access, no file write operations, and no destructive commands. The agent physically cannot spoliate evidence — this is enforced architecturally, not by prompt.

## Requirements

- SANS SIFT Workstation (Ubuntu-based, x86-64 VM)
- Python 3.10+
- Anthropic API key
- SIFT tools: `vol`, `log2timeline.py`, `psort.py`, `regripper`, `fls`

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/find-evil.git
cd find-evil

# 2. Set your API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# 3. Run the installer
chmod +x install.sh && ./install.sh
```

## Usage

### Autonomous agent (recommended)

```bash
source .venv/bin/activate
export $(cat .env | xargs)

python find_evil.py investigate \
  --case-dir /cases/case001 \
  --case-id CASE-001 \
  --memory memory.raw \
  --disk disk.dd \
  --ntuser /mnt/disk/Users/victim/NTUSER.DAT \
  --software /mnt/disk/Windows/System32/config/SOFTWARE \
  --system /mnt/disk/Windows/System32/config/SYSTEM \
  --prefetch /mnt/disk/Windows/Prefetch
```

The agent runs autonomously, corroborates findings, and writes a report to `audit/reports/`.

### Claude Code (MCP mode)

```bash
# Register the MCP server with Claude Code
claude mcp add find-evil -- $(pwd)/.venv/bin/python $(pwd)/find_evil.py mcp-server

# Open Claude Code in the case directory
claude
```

Claude Code will have access to all ARGUS tools and will follow the investigation methodology in `CLAUDE.md`.

## Output

```
audit/
├── session_20260607_143022.jsonl   ← every tool call with timestamps + params
├── iterations.jsonl                ← iteration-by-iteration agent trace
└── reports/
    ├── CASE-001_20260607_143122.txt  ← human-readable incident report
    └── CASE-001_20260607_143122.json ← machine-readable findings + IOCs
```

Every finding in the report links back to the specific tool call that produced it via `call_id`.

## Self-Correction

After every HIGH/CRITICAL finding, the corroboration engine runs a second independent Volatility plugin:

| Finding | Primary | Corroboration |
|---|---|---|
| Process injection (malfind) | `windows.malfind` | `windows.dlllist` (RWX DLL paths) |
| Suspicious process (pslist) | `windows.pslist` | `windows.pstree` (DKOM check) |
| External connection (netscan) | `windows.netscan` | `windows.netstat` |
| Registry persistence | `regripper:run` | Prefetch (was binary executed?) |

Findings that fail corroboration are labeled `UNVERIFIED` in the final report — never promoted to CONFIRMED.

## Tests

```bash
source .venv/bin/activate
python -m pytest tests/ -v
```

10 unit tests covering parser logic with synthetic tool output. No SIFT tools required.

## License

MIT
