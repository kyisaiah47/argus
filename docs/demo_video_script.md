# Demo Video Script — Find Evil (5 min max)

## Setup before recording
- Terminal: full screen, large font (18pt+), dark theme
- Have the command ready to paste
- Clear audit/reports/ and audit/iterations.jsonl so the run is fresh
- Memory image: Rocba-Memory.raw (clean baseline) OR rocba-cdrive artifacts

---

## [0:00–0:30] Hook — the problem

Narrate over a blank terminal:

> "An AI-powered adversary can achieve full domain compromise in under 8 minutes.
> A human incident responder is still pulling up their toolkit.
> Find Evil closes that gap — a fully autonomous DFIR agent that investigates
> memory and disk artifacts, corroborates every finding with a second tool,
> and produces a structured incident report. No human in the loop."

---

## [0:30–1:00] Architecture — 15 seconds

Show the architecture diagram (docs/architecture_diagram.md) briefly:

> "The key design decision: a custom MCP server exposes typed, read-only
> forensics functions. The agent physically cannot run destructive commands —
> not by prompt instruction, by architecture. Evidence integrity is enforced
> at the server layer."

---

## [1:00–1:30] Launch the agent

```bash
cd /Users/admin/Projects/find-evil
source .venv/bin/activate
export ANTHROPIC_API_KEY=...

python find_evil.py investigate \
  --case-id ROCBA-2020 \
  --case-dir cases/sample \
  --memory cases/sample/Rocba-Memory.raw \
  --context "Suspected APT compromise, Windows 10, Nov 2020"
```

Narrate:
> "Single command. The agent takes it from here."

---

## [1:30–3:30] Agent running — narrate as it works

Watch the output. Narrate each iteration as it appears:

**Iter 1 — analyze_memory:**
> "Volatility 3 running pslist, netscan, and malfind simultaneously.
> The MCP server parses all output before returning it to the model —
> the agent receives structured findings, not raw text dumps."

**Iter 2 — analyze_persistence:**
> "Agent moves to persistence mechanisms — a senior analyst always checks
> for footholds after initial triage."

**[KEY MOMENT] Corroboration:**
> "Watch this — the agent flagged csrss.exe and wininit.exe as suspicious
> based on orphan parent PIDs. But rather than reporting them as confirmed,
> it ran pstree as a second check. The discrepancy resolved: these are
> benign Windows artifacts. The heuristic fired, the corroboration caught it.
> Zero false positives in the final report."

**Iter 3 — correlate_findings:**
> "Cross-referencing memory and disk artifacts. IOCs that appear in both
> sources get CONFIRMED status. Single-source findings stay UNVERIFIED."

---

## [3:30–4:30] Show the report

```bash
cat audit/reports/ROCBA-2020_*.txt
```

Point out:
1. **CONFIRMED vs UNVERIFIED** distinction — explicit, not buried
2. **MITRE ATT&CK coverage** — auto-mapped
3. **Recommended next steps** — agent knows what it couldn't check
4. **Audit trail note** — every finding traceable to a specific tool call

Narrate:
> "The agent explicitly flags what it couldn't verify and recommends
> acquiring the disk image. That's the gap admission — and it's
> correct. A practitioner can trust this report precisely because
> the agent distinguishes what it knows from what it inferred."

---

## [4:30–5:00] Audit trail

```bash
cat audit/iterations.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    r = json.loads(line)
    print(f\"{r['timestamp'][11:19]} | iter {r['iteration']} | {r['tool_called']}\")
"
```

Narrate:
> "Full audit trail. Every tool call, every timestamp, every finding ID.
> Judges can trace any claim in the report back to the exact Volatility
> command that produced it. This is what chain of custody looks like
> for AI-assisted forensics."

---

## Closing line

> "Find Evil — open source, MIT licensed, built on SANS SIFT Workstation
> via Model Context Protocol. The autonomous DFIR analyst that checks
> its own work."

---

## Tips
- If the agent run takes too long for the video, start recording partway through
  with the agent already running and show the live output as it finishes
- The corroboration moment (agent catching its own FP) is the money shot — make sure it's visible
- Keep terminal font large enough that text is readable in the recording
