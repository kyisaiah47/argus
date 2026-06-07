# Devpost Submission — Find Evil!
# Copy-paste each section into the Devpost project form

---

## What it does

Find Evil is an autonomous DFIR agent that investigates disk images and memory captures on the SANS SIFT Workstation. Given a case directory, it runs the full investigation — memory triage, persistence analysis, disk timeline, cross-source correlation, and severity scoring — without human intervention, producing a structured incident report with every finding traceable to the specific tool execution that produced it.

The core differentiator: after every HIGH or CRITICAL finding, the agent automatically attempts corroboration via a second independent tool before labeling anything CONFIRMED. If corroboration fails, the finding is labeled UNVERIFIED in the final report. This directly addresses Protocol SIFT's stated hallucination problem — the agent catches its own mistakes before writing the report.

---

## How we built it

**Architecture: Custom MCP Server**

The agent connects to a purpose-built MCP server that exposes typed, read-only functions instead of raw shell access. The server wraps key SIFT Workstation tools:

- `analyze_memory()` — Volatility 3: pslist, netscan, malfind in one structured call
- `analyze_disk_timeline()` — log2timeline + psort, returns structured events (no raw text dumps)
- `analyze_persistence()` — regripper (Run keys, shimcache) + prefetch parser
- `correlate_findings()` — cross-references memory and disk IOCs, flags discrepancies
- `score_severity()` — risk scoring with MITRE ATT&CK mapping
- `generate_incident_report()` — writes structured .txt + .json report to disk

**Evidence integrity by architecture, not by prompt.** The MCP server exposes no shell access, no file write tools, and no destructive commands. The agent physically cannot spoliate evidence — this constraint is enforced at the server layer.

**The corroboration engine** (`agent/corroborate.py`) runs after every HIGH/CRITICAL finding. For process injection, it cross-checks with `windows.dlllist` for suspicious DLL load paths. For suspicious processes, it runs `windows.pstree` — a discrepancy between pslist and pstree is itself a high-confidence rootkit indicator (DKOM). For external connections, it independently confirms via `windows.netstat`.

**The agent loop** uses Claude Opus via the Anthropic API with a 12-iteration cap. The system prompt encodes a senior analyst's investigation sequence: volatile memory first, persistence second, corroborate before concluding, disk timeline anchored to suspicious timestamps from memory. The agent logs every tool call with timestamps and token usage to a JSONL audit file.

**Stack:** Python 3.10+, Anthropic SDK, MCP Python SDK (FastMCP), Pydantic v2, Volatility 3, log2timeline, regripper.

---

## Challenges we ran into

**Context window management.** Volatility output can be tens of thousands of lines. Passing raw tool output to the LLM would overflow the context window and degrade analysis quality. The MCP server solves this by parsing every tool output before returning it — the agent receives structured JSON with `suspicious: bool` flags and pre-extracted IOCs, not raw text.

**False positive rate.** Early versions flagged nearly every Run key as suspicious. We built a known-good path allowlist (Program Files, Windows\System32, OneDrive, Chrome) and only flag entries with both suspicious path patterns AND no known-good indicators. The corroboration step further filters findings before they reach the report.

**Corroboration strategy per finding type.** There's no universal "second check" — what corroborates a memory injection is different from what corroborates a network connection. We mapped each finding category to a specific second tool with a specific interpretation of that tool's output. A pslist/pstree discrepancy is not a failed corroboration — it's a higher-confidence finding (DKOM rootkit indicator).

**Termination conditions.** Without a hard stop, agent loops drift into redundant tool calls. We cap at 12 iterations and instruct the agent to emit `ANALYSIS_COMPLETE` when done. Iteration traces in `audit/iterations.jsonl` show the agent's approach changing across iterations.

---

## What we learned

The most important design decision was choosing architectural guardrails over prompt-based restrictions. When we prototyped with raw shell access, the agent would occasionally run `grep -r` across the entire filesystem and overflow both the context window and the analysis timeline. Typed MCP functions with pre-parsed output made the agent faster, more accurate, and genuinely incapable of breaking evidence.

We also learned that the corroboration engine is most valuable not when it confirms a finding, but when it disagrees. A process present in `windows.pslist` but absent from `windows.pstree` is a more important finding than either tool would produce alone — it's a direct indicator of Direct Kernel Object Manipulation, used by rootkits to hide processes. The agent discovering that discrepancy and labeling it explicitly is the kind of senior-analyst reasoning Protocol SIFT's current baseline doesn't do.

---

## What's next

- **NSRL integration:** Cross-reference file hashes against the National Software Reference Library to eliminate known-good binaries from findings automatically.
- **YARA scanning:** Add a `scan_yara(memory_image, rules_dir)` MCP tool for signature-based detection alongside behavioral analysis.
- **Live endpoint support:** MCP server extension for remote endpoint triage via WinRM/SSH instead of offline images.
- **Accuracy benchmarking framework:** Run Find Evil against the CFReDS Project's known-answer datasets to produce objective false positive and false negative rates for community comparison.
- **Multi-case correlation:** Track IOCs across cases to identify attacker infrastructure reuse.

---

## Built With

`python` `anthropic-api` `mcp` `pydantic` `volatility3` `log2timeline` `regripper` `sans-sift-workstation` `digital-forensics` `incident-response` `dfir`
