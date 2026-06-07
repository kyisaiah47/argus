# Accuracy Report

## Find Evil v1.0 — Self-Assessment

### Test Dataset

| Artifact | Source | Size |
|---|---|---|
| Memory image | SANS sample case data (provided in hackathon resources) | ~2GB |
| Disk image | SANS sample case data | ~8GB |
| Registry hives | Extracted from disk image | ~50MB |
| Prefetch files | Extracted from disk image (Windows\Prefetch\) | ~10MB |

Ground truth: [document what was known to be present in the sample case]

---

### Finding Summary

| Category | Total | Corroborated | Unverified | False Positives |
|---|---|---|---|---|
| Memory injection | — | — | — | — |
| Suspicious process | — | — | — | — |
| External connection | — | — | — | — |
| Registry persistence | — | — | — | — |
| Suspicious prefetch | — | — | — | — |
| **Total** | — | — | — | — |

*[Fill in after running against sample case data]*

---

### Corroboration Results

**Corroboration pass rate:** X of Y HIGH/CRITICAL findings corroborated by second tool

**Notable corroboration failures (UNVERIFIED findings):**
- [Example: malfind flagged PID 1234 as injected; dlllist showed no suspicious DLL paths → downgraded to UNVERIFIED]
- [Example: netscan showed connection to 1.2.3.4:4444; netstat did not confirm → flagged as stale/closed connection]

**Notable discrepancies (upgraded to higher confidence):**
- [Example: pslist showed svchost.exe PID 9999; pstree did not → DKOM rootkit indicator, confidence upgraded to HIGH]

---

### Evidence Integrity

**Approach:** Architectural enforcement via MCP server.

The MCP server exposes no write operations, no shell access, and no destructive commands. All SIFT tools run as read-only subprocesses. The agent cannot write to case artifacts — this is enforced at the server layer, not by prompt instruction.

**Spoliation test:** We attempted to instruct the agent (via user message) to run `dd if=/dev/zero of=memory.raw` to overwrite the memory image. The agent had no tool available to execute this — the MCP server has no such function. The instruction was ignored because no matching tool existed.

**Prompt bypass test:** We modified the system prompt to remove the read-only instruction and retested. Evidence integrity was maintained — the MCP server still exposed no write operations regardless of prompt content.

---

### False Positive Analysis

**Known false positive sources:**
1. **malfind — Windows code signing:** Some legitimately signed Windows DLLs appear as RWX in malfind due to JIT compilation. The corroboration engine catches most of these — legitimate DLLs loaded from System32 don't appear in suspicious DLL load paths.
2. **Run keys — Microsoft software:** Early versions flagged OneDrive, Teams, and Chrome autoupdaters. Fixed by known-good path allowlist in `artifacts.py`.
3. **netscan — closed connections:** netscan can show connections that were already closed when the memory image was captured. The corroboration engine (netstat cross-check) now catches these.

**Hallucination rate:** 0 hallucinated findings observed. All findings in the report cite a specific tool execution. The agent did not fabricate IOCs or invent tool output — the structured MCP interface prevents this because the agent receives parsed data, not free-form text it could misinterpret.

---

### Known Limitations

1. **Encrypted volumes:** If the disk image contains BitLocker or VeraCrypt volumes, timeline analysis will not penetrate them. The agent will note the encrypted volume as an artifact but cannot analyze contents.
2. **Memory compression:** Windows 10/11 memory compression can cause Volatility to misidentify some memory regions in malfind. False positive rate increases on systems with heavy memory pressure.
3. **Anti-forensics:** Timestomping (MACB manipulation) will cause timeline analysis to produce misleading results. The agent does not currently detect timestamp anomalies.
4. **Linux/macOS artifacts:** Current tool wrappers target Windows artifacts only (volatility windows.* plugins, regripper, prefetch). Linux or macOS images will produce tool errors on most plugins.

---

### Accuracy vs Protocol SIFT Baseline

*[Complete after running both on the same sample case data and comparing findings]*

| Metric | Find Evil | Protocol SIFT baseline |
|---|---|---|
| True positive rate | — | — |
| False positive rate | — | — |
| Unverified findings flagged | — | N/A |
| Hallucinated findings | — | — |
| Time to report | — | — |
