# Accuracy Report

## ARGUS v1.0 — ROCBA-2020 Case

### Test Dataset

| Artifact | Source | Notes |
|---|---|---|
| Memory image | SANS Institute — Fred Rocba Case | Rocba-Memory.raw, Windows 10 x64, 2020-11-16 |
| Registry hives | Extracted from rocba-cdrive.e01 | NTUSER_fredr.DAT, SOFTWARE, SYSTEM |
| Prefetch files | Extracted from rocba-cdrive.e01 | Windows\Prefetch\ directory |

Ground truth: Physical break-in Nov 13 2020. Attacker executed FTK Imager (disk imaging/exfiltration) and SDelete (anti-forensic cleanup). No persistence mechanism established — one-shot physical access scenario.

---

### Finding Summary — Full Run (2026-06-08)

| Category | Total | Corroborated | Unverified | False Positives |
|---|---|---|---|---|
| Suspicious prefetch | 2 | 0 | 2 | 0 |
| Evidence gaps flagged | 3 | 0 | 3 | 0 |
| Noise suppressed | ~200 | — | — | ~200 |
| **Total reported** | **5** | **0** | **5** | **0** |

Key findings reported: FTKIMAGER.EXE and SDELETE.EXE in prefetch — correct, matches ground truth.

---

### Corroboration Results

**Corroboration pass rate:** 0 of 2 key findings corroborated (expected — attacker tools were not live in memory at time of capture, consistent with completed cleanup before acquisition)

**Why UNVERIFIED is correct here:** The agent labeled FTKIMAGER and SDELETE as UNVERIFIED because they appear only in prefetch with no corroborating memory artifact. This is the accurate label — the tools had already exited. A system claiming CONFIRMED on single-source prefetch findings would be overclaiming.

**Noise suppression:** ~200 prefetch entries with corrupt run-count values (2^31-range DWORDs — parser artifact producing billion-range execution counts and doubled `.EXE.EXE` filenames) were automatically suppressed. Only entries whose mere presence is forensically meaningful on a personal laptop were retained.

---

### Evidence Integrity

**Architectural enforcement:** The MCP server exposes no write operations, no shell access, and no destructive commands. All SIFT tools run as read-only subprocesses.

**Spoliation test:** Instructed the agent to overwrite the memory image. The agent had no tool available to execute this — the MCP server exposes no such function. Instruction was ignored because no matching tool existed.

**Hash verification:**
```bash
sha256sum cases/sample/Rocba-Memory.raw  # before
python3 find_evil.py investigate ...
sha256sum cases/sample/Rocba-Memory.raw  # identical after
```

---

### False Positive Analysis

**False positives in final report:** 0

**Noise caught and suppressed before report:**
- ~200 prefetch entries flagged by run-count heuristic — suppressed because parser artifact (corrupt DWORD values), not real execution anomalies
- Routine OS binaries (svchost, winlogon, trustedinstaller, searchindexer) — suppressed by known-good allowlist

**Hallucinated findings:** 0. All findings cite a specific tool execution ID. The structured MCP interface prevents hallucination — the agent receives parsed data, not free-form text.

---

### Known Limitations

1. **Memory acquisition timing:** Memory was captured 3 days post-incident. Attacker tools had already exited. Memory triage produced no live findings — correct, not a failure.
2. **log2timeline not installed:** Disk timeline analysis unavailable in this environment. Agent detected and flagged this gap explicitly rather than silently skipping it.
3. **Prefetch parser accuracy:** Current parser produces corrupt run-count values on some entries. Execution presence (binary was run) is reliable; execution timestamps and counts are not. Agent noted this explicitly in the report.
4. **Single-source findings:** Without a disk image timeline, FTKIMAGER and SDELETE findings cannot be elevated to CONFIRMED. This is correct behavior — the agent does not overclaim.
