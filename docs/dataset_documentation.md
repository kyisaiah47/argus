# Dataset Documentation

## Case Data Used for Testing and Demo

### Source
SANS SIFT Workstation sample case data — "The Fred Rocba Case" (Standard Forensic Case, HACKATHON-2026).
Provided by Rob Lee / SANS Institute via the Find Evil! hackathon resources page (sansorg.egnyte.com).

**Case background:** Fred Rocba, new employee at Stark Research Labs (defense/biotech contractor).
Physical break-in at his home on November 13, 2020 while on vacation at Disney World. Suspect accessed
his laptop and exfiltrated intellectual property. Memory captured November 16 (post-incident).
Disk image captures the C: drive including suspect activity.

All data is sourced from SANS Institute's publicly distributed forensic training materials.
No real victim data. No proprietary artifacts.

### Artifacts

| Artifact | Type | Size | Notes |
|---|---|---|---|
| Rocba-Memory.raw | Raw memory image | 18 GB | Windows 10 x64, 2020-11-16 02:32 UTC |
| rocba-cdrive.e01 | E01 disk image | 22.1 GB | C: drive, NTFS, Windows 10 |

### What the Agent Found

**Memory analysis run — 2026-06-07, 6 iterations, ~3 minutes**

| Check | Tool | Result |
|---|---|---|
| Process injection | volatility:malfind | CLEAN — zero injected regions |
| Suspicious processes | volatility:pslist | 3 heuristic alerts → corroborated as benign FPs (orphan-PPID Windows artifacts) |
| External connections | volatility:netscan | CLEAN — legitimate traffic only (Teams, Slack, iCloud, Google Drive) |
| Persistence | N/A | UNABLE TO ASSESS — no disk provided; agent flagged gap correctly |

**Disk analysis run — pending (rocba-cdrive.e01 downloading)**

Expected findings: evidence of data exfiltration, attacker tooling, modified files post-Nov-13.

### Reproducibility

Judges can reproduce the exact analysis by:

1. Downloading the SANS sample case data from the hackathon resources page
2. Installing Find Evil on a SIFT Workstation following `README.md`
3. Running:
```bash
python find_evil.py investigate \
  --case-dir /path/to/case \
  --case-id HACKATHON-DEMO \
  --memory memory.raw \
  --disk disk.dd \
  --ntuser /path/to/NTUSER.DAT \
  --software /path/to/SOFTWARE \
  --system /path/to/SYSTEM \
  --prefetch /path/to/Prefetch
```

The audit log (`audit/session_*.jsonl`) records every tool call with parameters — any finding can be independently reproduced by re-running the specific Volatility/regripper command logged.

### Evidence Integrity Verification

Original artifacts were not modified during analysis. To verify:
```bash
# Hash the memory image before and after running Find Evil
sha256sum memory.raw  # record this value
python find_evil.py investigate ...
sha256sum memory.raw  # must match
```
