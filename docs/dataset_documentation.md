# Dataset Documentation

## Case Data — ROCBA-2020

### Source

SANS Institute — "The Fred Rocba Case" forensic training dataset, distributed via the Find Evil! hackathon resources page.

**Case background:** Fred Rocba, employee at Stark Research Labs. Physical break-in at his residence on November 13, 2020 while on vacation. Suspect accessed his laptop and exfiltrated data. Memory captured November 16 (3 days post-incident). C: drive imaged to rocba-cdrive.e01.

All data is sourced from SANS Institute's publicly distributed forensic training materials. No real victim data. No proprietary artifacts.

---

### Artifacts Included in Repo (`cases/sample/`)

| Artifact | Type | Notes |
|---|---|---|
| Rocba-Memory.raw | Raw memory image | Windows 10 x64, captured 2020-11-16 |
| artifacts/registry/NTUSER_fredr.DAT | Registry hive | Fred Rocba's user hive |
| artifacts/registry/SOFTWARE | Registry hive | System SOFTWARE hive |
| artifacts/registry/SYSTEM | Registry hive | System SYSTEM hive |
| artifacts/prefetch/ | Prefetch files | Windows\Prefetch\ directory contents |

Note: rocba-cdrive.e01 (full disk image, ~22GB) is not included in the repo due to size. Registry hives and prefetch files were pre-extracted from it.

---

### Ground Truth

Known attacker activity confirmed by case background and forensic artifacts:

- **FTKIMAGER.EXE** — AccessData FTK Imager executed. Used to image the drive to external media for offline exfiltration. (MITRE T1005)
- **SDELETE.EXE** — Sysinternals SDelete executed twice (two distinct prefetch hashes). Used for anti-forensic cleanup of dropped tools and staging artifacts. (MITRE T1070.004)
- **No persistence** — One-shot physical access. No Run key or service modifications observed.
- **No live attacker processes** — Memory captured 3 days post-incident. All attacker tools had exited.

---

### What ARGUS Found

Run 2026-06-08, 6 iterations, ~3 minutes:

- FTKIMAGER.EXE identified from prefetch — correct
- SDELETE.EXE identified from prefetch (2 executions) — correct
- T1005 and T1070.004 auto-mapped — correct
- No false positives in final report
- Evidence gaps (missing disk timeline, memory acquisition timing) explicitly flagged

---

### Reproducibility

All artifacts required to reproduce the full analysis are included in `cases/sample/`. Clone the repo and follow the README — no additional data download required.

The audit log (`audit/session_*.jsonl`) records every tool call with parameters and outputs. Any finding can be independently verified by re-running the specific tool command logged.
