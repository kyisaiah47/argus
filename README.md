<div align="center">

<img src="assets/banner.png" alt="banner" width="100%" />

# 🕵️ Find Evil

**Autonomous DFIR agent that never reports a finding without a second source to back it up**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Claude](https://img.shields.io/badge/Claude-Opus-D4A017?style=for-the-badge&logo=anthropic&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Server-6B46C1?style=for-the-badge&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)

</div>

<br/>

ARGUS connects Claude Opus to SIFT's 200+ forensics tools through a purpose-built MCP server with typed, read-only functions. The agent investigates disk images and memory captures, corroborates every HIGH/CRITICAL finding with a second independent tool, and produces a structured incident report with a full audit trail — all without ever touching raw shell access or modifying evidence.

## ✨ Features

- **Corroboration engine** — every HIGH/CRITICAL finding is verified by a second independent tool before it appears in the report; unverified findings are labeled `UNVERIFIED`, never promoted to `CONFIRMED`
- **Typed, read-only MCP layer** — no shell access, no file writes, no destructive commands; evidence spoliation is architecturally impossible, not just policy
- **Self-correction loop** — up to 12 autonomous iterations with full iteration-by-iteration trace logged to `audit/iterations.jsonl`
- **MITRE ATT&CK scoring** — every finding is risk-scored and mapped to ATT&CK techniques via the built-in `score_severity()` tool
- **Full audit trail** — every tool call is recorded with timestamps and parameters in `audit/session_*.jsonl`, and each report finding links back to its originating `call_id`
- **Dual output formats** — generates both a human-readable `.txt` incident report and a machine-readable `.json` findings + IOCs file

## 🎥 Demo

[![Watch Demo](https://img.shields.io/badge/YouTube-Watch%20Demo-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=_S4m4CGcdis)

## 🛠️ Tech Stack

SANS SIFT · Claude Opus (Anthropic API) · Model Context Protocol (MCP) · Volatility 3 · log2timeline · psort · regripper · Python 3.10+

## 🚀 Getting Started

```bash
# 1. Clone the repo
git clone https://github.com/kyisaiah47/argus.git
cd argus

# 2. Set your API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# 3. Run the installer
chmod +x install.sh && ./install.sh

# 4. Investigate a case
source .venv/bin/activate
export $(cat .env | xargs)

python3 find_evil.py investigate \
  --case-id ROCBA-2020 \
  --case-dir cases/sample \
  --memory cases/sample/Rocba-Memory.raw \
  --ntuser cases/sample/artifacts/registry/NTUSER_fredr.DAT \
  --software cases/sample/artifacts/registry/SOFTWARE \
  --system cases/sample/artifacts/registry/SYSTEM \
  --prefetch cases/sample/artifacts/prefetch \
  --context "Fred Rocba case: physical break-in Nov 13 2020. Investigate for attacker tooling and data exfiltration."
```

Reports are written to `audit/reports/` on completion.

The full tool-execution audit trail is written to `audit/session_<timestamp>.jsonl` (one `ToolCallRecord` per tool call, including call_id, params, duration_ms, and the list of finding IDs produced). A per-iteration summary is also written to `audit/iterations.jsonl`. Both files are committed for the ROCBA-2020 sample run in this repo.

## 📄 License

This project is released under the [MIT License](LICENSE).
