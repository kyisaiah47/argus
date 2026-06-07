#!/usr/bin/env bash
set -euo pipefail

echo "╔══════════════════════════════════════════╗"
echo "║  Find Evil — SIFT Workstation Installer  ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 || ("$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 10) ]]; then
    echo "ERROR: Python 3.10+ required (found $PYTHON_VERSION)"
    exit 1
fi
echo "✓ Python $PYTHON_VERSION"

# Check SIFT tools
MISSING_TOOLS=()
for tool in vol log2timeline.py psort.py regripper fls; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    else
        echo "✓ $tool found"
    fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo ""
    echo "WARNING: Missing SIFT tools: ${MISSING_TOOLS[*]}"
    echo "These are required on the SIFT Workstation."
    echo "Download SIFT at: https://www.sans.org/tools/sift-workstation/"
    echo "Install Protocol SIFT first, then re-run this installer."
    echo ""
    echo "Continuing installation (tools may not be available in this environment)..."
fi

# Check ANTHROPIC_API_KEY
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo ""
    echo "WARNING: ANTHROPIC_API_KEY not set."
    echo "The autonomous agent requires an Anthropic API key."
    echo "Set it with: export ANTHROPIC_API_KEY=sk-ant-..."
fi

# Create virtualenv
echo ""
echo "Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "✓ Dependencies installed"

# Create audit directory
mkdir -p audit/reports
echo "✓ Audit directory ready"

# Set up Claude Code MCP config
CLAUDE_MCP_CONFIG='{
  "mcpServers": {
    "find-evil": {
      "command": "'$(pwd)'/.venv/bin/python",
      "args": ["'$(pwd)'/find_evil.py", "mcp-server"],
      "env": {
        "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"
      }
    }
  }
}'

echo ""
echo "To use with Claude Code, add this to your .claude/settings.json:"
echo ""
echo "$CLAUDE_MCP_CONFIG"
echo ""
echo "Or run:  claude mcp add find-evil -- $(pwd)/.venv/bin/python $(pwd)/find_evil.py mcp-server"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Installation complete."
echo ""
echo "Usage:"
echo "  source .venv/bin/activate"
echo "  python find_evil.py investigate \\"
echo "    --case-dir /cases/case001 \\"
echo "    --memory memory.raw \\"
echo "    --disk disk.dd"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
