#!/usr/bin/env python3
"""
ARGUS — CLI entrypoint.

Usage:
  python find_evil.py investigate --case-dir /cases/case001 --memory memory.raw --disk disk.dd
  python find_evil.py mcp-server     # start MCP server for Claude Code
"""
import sys
import argparse
from pathlib import Path


def cmd_investigate(args: argparse.Namespace) -> None:
    case_dir = Path(args.case_dir).resolve()
    if not case_dir.exists():
        print(f"Error: case directory not found: {case_dir}", file=sys.stderr)
        sys.exit(1)

    artifacts: list[str] = []

    def _resolve(p: str) -> Path:
        """Resolve relative paths from CWD, then case_dir as fallback."""
        path = Path(p)
        if path.is_absolute():
            return path
        if path.exists():
            return path.resolve()
        return (case_dir / p).resolve()

    if args.memory:
        mem_path = _resolve(args.memory)
        if not mem_path.exists():
            print(f"Warning: memory image not found: {mem_path}", file=sys.stderr)
        else:
            artifacts.append(f"Memory image: {mem_path}")

    if args.disk:
        disk_path = _resolve(args.disk)
        if not disk_path.exists():
            print(f"Warning: disk image not found: {disk_path}", file=sys.stderr)
        else:
            artifacts.append(f"Disk image: {disk_path}")

    if args.prefetch:
        artifacts.append(f"Prefetch directory: {args.prefetch}")
    if args.ntuser:
        artifacts.append(f"NTUSER.DAT: {args.ntuser}")
    if args.software:
        artifacts.append(f"SOFTWARE hive: {args.software}")
    if args.system:
        artifacts.append(f"SYSTEM hive: {args.system}")

    case_description = f"""Case ID: {args.case_id or case_dir.name}
Available artifacts:
{chr(10).join(f'  - {a}' for a in artifacts)}

Additional context: {args.context or 'None provided.'}

Investigate all available artifacts. Start with memory (volatile first).
Corroborate every HIGH/CRITICAL finding with a second independent tool.
Produce a structured incident report when complete."""

    from agent.loop import run_agent
    result = run_agent(case_description, str(case_dir))
    sys.exit(0 if result.get("report") else 1)


def cmd_mcp_server(args: argparse.Namespace) -> None:
    from mcp_server.server import mcp
    mcp.run(transport="stdio")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="find-evil",
        description="Autonomous DFIR agent on SIFT Workstation",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("investigate", help="Run autonomous investigation on case data")
    inv.add_argument("--case-dir", required=True, help="Directory containing case artifacts")
    inv.add_argument("--case-id", help="Case identifier (defaults to directory name)")
    inv.add_argument("--memory", help="Memory image filename (relative to case-dir or absolute)")
    inv.add_argument("--disk", help="Disk image filename (relative to case-dir or absolute)")
    inv.add_argument("--prefetch", help="Path to Windows\\Prefetch directory")
    inv.add_argument("--ntuser", help="Path to NTUSER.DAT hive")
    inv.add_argument("--software", help="Path to SOFTWARE hive")
    inv.add_argument("--system", help="Path to SYSTEM hive")
    inv.add_argument("--context", help="Additional case context or notes")
    inv.add_argument("--max-iterations", type=int, default=12, help="Max agent iterations (default: 12)")
    inv.set_defaults(func=cmd_investigate)

    srv = sub.add_parser("mcp-server", help="Start MCP server for Claude Code integration")
    srv.set_defaults(func=cmd_mcp_server)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
