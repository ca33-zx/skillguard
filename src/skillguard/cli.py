"""Command-line interface for `skillguard`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import Severity
from .reporters import format_html, format_json, format_sarif, format_terminal
from .rules import RULE_CATALOG
from .scanner import scan_paths


def cmd_scan(args: argparse.Namespace) -> int:
    roots = args.paths or ["."]
    ignore_rules = {r.strip().upper() for r in (args.ignore_rule or []) if r.strip()}
    report = scan_paths(
        roots,
        scan_all=args.all_files,
        include_home=args.include_home,
        ignore_rules=ignore_rules,
    )

    if args.format == "json":
        output = format_json(report)
    elif args.format == "sarif":
        output = format_sarif(report)
    elif args.format == "html":
        output = format_html(report)
    else:
        use_color = (not args.no_color) and sys.stdout.isatty() and args.out is None
        output = format_terminal(report, color=use_color)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(
            f"Wrote {args.format.upper()} report ({len(report.findings)} findings, "
            f"Risk {report.risk_score}/100 Grade {report.grade}) to {out_path}"
        )
    else:
        print(output)

    if args.fail_on != "none":
        threshold = Severity(args.fail_on.upper())
        if report.exceeds_threshold(threshold):
            return 1
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    print(f"{'ID':7s} {'SEVERITY':9s} {'CWE':9s} {'CATEGORY':22s} TITLE")
    print("-" * 92)
    for rid in sorted(RULE_CATALOG):
        meta = RULE_CATALOG[rid]
        print(
            f"{meta.rule_id:7s} {meta.severity.value:9s} {meta.cwe:9s} "
            f"{meta.category:22s} {meta.title}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description=(
            "Zero-dependency static security auditor for AI coding agent Skills, "
            "MCP configs, CLAUDE.md/AGENTS.md instructions, and hooks."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan workspace or agent config paths for threats.")
    p_scan.add_argument(
        "paths",
        nargs="*",
        help="Directories or files to scan (defaults to current working directory).",
    )
    p_scan.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "html"],
        default="terminal",
        help="Output report format.",
    )
    p_scan.add_argument("--out", type=str, default=None, help="Write report to a file path.")
    p_scan.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="high",
        help="Exit with code 1 if any finding meets or exceeds this severity (default: high).",
    )
    p_scan.add_argument(
        "--ignore-rule",
        action="append",
        default=None,
        help="Repeatable rule ID to ignore (e.g. --ignore-rule SG040).",
    )
    p_scan.add_argument(
        "--all-files",
        action="store_true",
        help="Scan all markdown/script/json files, not just recognized agent surfaces.",
    )
    p_scan.add_argument(
        "--include-home",
        action="store_true",
        help="Also scan user-level agent directories (~/.claude, ~/.codex, ~/.cursor, etc.).",
    )
    p_scan.add_argument("--no-color", action="store_true", help="Disable ANSI color codes.")
    p_scan.set_defaults(func=cmd_scan)

    p_rules = sub.add_parser("rules", help="List all built-in detection rules (SG001-SG051).")
    p_rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
