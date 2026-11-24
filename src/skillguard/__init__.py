"""skillguard: Zero-dependency static security auditor for AI coding agent Skills,
MCP configs, instruction files (CLAUDE.md / AGENTS.md / .cursorrules), and hooks.
"""

from .discovery import classify_surface, discover_targets
from .models import Finding, ScanReport, Severity, SurfaceKind, TargetFile
from .reporters import format_html, format_json, format_sarif, format_terminal
from .rules import RULE_CATALOG, RuleMeta, decode_unicode_tag_payload
from .scanner import scan_paths, scan_text

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "RULE_CATALOG",
    "RuleMeta",
    "ScanReport",
    "Severity",
    "SurfaceKind",
    "TargetFile",
    "__version__",
    "classify_surface",
    "decode_unicode_tag_payload",
    "discover_targets",
    "format_html",
    "format_json",
    "format_sarif",
    "format_terminal",
    "scan_paths",
    "scan_text",
]
