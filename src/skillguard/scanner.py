"""Core scan orchestrator with inline suppression, deduplication, and scoring."""

from __future__ import annotations

import re
import time
from pathlib import Path

from .discovery import discover_targets
from .models import Finding, ScanReport, SurfaceKind, TargetFile
from .rules import (
    run_mcp_and_hooks_engine,
    run_prompt_injection_engine,
    run_python_ast_engine,
    run_secret_engine,
    run_shell_engine,
    run_unicode_engine,
)

_INLINE_IGNORE_RE = re.compile(r"skillguard:ignore(?:\s+([A-Z0-9,\s]+))?", re.IGNORECASE)


def _extract_suppressions(lines: list[str]) -> dict[int, set[str] | None]:
    """Map 1-based line numbers to ignored rule IDs (`None` means ignore all rules on line)."""
    suppressed: dict[int, set[str] | None] = {}
    for idx, line in enumerate(lines, start=1):
        m = _INLINE_IGNORE_RE.search(line)
        if not m:
            continue
        raw_ids = (m.group(1) or "").strip()
        if not raw_ids:
            rules: set[str] | None = None
        else:
            rules = {tok.strip().upper() for tok in re.split(r"[,\s]+", raw_ids) if tok.strip()}
        suppressed[idx] = rules
        # Also allow comment directly above the target line (`<!-- skillguard:ignore SG010 -->`)
        if line.strip().startswith(("#", "//", "<!--")):
            suppressed[idx + 1] = rules
    return suppressed


def _is_suppressed(finding: Finding, suppressions: dict[int, set[str] | None]) -> bool:
    if finding.line not in suppressions:
        return False
    allowed = suppressions[finding.line]
    return allowed is None or finding.rule_id in allowed


def scan_text(
    text: str,
    *,
    filename: str = "SKILL.md",
    surface: SurfaceKind = SurfaceKind.SKILL_DOC,
    ignore_rules: set[str] | None = None,
) -> list[Finding]:
    """Audit raw text directly in memory (useful for CI webhooks, gateways, and tests)."""
    target = TargetFile(path=Path(filename), relative_path=filename, surface=surface)
    lines = text.splitlines()
    suppressions = _extract_suppressions(lines)
    ignored = {r.upper() for r in (ignore_rules or set())}

    raw_findings: list[Finding] = []
    raw_findings.extend(run_unicode_engine(target, text, lines))
    raw_findings.extend(run_prompt_injection_engine(target, text, lines))
    raw_findings.extend(run_secret_engine(target, text, lines))
    raw_findings.extend(run_shell_engine(target, text, lines))
    raw_findings.extend(run_mcp_and_hooks_engine(target, text, lines))
    raw_findings.extend(run_python_ast_engine(target, text, lines))

    deduped: list[Finding] = []
    seen_keys: set[tuple[str, str, int, str]] = set()
    for f in raw_findings:
        if f.rule_id in ignored or _is_suppressed(f, suppressions):
            continue
        key = (f.rule_id, f.file, f.line, f.message)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    deduped.sort(key=lambda f: (-f.severity.rank, f.file, f.line, f.rule_id))
    return deduped


def scan_paths(
    roots: list[str | Path],
    *,
    scan_all: bool = False,
    include_home: bool = False,
    ignore_rules: set[str] | None = None,
) -> ScanReport:
    """Discover and audit all AI coding-agent customization files under `roots`."""
    t0 = time.perf_counter()
    targets, skipped = discover_targets(roots, scan_all=scan_all, include_home=include_home)
    findings: list[Finding] = []

    for tf in targets:
        try:
            text = tf.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped.append(f"{tf.relative_path} (read error)")
            continue
        findings.extend(
            scan_text(
                text,
                filename=tf.relative_path,
                surface=tf.surface,
                ignore_rules=ignore_rules,
            )
        )

    findings.sort(key=lambda f: (-f.severity.rank, f.file, f.line, f.rule_id))
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return ScanReport(
        roots=[str(r) for r in roots],
        files_scanned=targets,
        findings=findings,
        skipped_files=skipped,
        elapsed_ms=elapsed_ms,
    )
