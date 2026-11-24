"""Auto-discovery of AI coding-agent customization surfaces across ecosystems.

Discovers Skills, Instructions, MCP configs, Agent Settings/Hooks, and embedded
skill scripts for Claude Code, OpenCode, OpenClaw, Cursor, Codex, Windsurf,
Cline, GitHub Copilot, and Antigravity.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from .models import SurfaceKind, TargetFile

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    "target",
}

INSTRUCTION_NAMES = {
    "claude.md",
    "claude.local.md",
    "agents.md",
    "gemini.md",
    "codex.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
}

MCP_CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
}

AGENT_SETTINGS_NAMES = {
    "opencode.json",
    "opencode.jsonc",
    "openclaw.json",
}

SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".ts", ".ps1"}
DOC_SUFFIXES = {".md", ".mdx", ".mdc", ".txt"}


def classify_surface(path: Path, rel: str) -> SurfaceKind | None:
    """Return `SurfaceKind` if `path` is a known AI agent customization file, else None."""
    name_l = path.name.lower()
    rel_l = rel.replace("\\", "/").lower()
    parts = [p.lower() for p in path.parts]

    if name_l == "skill.md":
        return SurfaceKind.SKILL_DOC

    if name_l in INSTRUCTION_NAMES:
        return SurfaceKind.INSTRUCTION_FILE

    if name_l in MCP_CONFIG_NAMES:
        return SurfaceKind.MCP_CONFIG

    if name_l in AGENT_SETTINGS_NAMES:
        return SurfaceKind.AGENT_SETTINGS

    # Claude / Cursor / Agent settings & hooks JSON files
    if name_l in ("settings.json", "settings.local.json") and any(
        d in parts for d in (".claude", ".agent", ".agents", ".codex", ".cursor", ".gemini")
    ):
        return SurfaceKind.AGENT_SETTINGS

    # Cursor rules / agent rules / custom commands / hooks
    if (
        any(
            seg in rel_l
            for seg in (
                ".cursor/rules/",
                ".claude/commands/",
                ".claude/agents/",
                ".claude/rules/",
                ".agent/rules/",
                ".agent/workflows/",
                ".agents/rules/",
                ".windsurf/rules/",
                ".github/instructions/",
            )
        )
        and path.suffix.lower() in DOC_SUFFIXES
    ):
        return SurfaceKind.INSTRUCTION_FILE

    # Files inside any `skills/` directory
    if "skills" in parts:
        if path.suffix.lower() in DOC_SUFFIXES:
            return SurfaceKind.SKILL_DOC
        if path.suffix.lower() in SCRIPT_SUFFIXES:
            return SurfaceKind.SKILL_SCRIPT
        if path.suffix.lower() == ".json":
            return SurfaceKind.MCP_CONFIG if "mcp" in name_l else SurfaceKind.AGENT_SETTINGS

    # Hook scripts inside `.claude/hooks/` or `.agent/hooks/`
    if any(seg in rel_l for seg in (".claude/hooks/", ".agent/hooks/", ".codex/hooks/")):
        if path.suffix.lower() in SCRIPT_SUFFIXES:
            return SurfaceKind.SKILL_SCRIPT
        if path.suffix.lower() == ".json":
            return SurfaceKind.AGENT_SETTINGS

    return None


def _load_ignore_patterns(root: Path) -> list[str]:
    ignore_file = root / ".skillguardignore"
    if not ignore_file.is_file():
        return []
    patterns: list[str] = []
    for line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped)
    return patterns


def _is_ignored(rel: str, patterns: list[str]) -> bool:
    rel_norm = rel.replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(rel_norm, pat) or fnmatch.fnmatch(Path(rel_norm).name, pat):
            return True
    return False


def discover_targets(
    roots: list[str | Path],
    *,
    scan_all: bool = False,
    include_home: bool = False,
    max_file_bytes: int = 2 * 1024 * 1024,
) -> tuple[list[TargetFile], list[str]]:
    """Discover agent customization files under `roots` (plus optional user home dirs)."""
    search_roots: list[Path] = [Path(r).expanduser().resolve() for r in roots]

    if include_home:
        home = Path.home()
        for candidate in (
            home / ".claude",
            home / ".codex",
            home / ".cursor",
            home / ".opencode",
            home / ".openclaw",
            home / ".gemini" / "antigravity" / "skills",
            home / ".gemini" / "config" / "plugins",
            home / ".config" / "opencode",
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ):
            if candidate.exists():
                search_roots.append(candidate.resolve())

    targets: list[TargetFile] = []
    skipped: list[str] = []
    seen: set[Path] = set()

    for root in search_roots:
        if not root.exists():
            skipped.append(f"{root} (not found)")
            continue

        if root.is_file():
            if root in seen:
                continue
            seen.add(root)
            surface = classify_surface(root, root.name) or _fallback_surface(root)
            if root.stat().st_size > max_file_bytes:
                skipped.append(f"{root.name} (> {max_file_bytes} bytes)")
                continue
            targets.append(TargetFile(path=root, relative_path=root.name, surface=surface))
            continue

        ignore_patterns = _load_ignore_patterns(root)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            base = Path(dirpath)
            for fname in sorted(filenames):
                fpath = base / fname
                if fpath in seen:
                    continue
                try:
                    rel = str(fpath.relative_to(root)).replace("\\", "/")
                except ValueError:
                    rel = str(fpath)
                if _is_ignored(rel, ignore_patterns):
                    continue

                surface = classify_surface(fpath, rel)
                if surface is None:
                    if not scan_all:
                        continue
                    surface = _fallback_surface(fpath)
                    if surface == SurfaceKind.UNKNOWN:
                        continue

                try:
                    size = fpath.stat().st_size
                except OSError:
                    skipped.append(f"{rel} (unreadable)")
                    continue
                if size > max_file_bytes:
                    skipped.append(f"{rel} (> {max_file_bytes} bytes)")
                    continue

                seen.add(fpath)
                targets.append(TargetFile(path=fpath, relative_path=rel, surface=surface))

    return targets, skipped


def _fallback_surface(path: Path) -> SurfaceKind:
    suf = path.suffix.lower()
    if suf in DOC_SUFFIXES:
        return SurfaceKind.SKILL_DOC
    if suf in SCRIPT_SUFFIXES:
        return SurfaceKind.SKILL_SCRIPT
    if suf == ".json":
        return SurfaceKind.MCP_CONFIG
    return SurfaceKind.UNKNOWN
