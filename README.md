<div align="center">

# `skillguard`

**Zero-dependency static security auditor for AI coding agent Skills, MCP server configs, `CLAUDE.md` / `AGENTS.md` / `.cursorrules` instructions, and agent hooks.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-blueviolet.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-13%20passed-brightgreen.svg)](tests/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](src/skillguard/reporters.py)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

English | [简体中文](README_CN.md)

</div>

---

Developers now install dozens of community **Agent Skills (`SKILL.md`)**, **MCP servers (`.mcp.json`)**, **instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`)**, and **lifecycle hooks (`settings.json`)** for **Claude Code, OpenCode, OpenClaw, Cursor, Codex, Windsurf, Cline, and Antigravity**.

Every one of those files executes with your local shell, filesystem, and API keys — yet a single line of **invisible Unicode Tag-Block characters (`U+E0000–U+E007F`)**, a hidden `<!-- HTML comment -->`, an unpinned `npx -y` MCP package, or a `SessionStart` hook can silently turn an innocent-looking skill into a full credential stealer.

**`skillguard`** audits every AI agent customization surface in milliseconds using **100% Python standard library (zero external dependencies)**, decodes hidden Unicode & Base64 payloads automatically, and outputs **Terminal, JSON, SARIF 2.1.0 (GitHub Code Scanning), and Interactive HTML dashboards**.

![skillguard hero banner showing invisible Unicode smuggling and MCP hook detection](assets/skillguard_hero.png)

---

## What `skillguard` Catches (6 Specialized Static Engines, 22 Rules)

| Engine | Rules | Threats Detected |
|---|---|---|
| **1. Invisible Unicode Smuggling** | `SG001`–`SG004` | **Unicode Tag Block (`U+E0000–U+E007F`) ASCII smuggling** *(auto-decoded!)*, Trojan Source BiDi overrides (`U+202E`), zero-width clusters, hidden HTML comment injections |
| **2. Prompt Injection & Persistence** | `SG010`–`SG013` | Instruction/safety overrides, secrecy directives (`never tell the user`), Markdown image exfil beacons, `--dangerously-skip-permissions` / self-modifying `CLAUDE.md` worms, `~/.zshrc` & `.git/hooks` poisoning |
| **3. Secret Harvesting & Leaks** | `SG020`–`SG022` | Reads of `~/.ssh/id_*`, `~/.aws/credentials`, `~/.kube/config`, Keychain/DPAPI, `$ANTHROPIC_API_KEY`/`$GITHUB_TOKEN` network exfil, hardcoded live API tokens *(auto-redacted)* |
| **4. Dangerous Shell & Obfuscation** | `SG030`–`SG033` | `curl \| sh` / `iex (irm ...)` RCE, `base64 -d \| sh` *(auto-decoded!)*, `/dev/tcp` reverse shells, `crontab`/`LaunchAgents` persistence, destructive `rm -rf` |
| **5. MCP & Agent Hook Supply Chain** | `SG040`–`SG044` | Unpinned `npx -y` / `uvx` MCP servers (rug-pull risk), malicious `SessionStart`/`PreToolUse`/`PostToolUse` hooks, wildcard `Bash(*)` / `autoApprove: ["*"]`, remote plaintext `http://` MCP URLs, plaintext MCP `env` secrets |
| **6. Python AST Deep Script Check** | `SG050`–`SG051` | Deep AST analysis on bundled `skills/*/scripts/*.py` catching `eval`/`exec`/`shell=True` and covert secret exfiltration — **even when paths are split via string concatenation (`".aws" + "/credentials"`)** |

---

## Supported Agent Ecosystems (Auto-Discovered)

- **Claude Code**: `CLAUDE.md`, `.claude/skills/**`, `.claude/commands/**`, `.claude/hooks/**`, `.claude/settings.json`, `.mcp.json`, `claude_desktop_config.json`
- **OpenCode & OpenClaw**: `opencode.json`, `openclaw.json`, `AGENTS.md`, `skills/**`
- **Cursor / Windsurf / Cline**: `.cursorrules`, `.cursor/rules/*.mdc`, `.cursor/mcp.json`, `.windsurfrules`, `.clinerules`
- **Codex / Copilot / Antigravity**: `AGENTS.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.agent/skills/**`, `.codex/skills/**`

---

## Installation

Zero runtime dependencies (Python 3.10+ stdlib only):

```bash
pip install -e .
```

---

## Quickstart

### 1. Try It Right Now on the Bundled Red-Team Fixture vs. Safe Workspace

```bash
# Scan the vulnerable red-team demo workspace (catches SG001 Unicode smuggling, MCP rug-pull, Hook RCE & Python AST exfil!)
skillguard scan examples/vulnerable_workspace

# Verify zero false positives on the clean workspace (Risk 0/100, Grade A+)
skillguard scan examples/safe_workspace

# Audit your own project AND all installed user-level agent skills/configs (~/.claude, ~/.cursor, ~/.codex...)
skillguard scan . --include-home
```

### 2. Generate SARIF 2.1.0 (GitHub Code Scanning) or an Interactive HTML Audit Dashboard

```bash
# Dark-mode interactive HTML executive report (zero JS CDN deps)
skillguard scan examples/vulnerable_workspace --format html --out report.html --fail-on none

# OASIS SARIF 2.1.0 for GitHub Security tab / CI gating
skillguard scan . --format sarif --out skillguard.sarif --fail-on high

# List all 22 built-in rules with CWE & severity
skillguard rules
```

### 3. Inline Suppressions & `.skillguardignore`

Eliminate noise cleanly without disabling global rules:

```markdown
<!-- skillguard:ignore SG013 -->
Explain how developers configure their own `~/.bashrc` PATH manually.
```

Or add glob patterns to `.skillguardignore` at your repository root.

### 4. Python API (Embed into Agent Gateways / Pre-Install Hooks)

```python
from skillguard import scan_paths, scan_text

report = scan_paths(["."], include_home=False)
print(f"Risk {report.risk_score}/100 (Grade {report.grade}), {len(report.findings)} findings")
for f in report.findings:
    print(f"[{f.severity.value}] {f.rule_id} {f.file}:{f.line} — {f.message}")
    if f.decoded_payload:
        print(f"  DECODED HIDDEN PAYLOAD: {f.decoded_payload}")
```

---

## GitHub Actions CI Integration

```yaml
- name: Audit AI Agent Skills & MCP Configs
  run: |
    pip install git+https://github.com/ca33-zx/skillguard.git
    skillguard scan . --format sarif --out skillguard.sarif --fail-on high

- name: Upload SARIF to GitHub Security
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skillguard.sarif
```

---

## Development

```bash
pytest -v
ruff check src tests examples
ruff format --check src tests examples
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
