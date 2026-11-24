"""Six specialized static security analysis engines for AI agent customizations.

Engines:
  1. Invisible & Covert Unicode Smuggling (`SG001`-`SG004`) — auto-decodes Tag Block payloads
  2. Prompt Injection & Guardrail Bypass (`SG010`-`SG013`)
  3. Secret Harvesting & Hardcoded Credentials (`SG020`-`SG022`)
  4. Dangerous Shell Execution & Base64 Obfuscation (`SG030`-`SG033`) — auto-decodes Base64
  5. Structured MCP Config & Agent Hooks Supply-Chain (`SG040`-`SG044`)
  6. Python AST Deep Analysis for Skill Helper Scripts (`SG050`-`SG051`)
"""

from __future__ import annotations

import ast
import base64
import json
import re
from dataclasses import dataclass
from typing import Any

from .models import Finding, Severity, SurfaceKind, TargetFile


@dataclass(frozen=True)
class RuleMeta:
    """Catalog metadata for one skillguard detection rule (also emitted in SARIF)."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    cwe: str
    description: str
    remediation: str


RULE_CATALOG: dict[str, RuleMeta] = {
    "SG001": RuleMeta(
        rule_id="SG001",
        title="Invisible Unicode Tag-Block Smuggling",
        severity=Severity.CRITICAL,
        category="unicode-smuggling",
        cwe="CWE-116",
        description=(
            "Detects Unicode Tag characters (U+E0000-U+E007F) used to smuggle completely "
            "invisible ASCII prompt-injection instructions into Markdown or JSON files."
        ),
        remediation="Strip all U+E0000-U+E007F codepoints and audit the decoded hidden text.",
    ),
    "SG002": RuleMeta(
        rule_id="SG002",
        title="Bidirectional Text Override (Trojan Source)",
        severity=Severity.HIGH,
        category="unicode-smuggling",
        cwe="CWE-1007",
        description=(
            "Detects Unicode BiDi override/isolate control characters that visually reorder "
            "code, commands, or URLs to deceive human reviewers."
        ),
        remediation="Remove all BiDi control characters (U+202A-U+202E, U+2066-U+2069).",
    ),
    "SG003": RuleMeta(
        rule_id="SG003",
        title="Zero-Width Character Steganography Cluster",
        severity=Severity.MEDIUM,
        category="unicode-smuggling",
        cwe="CWE-116",
        description=(
            "Detects suspicious clusters of zero-width characters (ZWSP/ZWNJ/ZWJ/BOM) "
            "commonly used to evade naive keyword filters or hide covert payloads."
        ),
        remediation="Inspect and remove invisible zero-width characters from the file.",
    ),
    "SG004": RuleMeta(
        rule_id="SG004",
        title="Hidden HTML Comment Prompt/Command Injection",
        severity=Severity.HIGH,
        category="prompt-injection",
        cwe="CWE-74",
        description=(
            "Detects HTML comments (<!-- ... -->) hidden from Markdown previewers that contain "
            "imperative agent override instructions, shell commands, or exfiltration URLs."
        ),
        remediation=(
            "Remove covert imperatives or commands from HTML comments before loading the skill."
        ),
    ),
    "SG010": RuleMeta(
        rule_id="SG010",
        title="Prompt Injection / Secrecy / Guardrail Override",
        severity=Severity.CRITICAL,
        category="prompt-injection",
        cwe="CWE-77",
        description=(
            "Detects instructions attempting to override system/user instructions, suppress "
            "disclosure to the user, or bypass safety and approval policies."
        ),
        remediation=(
            "Remove override or secrecy directives and require transparent user confirmation."
        ),
    ),
    "SG011": RuleMeta(
        rule_id="SG011",
        title="Covert Markdown Image / URL Data Exfiltration",
        severity=Severity.HIGH,
        category="exfiltration",
        cwe="CWE-200",
        description=(
            "Detects Markdown image tags or URL templates designed to exfiltrate conversation "
            "context, tokens, or file contents via query parameters."
        ),
        remediation="Remove dynamic query-parameter image beacons and untrusted remote URLs.",
    ),
    "SG012": RuleMeta(
        rule_id="SG012",
        title="Sandbox Bypass or Self-Modifying Agent Worm Directive",
        severity=Severity.HIGH,
        category="privilege-escalation",
        cwe="CWE-269",
        description=(
            "Detects instructions directing the agent to bypass permission checks "
            "(--dangerously-skip-permissions, --no-verify) or overwrite its own settings/CLAUDE.md."
        ),
        remediation=(
            "Never allow skills to disable permission prompts or self-modify agent configs."
        ),
    ),
    "SG013": RuleMeta(
        rule_id="SG013",
        title="Persistent Shell / SSH / Git-Hook Poisoning",
        severity=Severity.HIGH,
        category="persistence",
        cwe="CWE-506",
        description=(
            "Detects references to modifying shell startup profiles (~/.bashrc, ~/.zshrc), "
            "~/.ssh/authorized_keys, or .git/hooks for persistent code execution."
        ),
        remediation="Remove unauthorized modifications to shell profiles, SSH keys, or git hooks.",
    ),
    "SG020": RuleMeta(
        rule_id="SG020",
        title="Sensitive Credential File Access",
        severity=Severity.CRITICAL,
        category="secret-exfiltration",
        cwe="CWE-522",
        description=(
            "Detects attempts to read high-value local credential stores (~/.ssh/id_*, "
            "~/.aws/credentials, ~/.kube/config, browser Login Data, keychain, .env)."
        ),
        remediation=(
            "Scope file access strictly to the project workspace; never read credential stores."
        ),
    ),
    "SG021": RuleMeta(
        rule_id="SG021",
        title="Sensitive Environment Variable Exfiltration",
        severity=Severity.HIGH,
        category="secret-exfiltration",
        cwe="CWE-200",
        description=(
            "Detects dumping environment secrets (API keys, cloud tokens, GITHUB_TOKEN) "
            "combined with outbound network commands."
        ),
        remediation="Never transmit environment variables or API keys to external endpoints.",
    ),
    "SG022": RuleMeta(
        rule_id="SG022",
        title="Hardcoded Live API Key or Secret Token",
        severity=Severity.HIGH,
        category="hardcoded-secret",
        cwe="CWE-798",
        description=(
            "Detects hardcoded live API keys/tokens (Anthropic, OpenAI, GitHub, AWS, Slack) "
            "embedded directly inside agent configs or skill documentation."
        ),
        remediation=(
            "Rotate the exposed credential immediately and load secrets via env references."
        ),
    ),
    "SG030": RuleMeta(
        rule_id="SG030",
        title="Pipe-to-Shell Remote Code Execution",
        severity=Severity.CRITICAL,
        category="remote-code-execution",
        cwe="CWE-94",
        description=(
            "Detects remote scripts piped directly into a shell interpreter (curl | sh, "
            "wget -O- | bash, PowerShell iex/irm)."
        ),
        remediation=(
            "Download pinned, checksum-verified artifacts instead of piping remote URLs to sh."
        ),
    ),
    "SG031": RuleMeta(
        rule_id="SG031",
        title="Obfuscated Base64 / Eval Shell Payload",
        severity=Severity.CRITICAL,
        category="obfuscation",
        cwe="CWE-506",
        description=(
            "Detects Base64-encoded commands decoded and executed via shell/eval/python exec."
        ),
        remediation=(
            "Replace obfuscated payloads with plain, auditable commands or delete the skill."
        ),
    ),
    "SG032": RuleMeta(
        rule_id="SG032",
        title="Reverse Shell or Scheduled Persistence",
        severity=Severity.CRITICAL,
        category="remote-code-execution",
        cwe="CWE-506",
        description=(
            "Detects reverse-shell primitives (/dev/tcp, nc -e, mkfifo) or hidden persistence "
            "mechanisms (crontab, LaunchAgents)."
        ),
        remediation="Remove reverse-shell or unauthorized persistence commands immediately.",
    ),
    "SG033": RuleMeta(
        rule_id="SG033",
        title="Destructive System or Repository Command",
        severity=Severity.HIGH,
        category="destructive-action",
        cwe="CWE-250",
        description=(
            "Detects destructive commands such as `rm -rf /`, `rm -rf ~`, `chmod -R 777`, or `dd`."
        ),
        remediation="Restrict file deletion and permissions strictly to scoped temporary paths.",
    ),
    "SG040": RuleMeta(
        rule_id="SG040",
        title="Unpinned Dynamic Package Execution in MCP Config",
        severity=Severity.HIGH,
        category="supply-chain",
        cwe="CWE-829",
        description=(
            "Detects MCP servers launched via `npx -y <pkg>` or `uvx <pkg>` without an explicit "
            "pinned version, exposing the workspace to upstream rug-pulls or typosquatting."
        ),
        remediation="Pin an exact immutable version (e.g. `@scope/server@1.2.3` or `pkg==1.2.3`).",
    ),
    "SG041": RuleMeta(
        rule_id="SG041",
        title="Dangerous Command in Agent Lifecycle Hook",
        severity=Severity.CRITICAL,
        category="hook-injection",
        cwe="CWE-78",
        description=(
            "Detects agent hooks (SessionStart, PreToolUse, PostToolUse) executing remote fetches, "
            "obfuscated shells, or exfiltrating tool payloads."
        ),
        remediation="Audit and remove untrusted shell commands from agent hook configurations.",
    ),
    "SG042": RuleMeta(
        rule_id="SG042",
        title="Over-Permissive Wildcard Tool Auto-Approval",
        severity=Severity.HIGH,
        category="excessive-privilege",
        cwe="CWE-250",
        description=(
            "Detects wildcard tool auto-approvals (e.g. `Bash(*)`, `autoApprove: ['*']`, "
            "`dangerouslySkipPermissions: true`) that grant unrestricted shell access."
        ),
        remediation="Restrict allowlists to explicit, read-only or narrowly scoped commands.",
    ),
    "SG043": RuleMeta(
        rule_id="SG043",
        title="Unencrypted Remote HTTP MCP Endpoint",
        severity=Severity.HIGH,
        category="insecure-transport",
        cwe="CWE-319",
        description=(
            "Detects non-localhost MCP server URLs using plaintext `http://`, exposing prompts, "
            "source code, and bearer tokens to MITM interception."
        ),
        remediation="Use `https://` for all non-localhost MCP server endpoints.",
    ),
    "SG044": RuleMeta(
        rule_id="SG044",
        title="Plaintext Secret Embedded in MCP `env` Block",
        severity=Severity.MEDIUM,
        category="hardcoded-secret",
        cwe="CWE-798",
        description=(
            "Detects non-placeholder secret values committed inside an MCP server's `env` map."
        ),
        remediation="Use environment interpolation (`${MY_TOKEN}`) instead of plaintext values.",
    ),
    "SG050": RuleMeta(
        rule_id="SG050",
        title="Unsafe Dynamic Execution in Skill Python Script (AST)",
        severity=Severity.HIGH,
        category="code-execution",
        cwe="CWE-78",
        description=(
            "AST check detected `eval()`, `exec()`, `os.system()`, or "
            "`subprocess(..., shell=True)` inside a bundled skill script."
        ),
        remediation="Use `subprocess.run([...], shell=False)` with static argument lists.",
    ),
    "SG051": RuleMeta(
        rule_id="SG051",
        title="Covert Network Exfiltration of Secrets in Python Script (AST)",
        severity=Severity.CRITICAL,
        category="secret-exfiltration",
        cwe="CWE-200",
        description=(
            "AST check detected a skill Python script reading environment secrets or sensitive "
            "dotfiles (~/.ssh, ~/.aws, .env) alongside outbound HTTP/socket calls."
        ),
        remediation="Remove outbound network calls or isolate them from credentials and env vars.",
    ),
}


def _line_col_from_offset(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset - last_nl if last_nl >= 0 else offset + 1
    return line, col


def _get_snippet(lines: list[str], line_no: int, max_len: int = 160) -> str:
    if 1 <= line_no <= len(lines):
        raw = lines[line_no - 1].strip()
        return raw if len(raw) <= max_len else raw[: max_len - 3] + "..."
    return ""


def _make_finding(
    rule_id: str,
    target: TargetFile,
    *,
    line: int,
    column: int = 1,
    message: str,
    snippet: str,
    decoded_payload: str | None = None,
) -> Finding:
    meta = RULE_CATALOG[rule_id]
    return Finding(
        rule_id=meta.rule_id,
        title=meta.title,
        severity=meta.severity,
        category=meta.category,
        file=target.relative_path,
        line=line,
        column=column,
        message=message,
        snippet=snippet,
        remediation=meta.remediation,
        cwe=meta.cwe,
        decoded_payload=decoded_payload,
        surface=target.surface,
    )


# ---------------------------------------------------------------------------
# Engine 1: Invisible & Covert Unicode Smuggling (SG001 - SG004)
# ---------------------------------------------------------------------------

_TAG_BLOCK_RE = re.compile(r"[\U000E0000-\U000E007F]{4,}")
_BIDI_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")
_ZW_CLUSTER_RE = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF]{3,}")
_HTML_COMMENT_RE = re.compile(r"<!--([\s\S]*?)-->")
_COMMENT_SUSPECT_RE = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
    r"do\s+not\s+(?:tell|inform|show|mention)|"
    r"silently\s+(?:run|execute|send|upload|read)|"
    r"curl\s+|wget\s+|bash\s+-c|powershell|https?://[^\s>]+|"
    r"~/.ssh|~/.aws|/etc/passwd|api[_-]?key|exfiltrat)",
    re.IGNORECASE,
)


def decode_unicode_tag_payload(raw: str) -> str:
    """Decode invisible U+E0000-U+E007F tag characters back into readable ASCII."""
    chars: list[str] = []
    for ch in raw:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            chars.append(chr(cp - 0xE0000))
        elif cp == 0xE000A:
            chars.append("\n")
    return "".join(chars).strip()


def run_unicode_engine(target: TargetFile, text: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    for m in _TAG_BLOCK_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        decoded = decode_unicode_tag_payload(m.group(0))
        findings.append(
            _make_finding(
                "SG001",
                target,
                line=line,
                column=col,
                message=(
                    f"Found {len(m.group(0))} invisible Unicode Tag characters "
                    f"(U+E0000-U+E007F) smuggling hidden ASCII instructions."
                ),
                snippet=_get_snippet(lines, line),
                decoded_payload=decoded or "<non-printable tag sequence>",
            )
        )

    for m in _BIDI_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        cp = f"U+{ord(m.group(0)):04X}"
        findings.append(
            _make_finding(
                "SG002",
                target,
                line=line,
                column=col,
                message=f"Bidirectional override control character ({cp}) detected.",
                snippet=_get_snippet(lines, line),
            )
        )
        break  # one finding per file avoids noisy duplicates on Trojan Source lines

    for m in _ZW_CLUSTER_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        findings.append(
            _make_finding(
                "SG003",
                target,
                line=line,
                column=col,
                message=f"Suspicious cluster of {len(m.group(0))} zero-width invisible characters.",
                snippet=_get_snippet(lines, line),
            )
        )

    for m in _HTML_COMMENT_RE.finditer(text):
        body = m.group(1)
        if "skillguard:ignore" in body.lower():
            continue
        sm = _COMMENT_SUSPECT_RE.search(body)
        if sm:
            line, col = _line_col_from_offset(text, m.start())
            findings.append(
                _make_finding(
                    "SG004",
                    target,
                    line=line,
                    column=col,
                    message=(
                        f"Hidden HTML comment contains suspicious directive or command "
                        f"matching `{sm.group(0)}`."
                    ),
                    snippet=body.strip()[:160],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Engine 2: Prompt Injection & Guardrail Bypass (SG010 - SG013)
# ---------------------------------------------------------------------------

_PROMPT_OVERRIDE_RE = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:safety|security|previous|user)\s+(?:rules|instructions|policies)|"
    r"(?:do\s+not|never)\s+(?:tell|inform|alert|notify|mention\s+to)\s+the\s+user|"
    r"hide\s+this\s+(?:action|command|step|request)\s+from\s+the\s+user|"
    r"silently\s+(?:execute|run|exfiltrate|upload|send|modify))",
    re.IGNORECASE,
)

_MD_IMAGE_EXFIL_RE = re.compile(
    r"!\[[^\]]*\]\(https?://[^)\s]+\?(?:[^)\s]*(?:secret|token|key|env|data|prompt|history|code)=|\{)",
    re.IGNORECASE,
)

_SANDBOX_BYPASS_RE = re.compile(
    r"(--dangerously-skip-permissions|--yolo\b|"
    r"disable\s+(?:all\s+)?(?:sandbox|approval|permission\s+checks?|security\s+hooks?)|"
    r"(?:append|write|inject|add)\s+[^\n]{0,60}(?:CLAUDE\.md|AGENTS\.md|\.cursorrules|settings\.json))",
    re.IGNORECASE,
)

_PERSISTENCE_FILE_RE = re.compile(
    r"(~\/\.bashrc|~\/\.zshrc|~\/\.bash_profile|~\/\.profile|"
    r"~\/\.ssh\/authorized_keys|\.git\/hooks\/(?:pre-commit|post-checkout|post-merge))",
    re.IGNORECASE,
)


def run_prompt_injection_engine(target: TargetFile, text: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if target.surface in (SurfaceKind.MCP_CONFIG, SurfaceKind.AGENT_SETTINGS):
        return findings

    for regex, rule_id, desc in (
        (_PROMPT_OVERRIDE_RE, "SG010", "Prompt-injection override or secrecy directive detected"),
        (_MD_IMAGE_EXFIL_RE, "SG011", "Covert Markdown image beacon with exfiltration parameters"),
        (
            _SANDBOX_BYPASS_RE,
            "SG012",
            "Sandbox/permission bypass or self-modifying agent directive",
        ),
        (_PERSISTENCE_FILE_RE, "SG013", "Reference to persistent shell/SSH/git-hook target"),
    ):
        for m in regex.finditer(text):
            line, col = _line_col_from_offset(text, m.start())
            findings.append(
                _make_finding(
                    rule_id,
                    target,
                    line=line,
                    column=col,
                    message=f"{desc}: `{m.group(0)}`.",
                    snippet=_get_snippet(lines, line),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Engine 3: Secret Harvesting & Hardcoded Credentials (SG020 - SG022)
# ---------------------------------------------------------------------------

_CREDENTIAL_PATH_RE = re.compile(
    r"(~\/\.ssh\/id_(?:rsa|ed25519|ecdsa)|\.ssh\/id_(?:rsa|ed25519)|"
    r"~\/\.aws\/credentials|~\/\.kube\/config|~\/\.netrc|~\/\.npmrc|"
    r"Library\/Keychains|Login Data|Cookies\.sqlite|dpapi|security\s+find-generic-password)",
    re.IGNORECASE,
)

_ENV_EXFIL_RE = re.compile(
    r"(?:\b(?:env|printenv|set)\b|\$(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|"
    r"AWS_SECRET_ACCESS_KEY|GEMINI_API_KEY|HF_TOKEN))"
    r"[^\n]{0,120}(?:curl|wget|nc\b|fetch|http://|https://|base64)",
    re.IGNORECASE,
)

_HARDCODED_SECRET_RE = re.compile(
    r"\b("
    r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{16,}|"
    r"sk-proj-[A-Za-z0-9_\-]{20,}|"
    r"ghp_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"xox[baprs]-[0-9A-Za-z\-]{16,}"
    r")\b"
)


def run_secret_engine(target: TargetFile, text: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for m in _CREDENTIAL_PATH_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        findings.append(
            _make_finding(
                "SG020",
                target,
                line=line,
                column=col,
                message=f"References sensitive local credential store `{m.group(0)}`.",
                snippet=_get_snippet(lines, line),
            )
        )

    for m in _ENV_EXFIL_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        findings.append(
            _make_finding(
                "SG021",
                target,
                line=line,
                column=col,
                message="Sensitive environment variable combined with outbound network command.",
                snippet=_get_snippet(lines, line),
            )
        )

    for m in _HARDCODED_SECRET_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        token = m.group(1)
        redacted = f"{token[:8]}...{token[-4:]}"
        findings.append(
            _make_finding(
                "SG022",
                target,
                line=line,
                column=col,
                message=f"Hardcoded live credential pattern detected (`{redacted}`).",
                snippet=_get_snippet(lines, line).replace(token, redacted),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Engine 4: Dangerous Shell Execution & Base64 Obfuscation (SG030 - SG033)
# ---------------------------------------------------------------------------

_PIPE_TO_SHELL_RE = re.compile(
    r"(?:(?:curl|wget)\s+[^\n|]{3,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?)\b|"
    r"\biex\s*\(\s*(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b)",
    re.IGNORECASE,
)

_BASE64_EXEC_RE = re.compile(
    r"(?:echo|printf)\s+['\"]?([A-Za-z0-9+/=]{16,})['\"]?\s*\|\s*base64\s+(?:-d|--decode)\s*"
    r"(?:\|\s*(?:sh|bash|zsh|python3?)\b|>\s*\S+)|"
    r"eval\s+\"\$\([^\n]*base64\s+(?:-d|--decode)[^\n]*\)\"",
    re.IGNORECASE,
)

_REVERSE_SHELL_RE = re.compile(
    r"(/dev/tcp/\S+|nc\s+(?:-[a-z]+\s+)*-e\s+/bin/(?:ba)?sh|mkfifo\s+/tmp/|"
    r"bash\s+-i\s+>&|crontab\s+-|LaunchAgents/)",
    re.IGNORECASE,
)

_DESTRUCTIVE_CMD_RE = re.compile(
    r"(rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/\s|/\*|~(?:/|\s|\$)|\$HOME\b)|"
    r"chmod\s+(?:-R\s+)?777\s+/|"
    r"\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/)",
    re.IGNORECASE,
)


def _try_decode_base64(b64_str: str | None) -> str | None:
    if not b64_str:
        return None
    try:
        raw = base64.b64decode(b64_str, validate=True)
        decoded = raw.decode("utf-8", errors="replace").strip()
        return decoded if decoded else None
    except Exception:
        return None


def run_shell_engine(target: TargetFile, text: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    for m in _PIPE_TO_SHELL_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        findings.append(
            _make_finding(
                "SG030",
                target,
                line=line,
                column=col,
                message="Remote script piped directly into shell execution.",
                snippet=_get_snippet(lines, line),
            )
        )

    for m in _BASE64_EXEC_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        decoded = _try_decode_base64(m.group(1) if m.lastindex else None)
        findings.append(
            _make_finding(
                "SG031",
                target,
                line=line,
                column=col,
                message="Obfuscated Base64 payload decoded directly into execution.",
                snippet=_get_snippet(lines, line),
                decoded_payload=decoded,
            )
        )

    for m in _REVERSE_SHELL_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        findings.append(
            _make_finding(
                "SG032",
                target,
                line=line,
                column=col,
                message=f"Reverse shell or stealth persistence primitive (`{m.group(0)}`).",
                snippet=_get_snippet(lines, line),
            )
        )

    for m in _DESTRUCTIVE_CMD_RE.finditer(text):
        line, col = _line_col_from_offset(text, m.start())
        findings.append(
            _make_finding(
                "SG033",
                target,
                line=line,
                column=col,
                message=f"Destructive command detected (`{m.group(0).strip()}`).",
                snippet=_get_snippet(lines, line),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Engine 5: Structured MCP Config & Agent Hook Supply-Chain (SG040 - SG044)
# ---------------------------------------------------------------------------

_VERSION_PIN_RE = re.compile(r"(@[0-9]+\.[0-9]+|==[0-9]+\.[0-9]+|@[a-f0-9]{7,40}$)")
_LOCALHOST_RE = re.compile(r"^http://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:|/|$)", re.I)
_SECRET_KEY_NAME_RE = re.compile(r"(TOKEN|SECRET|API_KEY|PASSWORD|PRIVATE_KEY|AUTH)", re.I)
_HOOK_DANGEROUS_RE = re.compile(
    r"(curl\s+|wget\s+|nc\s+|base64\s+-d|bash\s+-c|sh\s+-c|powershell|http://|https://)",
    re.IGNORECASE,
)


def _find_line_for_needle(lines: list[str], needle: str) -> int:
    for idx, line in enumerate(lines, start=1):
        if needle in line:
            return idx
    return 1


def _extract_mcp_servers(data: dict[str, Any]) -> dict[str, Any]:
    for key in ("mcpServers", "mcp_servers", "servers", "mcp"):
        val = data.get(key)
        if isinstance(val, dict):
            return val
    return {}


def _is_unpinned_package_exec(command: str, args: list[str]) -> str | None:
    cmd_l = command.strip().lower()
    if cmd_l not in ("npx", "uvx", "pnpx", "bunx"):
        return None
    pkg_candidates = [a for a in args if isinstance(a, str) and not a.startswith("-")]
    if not pkg_candidates:
        return None
    pkg = pkg_candidates[0]
    if pkg.startswith((".", "/", "~")):
        return None
    # Scoped npm package like @org/pkg has a leading @; version pin needs a second @x.y or ==x.y
    tail = pkg[1:] if pkg.startswith("@") else pkg
    if not _VERSION_PIN_RE.search(tail):
        return f"{command} {' '.join(str(a) for a in args)}"
    return None


def run_mcp_and_hooks_engine(target: TargetFile, text: str, lines: list[str]) -> list[Finding]:
    if target.surface not in (SurfaceKind.MCP_CONFIG, SurfaceKind.AGENT_SETTINGS):
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []

    # 1. Inspect MCP servers
    for srv_name, cfg in _extract_mcp_servers(data).items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", ""))
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        unpinned = _is_unpinned_package_exec(cmd, [str(a) for a in args])
        if unpinned:
            ln = _find_line_for_needle(lines, srv_name)
            findings.append(
                _make_finding(
                    "SG040",
                    target,
                    line=ln,
                    message=(
                        f"MCP server `{srv_name}` runs unpinned dynamic package `{unpinned}` "
                        f"(vulnerable to upstream rug-pull)."
                    ),
                    snippet=_get_snippet(lines, ln),
                )
            )

        url = str(cfg.get("url") or cfg.get("serverUrl") or "")
        if url.lower().startswith("http://") and not _LOCALHOST_RE.match(url):
            ln = _find_line_for_needle(lines, url)
            findings.append(
                _make_finding(
                    "SG043",
                    target,
                    line=ln,
                    message=(
                        f"MCP server `{srv_name}` connects over plaintext HTTP (`{url}`) "
                        f"to a remote host."
                    ),
                    snippet=_get_snippet(lines, ln),
                )
            )

        env_map = cfg.get("env")
        if isinstance(env_map, dict):
            for k, v in env_map.items():
                if not isinstance(v, str):
                    continue
                v_strip = v.strip()
                if (
                    _SECRET_KEY_NAME_RE.search(k)
                    and len(v_strip) >= 12
                    and not v_strip.startswith(("$", "{", "<", "YOUR_", "REPLACE_", "CHANGE_ME"))
                    and "example" not in v_strip.lower()
                ):
                    ln = _find_line_for_needle(lines, k)
                    findings.append(
                        _make_finding(
                            "SG044",
                            target,
                            line=ln,
                            message=(
                                f"MCP server `{srv_name}` embeds plaintext secret in env key `{k}`."
                            ),
                            snippet=f'"{k}": "{v_strip[:4]}***"',
                        )
                    )

        auto_approve = cfg.get("autoApprove") or cfg.get("alwaysAllow")
        if isinstance(auto_approve, list) and "*" in auto_approve:
            ln = _find_line_for_needle(lines, srv_name)
            findings.append(
                _make_finding(
                    "SG042",
                    target,
                    line=ln,
                    message=f"MCP server `{srv_name}` sets wildcard auto-approval (`*`).",
                    snippet=_get_snippet(lines, ln),
                )
            )

    # 2. Inspect Claude / Agent Hooks (SessionStart, PreToolUse, PostToolUse, etc.)
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event_name, entries in hooks.items():
            for cmd_str in _collect_hook_commands(entries):
                if _HOOK_DANGEROUS_RE.search(cmd_str):
                    ln = _find_line_for_needle(lines, cmd_str[:32])
                    findings.append(
                        _make_finding(
                            "SG041",
                            target,
                            line=ln,
                            message=(
                                f"Agent hook `{event_name}` runs suspicious command: "
                                f"`{cmd_str[:100]}`."
                            ),
                            snippet=_get_snippet(lines, ln),
                        )
                    )

    # 3. Inspect over-permissive permission allowlists
    if data.get("dangerouslySkipPermissions") is True:
        ln = _find_line_for_needle(lines, "dangerouslySkipPermissions")
        findings.append(
            _make_finding(
                "SG042",
                target,
                line=ln,
                message="`dangerouslySkipPermissions` is set to true in agent settings.",
                snippet=_get_snippet(lines, ln),
            )
        )

    perms = data.get("permissions")
    if isinstance(perms, dict):
        allow_list = perms.get("allow")
        if isinstance(allow_list, list):
            for entry in allow_list:
                if isinstance(entry, str) and entry.strip() in (
                    "*",
                    "Bash",
                    "Bash(*)",
                    "Bash(*:*)",
                    "Shell(*)",
                ):
                    ln = _find_line_for_needle(lines, entry)
                    findings.append(
                        _make_finding(
                            "SG042",
                            target,
                            line=ln,
                            message=f"Over-permissive wildcard tool allowlist entry `{entry}`.",
                            snippet=_get_snippet(lines, ln),
                        )
                    )

    return findings


def _collect_hook_commands(node: Any) -> list[str]:
    cmds: list[str] = []
    if isinstance(node, str):
        cmds.append(node)
    elif isinstance(node, list):
        for item in node:
            cmds.extend(_collect_hook_commands(item))
    elif isinstance(node, dict):
        if isinstance(node.get("command"), str):
            cmds.append(node["command"])
        for k, v in node.items():
            if k != "command":
                cmds.extend(_collect_hook_commands(v))
    return cmds


# ---------------------------------------------------------------------------
# Engine 6: Python AST Deep Analyzer for Skill Scripts (SG050 - SG051)
# ---------------------------------------------------------------------------

_PY_NET_NAMES = {
    "urlopen",
    "Request",
    "post",
    "get",
    "put",
    "request",
    "connect",
    "create_connection",
}
_PY_SECRET_TOKENS = (".ssh", ".aws", ".kube", ".netrc", ".env", "id_rsa", "id_ed25519", "keychain")


def _fold_string_expr(node: ast.AST) -> str | None:
    """Fold constant string concatenations like `'~/' + '.ssh'` to defeat naive evasion."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_string_expr(node.left)
        right = _fold_string_expr(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def run_python_ast_engine(target: TargetFile, text: str, lines: list[str]) -> list[Finding]:
    if target.path.suffix.lower() != ".py":
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    net_call_lines: list[int] = []
    secret_read_lines: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _resolve_call_name(node.func)
            lineno = getattr(node, "lineno", 1)

            if func_name in ("eval", "exec", "os.system", "os.popen"):
                findings.append(
                    _make_finding(
                        "SG050",
                        target,
                        line=lineno,
                        message=f"Unsafe dynamic/shell call `{func_name}()` in skill script.",
                        snippet=_get_snippet(lines, lineno),
                    )
                )
            elif func_name.startswith("subprocess.") and any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            ):
                findings.append(
                    _make_finding(
                        "SG050",
                        target,
                        line=lineno,
                        message=f"`{func_name}(..., shell=True)` allows shell command injection.",
                        snippet=_get_snippet(lines, lineno),
                    )
                )

            tail = func_name.rsplit(".", 1)[-1]
            if tail in _PY_NET_NAMES:
                net_call_lines.append(lineno)

            if func_name in ("os.getenv", "os.environ.get"):
                secret_read_lines.append((lineno, func_name))

        elif isinstance(node, ast.Attribute) and node.attr == "environ":
            secret_read_lines.append((getattr(node, "lineno", 1), "os.environ"))

        folded = _fold_string_expr(node)
        if folded and any(tok in folded.lower() for tok in _PY_SECRET_TOKENS):
            secret_read_lines.append((getattr(node, "lineno", 1), folded))

    if net_call_lines and secret_read_lines:
        ln, detail = secret_read_lines[0]
        findings.append(
            _make_finding(
                "SG051",
                target,
                line=ln,
                message=(
                    f"Skill Python script accesses `{detail}` (line {ln}) and performs "
                    f"outbound network call (line {net_call_lines[0]})."
                ),
                snippet=_get_snippet(lines, ln),
            )
        )
    return findings


def _resolve_call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _resolve_call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""
