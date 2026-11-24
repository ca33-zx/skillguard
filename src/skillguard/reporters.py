"""Output formatters: Rich ANSI terminal, SARIF 2.1.0, JSON, and interactive HTML."""

from __future__ import annotations

import html
import json
from typing import Any

from .models import ScanReport, Severity
from .rules import RULE_CATALOG

_ANSI_RESET = "\033[0m"
_ANSI_BOLD = "\033[1m"
_ANSI_DIM = "\033[2m"
_ANSI_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",  # bold white on red
    Severity.HIGH: "\033[1;91m",  # bold bright red
    Severity.MEDIUM: "\033[1;93m",  # bold yellow
    Severity.LOW: "\033[1;96m",  # bold cyan
}


def format_terminal(report: ScanReport, *, color: bool = True) -> str:
    """Render a crisp, human-readable terminal security audit summary."""

    def _c(code: str, text: str) -> str:
        return f"{code}{text}{_ANSI_RESET}" if color else text

    counts = report.counts_by_severity
    lines: list[str] = []
    lines.append(_c(_ANSI_BOLD, "skillguard — AI Agent Skill & MCP Security Audit"))
    lines.append(
        f"Scanned {len(report.files_scanned)} agent file(s) in {report.elapsed_ms:.1f} ms  |  "
        f"Risk Score: {report.risk_score}/100 (Grade {report.grade})"
    )
    lines.append(
        f"Findings: {len(report.findings)} total  "
        f"[CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  "
        f"MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}]"
    )
    lines.append("-" * 78)

    if not report.findings:
        lines.append("PASS: No security issues detected across scanned agent customizations.")
        return "\n".join(lines)

    for idx, f in enumerate(report.findings, start=1):
        sev_badge = _c(_ANSI_COLORS[f.severity], f" {f.severity.value:8s} ")
        loc = _c(_ANSI_BOLD, f"{f.file}:{f.line}:{f.column}")
        cwe_tag = f" ({f.cwe})" if f.cwe else ""
        lines.append(f"{idx:2d}. {sev_badge} [{f.rule_id}]{cwe_tag} {f.title}")
        lines.append(f"    Location : {loc}  [{f.surface.value}]")
        lines.append(f"    Detail   : {f.message}")
        if f.snippet:
            lines.append(f"    Evidence : {_c(_ANSI_DIM, f.snippet)}")
        if f.decoded_payload:
            lines.append(f"    Decoded  : {_c(_ANSI_COLORS[Severity.HIGH], f.decoded_payload)}")
        lines.append(f"    Fix      : {f.remediation}")
        lines.append("")

    return "\n".join(lines).rstrip()


def format_json(report: ScanReport) -> str:
    """Render machine-readable JSON audit report."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def format_sarif(report: ScanReport, *, tool_version: str = "0.1.0") -> str:
    """Render OASIS SARIF 2.1.0 compatible with GitHub Code Scanning."""
    used_rules = sorted({f.rule_id for f in report.findings})
    rules_payload: list[dict[str, Any]] = []
    for rid in used_rules:
        meta = RULE_CATALOG[rid]
        rules_payload.append(
            {
                "id": meta.rule_id,
                "name": meta.title,
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.description},
                "help": {"text": meta.remediation},
                "defaultConfiguration": {"level": meta.severity.sarif_level},
                "properties": {
                    "category": meta.category,
                    "severity": meta.severity.value,
                    "tags": ["security", "ai-agent", meta.category, meta.cwe]
                    if meta.cwe
                    else ["security", "ai-agent", meta.category],
                },
            }
        )

    results_payload: list[dict[str, Any]] = []
    for f in report.findings:
        msg = f.message
        if f.decoded_payload:
            msg += f" | Decoded hidden payload: {f.decoded_payload}"
        results_payload.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level,
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {
                                "startLine": max(1, f.line),
                                "startColumn": max(1, f.column),
                                "snippet": {"text": f.snippet},
                            },
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skillguard",
                        "version": tool_version,
                        "informationUri": "https://github.com/ca33-zx/skillguard",
                        "rules": rules_payload,
                    }
                },
                "results": results_payload,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def format_html(report: ScanReport) -> str:
    """Render a zero-dependency dark-mode interactive HTML security dashboard."""
    counts = report.counts_by_severity
    score = report.risk_score
    grade = report.grade
    grade_color = (
        "#10b981"
        if score == 0
        else "#22c55e"
        if score <= 35
        else "#f59e0b"
        if score <= 60
        else "#ef4444"
    )

    cards_html: list[str] = []
    for f in report.findings:
        sev_cls = f.severity.value.lower()
        decoded_block = ""
        if f.decoded_payload:
            decoded_block = (
                '<div class="decoded"><strong>DECODED HIDDEN PAYLOAD:</strong> '
                f"<code>{html.escape(f.decoded_payload)}</code></div>"
            )
        cards_html.append(
            f"""
            <article class="card" data-sev="{sev_cls}">
              <div class="card-head">
                <span class="badge {sev_cls}">{f.severity.value}</span>
                <span class="rule">{html.escape(f.rule_id)}</span>
                <span class="title">{html.escape(f.title)}</span>
                <span class="cwe">{html.escape(f.cwe)}</span>
              </div>
              <div class="meta">
                <code>{html.escape(f.file)}:{f.line}:{f.column}</code>
                <span class="pill">{html.escape(f.surface.value)}</span>
                <span class="pill">{html.escape(f.category)}</span>
              </div>
              <p class="msg">{html.escape(f.message)}</p>
              <pre class="snippet">{html.escape(f.snippet)}</pre>
              {decoded_block}
              <div class="fix"><strong>Fix:</strong> {html.escape(f.remediation)}</div>
            </article>
            """
        )

    findings_body = (
        "\n".join(cards_html)
        if cards_html
        else '<div class="clean">PASS — No security findings detected.</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>skillguard Security Audit Report</title>
<style>
  :root {{ --bg:#0b1120; --panel:#111827; --border:#1f2937; --fg:#e5e7eb; --muted:#9ca3af; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:var(--bg); color:var(--fg); padding:28px; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  header {{ display:flex; justify-content:space-between; align-items:center; gap:20px;
            background:var(--panel); border:1px solid var(--border); border-radius:14px;
            padding:22px 26px; margin-bottom:20px; }}
  h1 {{ margin:0 0 6px; font-size:22px; }}
  .sub {{ color:var(--muted); font-size:13px; }}
  .grade {{ text-align:center; min-width:120px; padding:12px 16px; border-radius:12px;
            border:2px solid {grade_color}; background:#0f172a; }}
  .grade .big {{ font-size:30px; font-weight:800; color:{grade_color}; line-height:1.1; }}
  .grade .small {{ font-size:12px; color:var(--muted); margin-top:4px; }}
  .stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:18px; }}
  .stat {{ background:var(--panel); border:1px solid var(--border); border-radius:10px;
           padding:14px 16px; cursor:pointer; transition:border-color .15s; }}
  .stat:hover {{ border-color:#60a5fa; }}
  .stat .num {{ font-size:26px; font-weight:700; }}
  .stat .lbl {{ font-size:12px; color:var(--muted); text-transform:uppercase; }}
  .filters {{ display:flex; gap:8px; margin-bottom:16px; }}
  .fbtn {{ background:var(--panel); color:var(--fg); border:1px solid var(--border);
           border-radius:8px; padding:6px 12px; cursor:pointer; font-size:12px; }}
  .fbtn.active {{ border-color:#38bdf8; color:#38bdf8; }}
  .card {{ background:var(--panel); border:1px solid var(--border); border-radius:12px;
           padding:16px 18px; margin-bottom:14px; }}
  .card-head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:8px; }}
  .badge {{ font-size:11px; font-weight:700; padding:3px 8px; border-radius:6px; }}
  .badge.critical {{ background:#dc2626; color:#fff; }}
  .badge.high {{ background:#ea580c; color:#fff; }}
  .badge.medium {{ background:#ca8a04; color:#111; }}
  .badge.low {{ background:#0284c7; color:#fff; }}
  .rule {{ font-family:ui-monospace,SFMono-Regular,monospace; color:#93c5fd; font-weight:700; }}
  .title {{ font-weight:600; font-size:15px; }}
  .cwe {{ margin-left:auto; font-size:12px; color:var(--muted); }}
  .meta {{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }}
  .pill {{ background:#1e293b; color:#cbd5e1; font-size:11px;
           padding:2px 8px; border-radius:999px; }}
  .msg {{ margin:6px 0 10px; color:#d1d5db; font-size:14px; }}
  .snippet {{ background:#020617; border:1px solid #1e293b; border-radius:8px; padding:10px 12px;
              overflow-x:auto; font-size:12px; color:#f8fafc; margin:0 0 10px; }}
  .decoded {{ background:#450a0a; border:1px solid #ef4444; border-radius:8px; padding:9px 12px;
              color:#fecaca; font-size:13px; margin-bottom:10px; }}
  .fix {{ font-size:13px; color:#86efac; }}
  .clean {{ background:#064e3b; border:1px solid #10b981; color:#d1fae5; padding:20px;
            border-radius:12px; font-weight:600; text-align:center; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>skillguard Security Audit Report</h1>
      <div class="sub">
        Scanned {len(report.files_scanned)} agent file(s) in {report.elapsed_ms:.1f} ms &bull;
        Roots: {html.escape(", ".join(report.roots))}
      </div>
    </div>
    <div class="grade">
      <div class="big">{grade}</div>
      <div class="small">Risk {score} / 100</div>
    </div>
  </header>

  <section class="stats">
    <div class="stat" onclick="filterSev('critical')">
      <div class="num" style="color:#ef4444">{counts["CRITICAL"]}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="stat" onclick="filterSev('high')">
      <div class="num" style="color:#f97316">{counts["HIGH"]}</div><div class="lbl">High</div>
    </div>
    <div class="stat" onclick="filterSev('medium')">
      <div class="num" style="color:#eab308">{counts["MEDIUM"]}</div><div class="lbl">Medium</div>
    </div>
    <div class="stat" onclick="filterSev('low')">
      <div class="num" style="color:#38bdf8">{counts["LOW"]}</div><div class="lbl">Low</div>
    </div>
  </section>

  <div class="filters">
    <button class="fbtn active" onclick="filterSev('all', this)">
      All ({len(report.findings)})
    </button>
    <button class="fbtn" onclick="filterSev('critical', this)">Critical</button>
    <button class="fbtn" onclick="filterSev('high', this)">High</button>
    <button class="fbtn" onclick="filterSev('medium', this)">Medium</button>
    <button class="fbtn" onclick="filterSev('low', this)">Low</button>
  </div>

  <main id="findings">
    {findings_body}
  </main>
</div>
<script>
function filterSev(sev, btn) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.querySelectorAll('.card').forEach(c => {{
    c.style.display = (sev === 'all' || c.dataset.sev === sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>
"""
