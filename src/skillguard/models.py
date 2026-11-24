"""Core data models for skillguard security findings and scan reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Finding severity aligned with SARIF & CVSS conventions."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @property
    def weight(self) -> int:
        return {
            Severity.LOW: 4,
            Severity.MEDIUM: 12,
            Severity.HIGH: 25,
            Severity.CRITICAL: 45,
        }[self]

    @property
    def sarif_level(self) -> str:
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


class SurfaceKind(str, Enum):
    """Classification of an AI coding-agent customization surface."""

    SKILL_DOC = "skill_doc"
    SKILL_SCRIPT = "skill_script"
    INSTRUCTION_FILE = "instruction_file"
    MCP_CONFIG = "mcp_config"
    AGENT_SETTINGS = "agent_settings"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TargetFile:
    """One discovered agent customization file to be audited."""

    path: Path
    relative_path: str
    surface: SurfaceKind


@dataclass(frozen=True)
class Finding:
    """Single security finding with exact location, evidence, and fix advice."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    file: str
    line: int
    column: int
    message: str
    snippet: str
    remediation: str
    cwe: str = ""
    decoded_payload: str | None = None
    surface: SurfaceKind = SurfaceKind.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "surface": self.surface.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "cwe": self.cwe,
        }
        if self.decoded_payload is not None:
            payload["decoded_payload"] = self.decoded_payload
        return payload


@dataclass
class ScanReport:
    """Aggregated audit report across one or more target roots."""

    roots: list[str]
    files_scanned: list[TargetFile]
    findings: list[Finding] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {
            s.value: 0 for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        }
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> int:
        """Bounded 0-100 risk score (0 = clean, 100 = severe compromise indicators)."""
        raw = sum(f.severity.weight for f in self.findings)
        return min(100, raw)

    @property
    def grade(self) -> str:
        score = self.risk_score
        if score == 0:
            return "A+"
        if score <= 15:
            return "A"
        if score <= 35:
            return "B"
        if score <= 60:
            return "C"
        if score <= 85:
            return "D"
        return "F"

    def exceeds_threshold(self, min_severity: Severity) -> bool:
        return any(f.severity.rank >= min_severity.rank for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "roots": self.roots,
            "summary": {
                "files_scanned": len(self.files_scanned),
                "total_findings": len(self.findings),
                "counts_by_severity": self.counts_by_severity,
                "risk_score": self.risk_score,
                "grade": self.grade,
                "elapsed_ms": round(self.elapsed_ms, 2),
            },
            "files": [
                {"path": tf.relative_path, "surface": tf.surface.value} for tf in self.files_scanned
            ],
            "findings": [f.to_dict() for f in self.findings],
        }
