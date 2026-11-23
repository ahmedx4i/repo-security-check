"""Core data types shared by every check."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple


class Severity(IntEnum):
    """How urgently a finding should be looked at."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as error:
            names = ", ".join(member.label for member in cls)
            raise ValueError(f"Unknown severity {value!r}; expected one of: {names}") from error


@dataclass(frozen=True)
class Rule:
    """Static metadata describing one detection rule."""

    id: str
    name: str
    title: str
    category: str
    severity: Severity
    description: str
    remediation: str
    references: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """One concrete problem found at a location in the scanned repository."""

    rule_id: str
    severity: Severity
    path: str
    message: str
    line: Optional[int] = None
    evidence: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class HygieneCheck:
    """One pass/warn result from the optional maintainer hygiene checks."""

    key: str
    passed: bool
    message: str
    points: int
    max_points: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "key": self.key,
            "status": "pass" if self.passed else "warn",
            "message": self.message,
            "points": self.points,
            "max_points": self.max_points,
        }


@dataclass
class Report:
    """Everything a scan produced."""

    target: str
    root: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    hygiene: Optional[List[HygieneCheck]] = None
    notes: List[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    @property
    def hygiene_score(self) -> Optional[int]:
        if self.hygiene is None:
            return None
        return sum(check.points for check in self.hygiene)

    def counts(self) -> Dict[str, int]:
        totals = {severity.label: 0 for severity in sorted(Severity, reverse=True)}
        for finding in self.findings:
            totals[finding.severity.label] += 1
        return totals

    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda item: (-int(item.severity), item.path, item.line or 0, item.rule_id),
        )
