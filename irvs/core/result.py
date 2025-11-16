"""Verification result data structures."""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        """Compare severity levels."""
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        return order[self] < order[other]


@dataclass
class Finding:
    """Represents a security finding."""
    severity: Severity
    category: str
    title: str
    description: str
    remediation: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    affected_component: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score,
            "affected_component": self.affected_component,
            "metadata": self.metadata
        }


@dataclass
class VerificationResult:
    """Aggregated verification results."""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    passed: bool = True
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    verification_types: List[str] = field(default_factory=list)

    def add_finding(self, finding: Finding):
        """Add a finding to the results."""
        self.findings.append(finding)
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            self.passed = False

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_count(self) -> int:
        """Get count of critical findings."""
        return len(self.get_findings_by_severity(Severity.CRITICAL))

    def get_high_count(self) -> int:
        """Get count of high severity findings."""
        return len(self.get_findings_by_severity(Severity.HIGH))

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of verification results."""
        severity_counts = {}
        for severity in Severity:
            severity_counts[severity.value] = len(self.get_findings_by_severity(severity))

        return {
            "timestamp": self.timestamp.isoformat(),
            "passed": self.passed,
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "verification_types": self.verification_types
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "passed": self.passed,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "verification_types": self.verification_types,
            "summary": self.get_summary()
        }
