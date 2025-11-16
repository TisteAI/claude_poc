"""Tests for core IRVS functionality."""

import pytest
from datetime import datetime

from irvs.core.result import VerificationResult, Finding, Severity
from irvs.core.config import Config


class TestVerificationResult:
    """Test VerificationResult class."""

    def test_create_result(self):
        """Test creating a verification result."""
        result = VerificationResult()
        assert result.passed is True
        assert len(result.findings) == 0
        assert isinstance(result.timestamp, datetime)

    def test_add_finding(self):
        """Test adding findings to result."""
        result = VerificationResult()

        finding = Finding(
            severity=Severity.HIGH,
            category="test",
            title="Test Finding",
            description="Test description"
        )

        result.add_finding(finding)
        assert len(result.findings) == 1
        assert result.passed is False  # High severity should fail

    def test_add_info_finding(self):
        """Test adding info finding doesn't fail verification."""
        result = VerificationResult()

        finding = Finding(
            severity=Severity.INFO,
            category="test",
            title="Info Finding",
            description="Informational"
        )

        result.add_finding(finding)
        assert len(result.findings) == 1
        assert result.passed is True  # Info shouldn't fail

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        result = VerificationResult()

        result.add_finding(Finding(
            severity=Severity.CRITICAL,
            category="test",
            title="Critical",
            description="Critical issue"
        ))

        result.add_finding(Finding(
            severity=Severity.HIGH,
            category="test",
            title="High",
            description="High issue"
        ))

        result.add_finding(Finding(
            severity=Severity.INFO,
            category="test",
            title="Info",
            description="Info"
        ))

        critical = result.get_findings_by_severity(Severity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].title == "Critical"

        high = result.get_findings_by_severity(Severity.HIGH)
        assert len(high) == 1

    def test_get_summary(self):
        """Test result summary generation."""
        result = VerificationResult()

        result.add_finding(Finding(
            severity=Severity.CRITICAL,
            category="test",
            title="Critical",
            description="Critical"
        ))

        result.add_finding(Finding(
            severity=Severity.HIGH,
            category="test",
            title="High",
            description="High"
        ))

        summary = result.get_summary()

        assert summary['total_findings'] == 2
        assert summary['severity_counts']['critical'] == 1
        assert summary['severity_counts']['high'] == 1
        assert summary['passed'] is False


class TestFinding:
    """Test Finding class."""

    def test_create_finding(self):
        """Test creating a finding."""
        finding = Finding(
            severity=Severity.HIGH,
            category="vulnerability",
            title="CVE-2023-12345",
            description="Test vulnerability",
            cve_ids=["CVE-2023-12345"],
            cvss_score=7.5,
            affected_component="package@1.0.0",
            remediation="Upgrade to 1.0.1"
        )

        assert finding.severity == Severity.HIGH
        assert finding.category == "vulnerability"
        assert "CVE-2023-12345" in finding.cve_ids
        assert finding.cvss_score == 7.5

    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = Finding(
            severity=Severity.MEDIUM,
            category="test",
            title="Test",
            description="Description"
        )

        finding_dict = finding.to_dict()

        assert finding_dict['severity'] == 'medium'
        assert finding_dict['category'] == 'test'
        assert finding_dict['title'] == 'Test'


class TestConfig:
    """Test configuration management."""

    def test_default_config(self):
        """Test default configuration creation."""
        config = Config()

        assert config.policy.enabled is True
        assert config.package_verification.verify_signatures is True
        assert config.vulnerability.enabled is True
        assert config.provenance.enabled is True

    def test_config_to_dict(self):
        """Test converting config to dictionary."""
        config = Config()
        config_dict = config.to_dict()

        assert 'policy' in config_dict
        assert 'package_verification' in config_dict
        assert 'vulnerability' in config_dict

    def test_config_modification(self):
        """Test modifying configuration."""
        config = Config()

        config.vulnerability.fail_on_critical = False
        config.provenance.require_slsa_level = 3

        assert config.vulnerability.fail_on_critical is False
        assert config.provenance.require_slsa_level == 3


class TestSeverity:
    """Test Severity enum."""

    def test_severity_comparison(self):
        """Test severity level comparisons."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
