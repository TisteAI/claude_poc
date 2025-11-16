"""Integration tests for IRVS."""

import pytest
from pathlib import Path

from irvs.core.config import Config
from irvs.core.verification import VerificationEngine
from irvs.core.result import Severity


FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestPackageVerification:
    """Test package verification with real fixtures."""

    def test_verify_vulnerable_requirements(self):
        """Test scanning vulnerable requirements file."""
        config = Config()
        config.supply_chain.check_typosquatting = True
        config.supply_chain.detect_malicious_packages = True

        engine = VerificationEngine(config)

        # This would need the verify to work with just a requirements file
        # For now, testing the supply chain analyzer directly
        from irvs.modules.supply_chain import SupplyChainAnalyzer

        analyzer = SupplyChainAnalyzer(config.supply_chain)
        fixtures_path = FIXTURES_DIR / "packages"

        result = analyzer.analyze_directory(str(fixtures_path))

        # Should find issues
        assert len(result.findings) > 0

        # Should detect typosquatting
        typo_findings = [f for f in result.findings if "Typosquatting" in f.title]
        assert len(typo_findings) > 0

        # Should detect malicious pattern
        malicious_findings = [f for f in result.findings if "Malicious" in f.title]
        assert len(malicious_findings) > 0

        # Should detect unpinned dependencies
        unpinned_findings = [f for f in result.findings if "Unpinned" in f.title]
        assert len(unpinned_findings) > 0

    def test_verify_good_requirements(self):
        """Test scanning well-secured requirements file."""
        config = Config()

        from irvs.modules.supply_chain import SupplyChainAnalyzer
        from irvs.utils.parsers import DependencyParser

        analyzer = SupplyChainAnalyzer(config.supply_chain)

        good_reqs = FIXTURES_DIR / "packages" / "good-requirements.txt"
        dependencies = DependencyParser.parse_requirements_txt(good_reqs)

        # Should parse dependencies
        assert len(dependencies) > 0

        # All should be pinned with ==
        for dep in dependencies:
            assert dep.version_spec == "=="


class TestPipelineScanning:
    """Test pipeline security scanning."""

    def test_scan_insecure_workflow(self):
        """Test scanning insecure GitHub Actions workflow."""
        config = Config()

        from irvs.modules.pipeline_scanner import PipelineScanner

        scanner = PipelineScanner(config.pipeline)
        insecure_workflow = FIXTURES_DIR / "pipelines" / "insecure-workflow.yml"

        result = scanner.scan(str(insecure_workflow.parent))

        # Should find multiple issues
        assert len(result.findings) > 0

        # Should detect unpinned actions
        unpinned = [f for f in result.findings if "Not Pinned" in f.title or "Unpinned" in f.title]
        assert len(unpinned) > 0

        # Should detect hardcoded secrets
        secrets = [f for f in result.findings if f.category == "secrets"]
        assert len(secrets) > 0

        # Should detect overly permissive permissions
        perms = [f for f in result.findings if "Permissive" in f.title]
        assert len(perms) > 0

    def test_scan_secure_workflow(self):
        """Test scanning secure GitHub Actions workflow."""
        config = Config()

        from irvs.modules.pipeline_scanner import PipelineScanner

        scanner = PipelineScanner(config.pipeline)
        secure_workflow = FIXTURES_DIR / "pipelines" / "secure-workflow.yml"

        result = scanner.scan(str(secure_workflow.parent))

        # Should have minimal findings (pinned actions are good)
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        # Secure workflow shouldn't have critical issues
        assert len(critical_findings) == 0


class TestDependencyParsing:
    """Test dependency parsing utilities."""

    def test_parse_requirements_txt(self):
        """Test parsing Python requirements.txt."""
        from irvs.utils.parsers import DependencyParser

        req_file = FIXTURES_DIR / "packages" / "vulnerable-requirements.txt"
        dependencies = DependencyParser.parse_requirements_txt(req_file)

        assert len(dependencies) > 0

        # Check for specific packages
        package_names = [d.name for d in dependencies]
        assert "requests" in package_names
        assert "flask" in package_names
        assert "django" in package_names

        # Check version parsing
        django_dep = next(d for d in dependencies if d.name == "django")
        assert django_dep.version == "2.2.0"
        assert django_dep.version_spec == "=="

    def test_parse_package_json(self):
        """Test parsing Node.js package.json."""
        from irvs.utils.parsers import DependencyParser

        pkg_file = FIXTURES_DIR / "packages" / "package.json"
        prod_deps, dev_deps = DependencyParser.parse_package_json(pkg_file)

        assert len(prod_deps) > 0
        assert len(dev_deps) > 0

        # Check production dependencies
        prod_names = [d.name for d in prod_deps]
        assert "express" in prod_names
        assert "lodash" in prod_names

        # Check dev dependencies
        dev_names = [d.name for d in dev_deps]
        assert "jest" in dev_names


class TestReporting:
    """Test report generation."""

    def test_generate_markdown_report(self):
        """Test Markdown report generation."""
        from irvs.core.result import VerificationResult, Finding
        from irvs.utils.reporters import ReportGenerator

        result = VerificationResult()
        result.add_finding(Finding(
            severity=Severity.HIGH,
            category="test",
            title="Test Finding",
            description="Test description",
            remediation="Fix it"
        ))

        markdown = ReportGenerator.generate_markdown_report(result, "Test Report")

        assert "# Test Report" in markdown
        assert "Test Finding" in markdown
        assert "FAILED" in markdown  # High severity should fail
        assert "HIGH" in markdown

    def test_generate_html_report(self):
        """Test HTML report generation."""
        from irvs.core.result import VerificationResult, Finding
        from irvs.utils.reporters import ReportGenerator

        result = VerificationResult()
        result.add_finding(Finding(
            severity=Severity.CRITICAL,
            category="vulnerability",
            title="CVE-2023-12345",
            description="Critical vulnerability",
            cve_ids=["CVE-2023-12345"],
            cvss_score=9.8
        ))

        html = ReportGenerator.generate_html_report(result, "Security Report")

        assert "<!DOCTYPE html>" in html
        assert "Security Report" in html
        assert "CVE-2023-12345" in html
        assert "CRITICAL" in html


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
