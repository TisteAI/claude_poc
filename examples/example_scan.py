#!/usr/bin/env python3
"""
Example script demonstrating programmatic use of IRVS.

This example shows how to use IRVS as a Python library rather than a CLI tool.
"""

from irvs.core.config import Config
from irvs.core.verification import VerificationEngine
from irvs.core.result import Severity
import json


def main():
    """Run example security scans."""

    # Example 1: Create custom configuration
    print("=" * 80)
    print("Example 1: Custom Configuration")
    print("=" * 80)

    config = Config()
    config.vulnerability.fail_on_critical = True
    config.vulnerability.fail_on_high = True
    config.policy.enabled = True
    config.supply_chain.check_typosquatting = True

    print(f"Configuration created with {config.log_level} log level")
    print(f"Vulnerability scanning: {config.vulnerability.enabled}")
    print(f"Policy enforcement: {config.policy.enabled}")
    print()

    # Example 2: Verify a package
    print("=" * 80)
    print("Example 2: Package Verification")
    print("=" * 80)

    engine = VerificationEngine(config)

    # Note: Replace with actual package path
    # result = engine.verify_package("/path/to/package.tar.gz")

    print("Package verification engine initialized")
    print("To verify a package: result = engine.verify_package('/path/to/package')")
    print()

    # Example 3: Analyze results
    print("=" * 80)
    print("Example 3: Result Analysis (Simulated)")
    print("=" * 80)

    # Create a sample result for demonstration
    from irvs.core.result import VerificationResult, Finding

    result = VerificationResult()

    # Add sample findings
    result.add_finding(Finding(
        severity=Severity.HIGH,
        category="vulnerability",
        title="Example CVE-2023-12345",
        description="This is an example vulnerability finding",
        cve_ids=["CVE-2023-12345"],
        cvss_score=7.5,
        affected_component="example-package@1.2.3",
        remediation="Upgrade to version 1.2.4 or higher"
    ))

    result.add_finding(Finding(
        severity=Severity.MEDIUM,
        category="supply_chain",
        title="Unpinned Dependency",
        description="Dependency is not pinned to exact version",
        affected_component="lodash@^4.17.0",
        remediation="Pin to exact version: lodash@4.17.21"
    ))

    result.add_finding(Finding(
        severity=Severity.INFO,
        category="package_integrity",
        title="SBOM Available",
        description="Package includes Software Bill of Materials",
        affected_component="package.tar.gz"
    ))

    # Analyze results
    summary = result.get_summary()

    print(f"Verification Status: {'PASSED' if result.passed else 'FAILED'}")
    print(f"Total Findings: {summary['total_findings']}")
    print(f"\nSeverity Breakdown:")
    for severity, count in summary['severity_counts'].items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")

    print(f"\nCritical Issues: {result.get_critical_count()}")
    print(f"High Severity Issues: {result.get_high_count()}")

    # Example 4: Export results to JSON
    print("\n" + "=" * 80)
    print("Example 4: Export Results")
    print("=" * 80)

    result_dict = result.to_dict()
    json_output = json.dumps(result_dict, indent=2)

    print("Results exported to JSON format:")
    print(json_output[:500] + "...")  # Print first 500 chars

    # Example 5: Filter findings by severity
    print("\n" + "=" * 80)
    print("Example 5: Filter Findings")
    print("=" * 80)

    high_findings = result.get_findings_by_severity(Severity.HIGH)
    print(f"\nHigh Severity Findings ({len(high_findings)}):")
    for finding in high_findings:
        print(f"  - {finding.title}")
        print(f"    {finding.description}")
        if finding.remediation:
            print(f"    Remediation: {finding.remediation}")

    # Example 6: Generate SBOM
    print("\n" + "=" * 80)
    print("Example 6: SBOM Generation")
    print("=" * 80)

    print("To generate SBOM:")
    print("  sbom_path = engine.generate_sbom('/path/to/project', 'spdx-json')")
    print("  print(f'SBOM generated: {sbom_path}')")

    # Example 7: Pipeline scanning
    print("\n" + "=" * 80)
    print("Example 7: Pipeline Security Scanning")
    print("=" * 80)

    print("To scan CI/CD pipelines:")
    print("  pipeline_result = engine.verify_pipeline('.github/workflows')")
    print("  for finding in pipeline_result.findings:")
    print("      if finding.severity == Severity.CRITICAL:")
    print("          print(f'CRITICAL: {finding.title}')")

    # Example 8: Policy-based scanning
    print("\n" + "=" * 80)
    print("Example 8: Policy Enforcement")
    print("=" * 80)

    print("Policy engine is automatically applied during verification")
    print("Custom policies can be loaded from YAML files")
    print("Policies enforce compliance with NIST, FedRAMP, and other standards")

    print("\n" + "=" * 80)
    print("Examples Complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
