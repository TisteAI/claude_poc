"""Policy engine for security rules and compliance enforcement."""

import logging
import yaml
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from irvs.core.result import VerificationResult, Finding, Severity
from irvs.core.config import PolicyConfig


logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """Represents a security policy rule."""
    id: str
    name: str
    description: str
    severity: Severity
    conditions: List[Dict[str, Any]]
    remediation: Optional[str] = None
    enabled: bool = True
    compliance_frameworks: List[str] = None

    def __post_init__(self):
        if self.compliance_frameworks is None:
            self.compliance_frameworks = []


class PolicyEngine:
    """
    Enforces security policies and compliance rules.

    Supports:
    - Declarative policy definitions
    - Compliance framework templates (NIST, FedRAMP, FISMA)
    - Custom policy rules
    - Policy violation reporting
    """

    def __init__(self, config: PolicyConfig):
        """Initialize policy engine."""
        self.config = config
        self.policies: List[PolicyRule] = []

        if config.enabled:
            self._load_policies()

    def _load_policies(self):
        """Load policies from configured directory."""
        policy_dir = Path(self.config.policy_dir)

        if not policy_dir.exists():
            logger.warning(f"Policy directory does not exist: {policy_dir}")
            # Create default policies
            self._create_default_policies()
            return

        # Load policy files
        policy_files = list(policy_dir.glob('*.yaml')) + list(policy_dir.glob('*.yml'))

        for policy_file in policy_files:
            try:
                policies = self._load_policy_file(policy_file)
                self.policies.extend(policies)
                logger.info(f"Loaded {len(policies)} policies from {policy_file.name}")
            except Exception as e:
                logger.error(f"Error loading policy file {policy_file}: {e}")

        # Load custom policies
        for custom_policy_path in self.config.custom_policies:
            try:
                custom_policies = self._load_policy_file(Path(custom_policy_path))
                self.policies.extend(custom_policies)
            except Exception as e:
                logger.error(f"Error loading custom policy {custom_policy_path}: {e}")

        logger.info(f"Loaded {len(self.policies)} total policies")

    def _load_policy_file(self, policy_file: Path) -> List[PolicyRule]:
        """Load policies from a YAML file."""
        with open(policy_file, 'r') as f:
            data = yaml.safe_load(f)

        policies = []
        policy_list = data.get('policies', [])

        for policy_data in policy_list:
            try:
                severity = Severity(policy_data.get('severity', 'medium'))
                policy = PolicyRule(
                    id=policy_data['id'],
                    name=policy_data['name'],
                    description=policy_data.get('description', ''),
                    severity=severity,
                    conditions=policy_data.get('conditions', []),
                    remediation=policy_data.get('remediation'),
                    enabled=policy_data.get('enabled', True),
                    compliance_frameworks=policy_data.get('compliance_frameworks', [])
                )
                policies.append(policy)
            except KeyError as e:
                logger.error(f"Missing required field in policy: {e}")
            except Exception as e:
                logger.error(f"Error parsing policy: {e}")

        return policies

    def _create_default_policies(self):
        """Create default security policies."""
        default_policies = [
            PolicyRule(
                id="no-critical-vulns",
                name="No Critical Vulnerabilities",
                description="No critical severity vulnerabilities allowed",
                severity=Severity.CRITICAL,
                conditions=[
                    {"finding_category": "vulnerability", "finding_severity": "critical"}
                ],
                remediation="Fix all critical vulnerabilities before deployment",
                compliance_frameworks=["NIST-800-53", "FedRAMP"]
            ),
            PolicyRule(
                id="require-signature",
                name="Package Signature Required",
                description="All packages must have valid cryptographic signatures",
                severity=Severity.HIGH,
                conditions=[
                    {"finding_category": "package_integrity", "finding_title": "*signature*"}
                ],
                remediation="Use only signed packages from trusted sources",
                compliance_frameworks=["NIST-800-161"]
            ),
            PolicyRule(
                id="require-sbom",
                name="SBOM Required",
                description="Software Bill of Materials required for all packages",
                severity=Severity.MEDIUM,
                conditions=[
                    {"finding_category": "supply_chain", "finding_title": "*SBOM*"}
                ],
                remediation="Generate or obtain SBOM for all components",
                compliance_frameworks=["EO-14028", "NIST-800-161"]
            ),
            PolicyRule(
                id="no-hardcoded-secrets",
                name="No Hardcoded Secrets",
                description="No hardcoded secrets in pipeline or code",
                severity=Severity.CRITICAL,
                conditions=[
                    {"finding_category": "secrets"}
                ],
                remediation="Remove all hardcoded secrets and use secret management",
                compliance_frameworks=["NIST-800-53"]
            ),
            PolicyRule(
                id="min-slsa-level-2",
                name="Minimum SLSA Level 2",
                description="All artifacts must meet SLSA Level 2 or higher",
                severity=Severity.HIGH,
                conditions=[
                    {"finding_category": "provenance", "finding_title": "*SLSA Level*"}
                ],
                remediation="Use build process with proper provenance generation",
                compliance_frameworks=["NIST-800-161"]
            ),
            PolicyRule(
                id="no-unpinned-dependencies",
                name="Dependencies Must Be Pinned",
                description="All dependencies must be pinned to exact versions",
                severity=Severity.MEDIUM,
                conditions=[
                    {"finding_category": "supply_chain", "finding_title": "*Unpinned*"}
                ],
                remediation="Pin all dependencies to exact versions with checksums",
                compliance_frameworks=["NIST-800-161"]
            ),
            PolicyRule(
                id="no-blocked-packages",
                name="No Blocked Packages",
                description="Blocked packages must not be used",
                severity=Severity.CRITICAL,
                conditions=[
                    {"finding_category": "supply_chain", "finding_title": "*Blocked Package*"}
                ],
                remediation="Remove blocked packages and find approved alternatives",
                compliance_frameworks=["organizational-policy"]
            ),
            PolicyRule(
                id="github-actions-pinned",
                name="GitHub Actions Must Be Pinned to SHA",
                description="All GitHub Actions must be pinned to commit SHA",
                severity=Severity.HIGH,
                conditions=[
                    {"finding_category": "pipeline_security", "finding_title": "*Not Pinned*"}
                ],
                remediation="Pin all actions to specific commit SHAs",
                compliance_frameworks=["NIST-800-53"]
            ),
        ]

        self.policies = default_policies
        logger.info(f"Created {len(default_policies)} default policies")

    def evaluate(self, verification_result: VerificationResult, context: str = "default") -> VerificationResult:
        """
        Evaluate verification results against policies.

        Args:
            verification_result: Results from verification
            context: Context of the verification (package, pipeline, etc.)

        Returns:
            VerificationResult with policy violation findings
        """
        policy_result = VerificationResult()

        if not self.config.enabled:
            return policy_result

        logger.info(f"Evaluating {len(self.policies)} policies in context: {context}")

        for policy in self.policies:
            if not policy.enabled:
                continue

            violations = self._evaluate_policy(policy, verification_result)

            if violations:
                # Create finding for policy violation
                finding = Finding(
                    severity=policy.severity,
                    category="policy_violation",
                    title=f"Policy Violation: {policy.name}",
                    description=f"{policy.description}. Found {len(violations)} violation(s).",
                    remediation=policy.remediation,
                    metadata={
                        "policy_id": policy.id,
                        "policy_name": policy.name,
                        "violation_count": len(violations),
                        "violations": [v.title for v in violations[:10]],  # First 10
                        "compliance_frameworks": policy.compliance_frameworks,
                        "context": context
                    }
                )

                policy_result.add_finding(finding)

                if self.config.fail_on_policy_violation:
                    policy_result.passed = False

        logger.info(f"Found {len(policy_result.findings)} policy violations")
        return policy_result

    def _evaluate_policy(self, policy: PolicyRule, verification_result: VerificationResult) -> List[Finding]:
        """Evaluate a single policy against verification results."""
        violations = []

        for condition in policy.conditions:
            matching_findings = self._find_matching_findings(condition, verification_result.findings)
            violations.extend(matching_findings)

        return violations

    def _find_matching_findings(self, condition: Dict[str, Any], findings: List[Finding]) -> List[Finding]:
        """Find findings that match a policy condition."""
        matches = []

        for finding in findings:
            if self._matches_condition(finding, condition):
                matches.append(finding)

        return matches

    def _matches_condition(self, finding: Finding, condition: Dict[str, Any]) -> bool:
        """Check if a finding matches a policy condition."""
        # Check category
        if 'finding_category' in condition:
            if finding.category != condition['finding_category']:
                return False

        # Check severity
        if 'finding_severity' in condition:
            required_severity = Severity(condition['finding_severity'])
            if finding.severity != required_severity:
                return False

        # Check title (supports wildcards)
        if 'finding_title' in condition:
            pattern = condition['finding_title']
            if '*' in pattern:
                # Simple wildcard matching
                pattern = pattern.replace('*', '.*')
                import re
                if not re.search(pattern, finding.title, re.IGNORECASE):
                    return False
            else:
                if pattern.lower() not in finding.title.lower():
                    return False

        # Check CVSS score threshold
        if 'min_cvss_score' in condition:
            if finding.cvss_score is None or finding.cvss_score < condition['min_cvss_score']:
                return False

        # Check affected component
        if 'affected_component_pattern' in condition:
            pattern = condition['affected_component_pattern']
            if finding.affected_component is None:
                return False
            if pattern not in finding.affected_component:
                return False

        return True

    def get_compliance_report(self, verification_result: VerificationResult, framework: str) -> Dict[str, Any]:
        """
        Generate compliance report for a specific framework.

        Args:
            verification_result: Verification results
            framework: Compliance framework (e.g., 'NIST-800-53', 'FedRAMP')

        Returns:
            Compliance report dictionary
        """
        relevant_policies = [p for p in self.policies if framework in p.compliance_frameworks]

        report = {
            "framework": framework,
            "timestamp": verification_result.timestamp.isoformat(),
            "total_policies": len(relevant_policies),
            "policies_evaluated": [],
            "violations": [],
            "compliant": True
        }

        for policy in relevant_policies:
            violations = self._evaluate_policy(policy, verification_result)

            policy_info = {
                "policy_id": policy.id,
                "policy_name": policy.name,
                "severity": policy.severity.value,
                "violation_count": len(violations),
                "compliant": len(violations) == 0
            }

            report["policies_evaluated"].append(policy_info)

            if violations:
                report["compliant"] = False
                report["violations"].extend([
                    {
                        "policy": policy.name,
                        "finding": v.title,
                        "severity": v.severity.value,
                        "remediation": policy.remediation
                    }
                    for v in violations
                ])

        return report
