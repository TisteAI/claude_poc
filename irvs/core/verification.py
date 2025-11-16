"""Main verification engine orchestrating all security checks."""

import logging
from typing import List, Optional
from pathlib import Path

from irvs.core.config import Config
from irvs.core.result import VerificationResult, Finding, Severity
from irvs.modules.package_verifier import PackageVerifier
from irvs.modules.pipeline_scanner import PipelineScanner
from irvs.modules.supply_chain import SupplyChainAnalyzer
from irvs.modules.vulnerability_scanner import VulnerabilityScanner
from irvs.modules.provenance_verifier import ProvenanceVerifier
from irvs.modules.policy_engine import PolicyEngine
from irvs.modules.sbom_handler import SBOMHandler


logger = logging.getLogger(__name__)


class VerificationEngine:
    """
    Main orchestration engine for infrastructure resilience verification.

    Coordinates all verification modules and aggregates results.
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the verification engine.

        Args:
            config: Configuration object. Uses default if not provided.
        """
        self.config = config or Config()
        self._setup_logging()
        self._initialize_modules()

    def _setup_logging(self):
        """Configure logging based on configuration."""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    def _initialize_modules(self):
        """Initialize all verification modules."""
        self.package_verifier = PackageVerifier(self.config.package_verification)
        self.pipeline_scanner = PipelineScanner(self.config.pipeline)
        self.supply_chain_analyzer = SupplyChainAnalyzer(self.config.supply_chain)
        self.vulnerability_scanner = VulnerabilityScanner(self.config.vulnerability)
        self.provenance_verifier = ProvenanceVerifier(self.config.provenance)
        self.policy_engine = PolicyEngine(self.config.policy)
        self.sbom_handler = SBOMHandler()

    def verify_package(self, package_path: str) -> VerificationResult:
        """
        Perform comprehensive verification of a package.

        Args:
            package_path: Path to the package to verify

        Returns:
            VerificationResult containing all findings
        """
        logger.info(f"Starting verification of package: {package_path}")
        result = VerificationResult()
        result.verification_types.append("package_verification")

        try:
            # Package integrity verification
            pkg_result = self.package_verifier.verify(package_path)
            result.findings.extend(pkg_result.findings)

            # Vulnerability scanning
            if self.config.vulnerability.enabled:
                vuln_result = self.vulnerability_scanner.scan_package(package_path)
                result.findings.extend(vuln_result.findings)
                result.verification_types.append("vulnerability_scan")

            # Supply chain analysis
            if self.config.supply_chain.analyze_dependencies:
                sc_result = self.supply_chain_analyzer.analyze_package(package_path)
                result.findings.extend(sc_result.findings)
                result.verification_types.append("supply_chain_analysis")

            # Policy enforcement
            if self.config.policy.enabled:
                policy_result = self.policy_engine.evaluate(result, context="package")
                result.findings.extend(policy_result.findings)
                result.verification_types.append("policy_check")

        except Exception as e:
            logger.error(f"Error during package verification: {e}")
            result.add_finding(Finding(
                severity=Severity.HIGH,
                category="verification_error",
                title="Verification Error",
                description=f"Error during verification: {str(e)}",
                metadata={"error_type": type(e).__name__}
            ))

        logger.info(f"Verification complete. Found {len(result.findings)} findings.")
        return result

    def verify_pipeline(self, pipeline_path: str) -> VerificationResult:
        """
        Verify CI/CD pipeline security.

        Args:
            pipeline_path: Path to pipeline configuration files

        Returns:
            VerificationResult containing all findings
        """
        logger.info(f"Starting pipeline verification: {pipeline_path}")
        result = VerificationResult()
        result.verification_types.append("pipeline_scan")

        try:
            # Scan pipeline configurations
            pipeline_result = self.pipeline_scanner.scan(pipeline_path)
            result.findings.extend(pipeline_result.findings)

            # Policy enforcement
            if self.config.policy.enabled:
                policy_result = self.policy_engine.evaluate(result, context="pipeline")
                result.findings.extend(policy_result.findings)

        except Exception as e:
            logger.error(f"Error during pipeline verification: {e}")
            result.add_finding(Finding(
                severity=Severity.HIGH,
                category="verification_error",
                title="Pipeline Verification Error",
                description=f"Error during pipeline verification: {str(e)}"
            ))

        return result

    def verify_provenance(self, artifact_path: str, provenance_path: Optional[str] = None) -> VerificationResult:
        """
        Verify build provenance and SLSA compliance.

        Args:
            artifact_path: Path to the artifact
            provenance_path: Optional path to provenance attestation

        Returns:
            VerificationResult containing all findings
        """
        logger.info(f"Starting provenance verification for: {artifact_path}")
        result = VerificationResult()
        result.verification_types.append("provenance_verification")

        try:
            prov_result = self.provenance_verifier.verify(artifact_path, provenance_path)
            result.findings.extend(prov_result.findings)

        except Exception as e:
            logger.error(f"Error during provenance verification: {e}")
            result.add_finding(Finding(
                severity=Severity.HIGH,
                category="provenance_error",
                title="Provenance Verification Error",
                description=f"Error during provenance verification: {str(e)}"
            ))

        return result

    def generate_sbom(self, target_path: str, output_format: str = "spdx") -> str:
        """
        Generate Software Bill of Materials.

        Args:
            target_path: Path to analyze
            output_format: SBOM format (spdx, cyclonedx)

        Returns:
            Path to generated SBOM file
        """
        logger.info(f"Generating SBOM for: {target_path}")
        return self.sbom_handler.generate(target_path, output_format)

    def verify_sbom(self, sbom_path: str) -> VerificationResult:
        """
        Verify and analyze an existing SBOM.

        Args:
            sbom_path: Path to SBOM file

        Returns:
            VerificationResult containing all findings
        """
        logger.info(f"Verifying SBOM: {sbom_path}")
        result = VerificationResult()
        result.verification_types.append("sbom_verification")

        try:
            sbom_result = self.sbom_handler.verify(sbom_path)
            result.findings.extend(sbom_result.findings)

            # Analyze SBOM contents for vulnerabilities
            if self.config.vulnerability.enabled:
                vuln_result = self.vulnerability_scanner.scan_sbom(sbom_path)
                result.findings.extend(vuln_result.findings)

        except Exception as e:
            logger.error(f"Error during SBOM verification: {e}")
            result.add_finding(Finding(
                severity=Severity.MEDIUM,
                category="sbom_error",
                title="SBOM Verification Error",
                description=f"Error during SBOM verification: {str(e)}"
            ))

        return result

    def full_verification(self, target_path: str) -> VerificationResult:
        """
        Perform comprehensive verification of all aspects.

        Args:
            target_path: Path to target (package, repository, etc.)

        Returns:
            Aggregated VerificationResult
        """
        logger.info(f"Starting full verification of: {target_path}")
        result = VerificationResult()

        path = Path(target_path)

        # Detect what we're analyzing and run appropriate checks
        if path.is_file():
            # Single file/package verification
            pkg_result = self.verify_package(target_path)
            result.findings.extend(pkg_result.findings)
            result.verification_types.extend(pkg_result.verification_types)

        elif path.is_dir():
            # Directory - check for pipelines, dependencies, etc.

            # Check for CI/CD pipelines
            pipeline_dirs = ['.github/workflows', '.gitlab-ci.yml', 'Jenkinsfile']
            for pipeline_dir in pipeline_dirs:
                pipeline_path = path / pipeline_dir
                if pipeline_path.exists():
                    pipeline_result = self.verify_pipeline(str(pipeline_path))
                    result.findings.extend(pipeline_result.findings)
                    result.verification_types.extend(pipeline_result.verification_types)

            # Supply chain analysis of dependencies
            if self.config.supply_chain.analyze_dependencies:
                sc_result = self.supply_chain_analyzer.analyze_directory(target_path)
                result.findings.extend(sc_result.findings)
                result.verification_types.append("supply_chain_analysis")

        # Apply policies
        if self.config.policy.enabled:
            policy_result = self.policy_engine.evaluate(result, context="full_verification")
            result.findings.extend(policy_result.findings)

        logger.info(f"Full verification complete. Total findings: {len(result.findings)}")
        return result
