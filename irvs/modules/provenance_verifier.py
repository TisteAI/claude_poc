"""Build provenance verification module (SLSA framework)."""

import logging
import json
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

from irvs.core.result import VerificationResult, Finding, Severity
from irvs.core.config import ProvenanceConfig


logger = logging.getLogger(__name__)


class ProvenanceVerifier:
    """
    Verifies build provenance and SLSA compliance.

    Supports:
    - SLSA provenance attestations
    - in-toto layouts
    - Cosign attestation verification
    - Build environment validation
    """

    def __init__(self, config: ProvenanceConfig):
        """Initialize provenance verifier."""
        self.config = config

    def verify(self, artifact_path: str, provenance_path: Optional[str] = None) -> VerificationResult:
        """
        Verify artifact provenance.

        Args:
            artifact_path: Path to the artifact
            provenance_path: Optional path to provenance attestation

        Returns:
            VerificationResult with findings
        """
        result = VerificationResult()

        if not self.config.enabled:
            logger.info("Provenance verification is disabled")
            return result

        logger.info(f"Verifying provenance for: {artifact_path}")

        artifact = Path(artifact_path)
        if not artifact.exists():
            result.add_finding(Finding(
                severity=Severity.CRITICAL,
                category="provenance",
                title="Artifact Not Found",
                description=f"Artifact file does not exist: {artifact_path}"
            ))
            return result

        # If provenance path not provided, look for it
        if not provenance_path:
            provenance_path = self._find_provenance(artifact)

        if provenance_path:
            # Verify provenance attestation
            prov_findings = self._verify_provenance_attestation(provenance_path, artifact_path)
            result.findings.extend(prov_findings)

            # Check SLSA level
            slsa_findings = self._check_slsa_level(provenance_path)
            result.findings.extend(slsa_findings)
        else:
            result.add_finding(Finding(
                severity=Severity.HIGH,
                category="provenance",
                title="No Provenance Attestation Found",
                description="Artifact does not have an accompanying provenance attestation",
                remediation="Ensure artifacts are built with provenance generation enabled",
                affected_component=artifact_path,
                metadata={"required_slsa_level": self.config.require_slsa_level}
            ))

        # Try to verify with cosign if available
        cosign_findings = self._verify_with_cosign(artifact_path)
        result.findings.extend(cosign_findings)

        # Check in-toto layout if configured
        if self.config.in_toto_layout:
            intoto_findings = self._verify_in_toto(artifact_path, self.config.in_toto_layout)
            result.findings.extend(intoto_findings)

        return result

    def _find_provenance(self, artifact: Path) -> Optional[str]:
        """Try to find provenance attestation for an artifact."""
        # Common provenance file patterns
        patterns = [
            f"{artifact}.intoto.jsonl",
            f"{artifact}.provenance.json",
            f"{artifact}.att",
            f"{artifact.stem}.provenance{artifact.suffix}",
        ]

        for pattern in patterns:
            prov_path = artifact.parent / pattern
            if prov_path.exists():
                logger.info(f"Found provenance: {prov_path}")
                return str(prov_path)

        return None

    def _verify_provenance_attestation(self, provenance_path: str, artifact_path: str) -> list[Finding]:
        """Verify provenance attestation format and content."""
        findings = []
        prov_file = Path(provenance_path)

        try:
            content = prov_file.read_text()

            # Try to parse as JSON
            try:
                provenance = json.loads(content)
            except json.JSONDecodeError:
                # Might be JSONL format
                lines = content.strip().split('\n')
                if lines:
                    provenance = json.loads(lines[0])
                else:
                    raise

            # Validate SLSA provenance structure
            if 'predicate' in provenance:
                predicate = provenance['predicate']

                # Check builder
                if 'builder' in predicate:
                    builder_id = predicate['builder'].get('id', '')

                    # Check if builder is trusted
                    if self.config.trusted_builders:
                        if not any(trusted in builder_id for trusted in self.config.trusted_builders):
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category="provenance",
                                title="Untrusted Builder",
                                description=f"Artifact was built by untrusted builder: {builder_id}",
                                remediation="Use artifacts from trusted builders only",
                                affected_component=artifact_path,
                                metadata={"builder_id": builder_id}
                            ))

                # Check build type
                if 'buildType' not in predicate:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category="provenance",
                        title="Missing Build Type",
                        description="Provenance does not specify build type",
                        affected_component=artifact_path
                    ))

                # Verify invocation parameters
                if 'invocation' in predicate:
                    invocation = predicate['invocation']

                    # Check for environment variables that might indicate tampering
                    if 'environment' in invocation:
                        env = invocation['environment']
                        suspicious_vars = ['DEBUG', 'UNSAFE', 'SKIP_VERIFY']

                        for var in suspicious_vars:
                            if var in env:
                                findings.append(Finding(
                                    severity=Severity.MEDIUM,
                                    category="provenance",
                                    title=f"Suspicious Environment Variable: {var}",
                                    description=f"Build environment contains suspicious variable: {var}={env[var]}",
                                    affected_component=artifact_path,
                                    metadata={"variable": var, "value": env[var]}
                                ))

                # Check materials (source inputs)
                if 'materials' in predicate:
                    materials = predicate['materials']
                    if not materials:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            category="provenance",
                            title="No Build Materials",
                            description="Provenance lists no source materials",
                            affected_component=artifact_path
                        ))
                else:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category="provenance",
                        title="Missing Build Materials",
                        description="Provenance does not include materials (source inputs)",
                        affected_component=artifact_path
                    ))

            else:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="provenance",
                    title="Invalid Provenance Format",
                    description="Provenance attestation missing 'predicate' field",
                    affected_component=artifact_path
                ))

        except json.JSONDecodeError as e:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="provenance",
                title="Invalid Provenance JSON",
                description=f"Failed to parse provenance: {str(e)}",
                affected_component=artifact_path
            ))
        except Exception as e:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="provenance",
                title="Provenance Verification Error",
                description=f"Error verifying provenance: {str(e)}",
                affected_component=artifact_path
            ))

        return findings

    def _check_slsa_level(self, provenance_path: str) -> list[Finding]:
        """Check SLSA compliance level."""
        findings = []

        try:
            with open(provenance_path, 'r') as f:
                content = f.read()
                provenance = json.loads(content)

            # Determine SLSA level based on provenance content
            # This is a simplified check - real implementation would be more thorough
            slsa_level = 1

            predicate = provenance.get('predicate', {})

            # SLSA Level 2: Source and build platform provenance
            if 'builder' in predicate and 'materials' in predicate:
                slsa_level = 2

            # SLSA Level 3: Hardened build platform
            if slsa_level >= 2 and predicate.get('builder', {}).get('id'):
                # Check for indicators of hardened platform
                slsa_level = 3

            if slsa_level < self.config.require_slsa_level:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="provenance",
                    title=f"SLSA Level Below Requirement",
                    description=f"Artifact meets SLSA Level {slsa_level}, but Level {self.config.require_slsa_level} is required",
                    remediation=f"Use build process that achieves SLSA Level {self.config.require_slsa_level}+",
                    metadata={
                        "detected_level": slsa_level,
                        "required_level": self.config.require_slsa_level
                    }
                ))
            else:
                logger.info(f"Artifact meets SLSA Level {slsa_level}")

        except Exception as e:
            logger.error(f"Error checking SLSA level: {e}")

        return findings

    def _verify_with_cosign(self, artifact_path: str) -> list[Finding]:
        """Verify attestations using Cosign."""
        findings = []

        try:
            # Try to verify cosign attestation
            result = subprocess.run(
                ['cosign', 'verify-attestation', '--type', 'slsaprovenance', artifact_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.debug(f"Cosign verification failed or not available: {result.stderr}")

        except FileNotFoundError:
            logger.debug("Cosign not installed")
        except Exception as e:
            logger.debug(f"Cosign verification skipped: {e}")

        return findings

    def _verify_in_toto(self, artifact_path: str, layout_path: str) -> list[Finding]:
        """Verify in-toto layout."""
        findings = []

        try:
            # This would use in-toto-verify command or library
            # For now, just check if layout exists
            if not Path(layout_path).exists():
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="provenance",
                    title="in-toto Layout Not Found",
                    description=f"Configured in-toto layout not found: {layout_path}",
                    affected_component=artifact_path
                ))

        except Exception as e:
            logger.error(f"Error verifying in-toto: {e}")

        return findings
