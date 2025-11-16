"""Package integrity verification module."""

import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import subprocess
import json

from irvs.core.result import VerificationResult, Finding, Severity
from irvs.core.config import PackageVerificationConfig


logger = logging.getLogger(__name__)


class PackageVerifier:
    """
    Verifies package integrity through cryptographic signatures and checksums.

    Supports:
    - GPG/PGP signatures
    - Sigstore/Cosign verification
    - SHA-256/SHA-512 checksum validation
    - SBOM presence checks
    """

    def __init__(self, config: PackageVerificationConfig):
        """Initialize package verifier with configuration."""
        self.config = config

    def verify(self, package_path: str) -> VerificationResult:
        """
        Perform comprehensive package verification.

        Args:
            package_path: Path to package file

        Returns:
            VerificationResult with findings
        """
        result = VerificationResult()
        path = Path(package_path)

        if not path.exists():
            result.add_finding(Finding(
                severity=Severity.CRITICAL,
                category="package_integrity",
                title="Package Not Found",
                description=f"Package file does not exist: {package_path}",
                affected_component=package_path
            ))
            return result

        logger.info(f"Verifying package: {package_path}")

        # Checksum verification
        if self.config.verify_checksums:
            checksum_result = self._verify_checksums(path)
            if checksum_result:
                result.add_finding(checksum_result)

        # Signature verification
        if self.config.verify_signatures:
            sig_findings = self._verify_signatures(path)
            result.findings.extend(sig_findings)

        # SBOM check
        if self.config.require_sbom:
            sbom_finding = self._check_sbom_presence(path)
            if sbom_finding:
                result.add_finding(sbom_finding)

        # File integrity checks
        integrity_findings = self._check_file_integrity(path)
        result.findings.extend(integrity_findings)

        return result

    def _verify_checksums(self, package_path: Path) -> Optional[Finding]:
        """
        Verify package checksums against expected values.

        Args:
            package_path: Path to package

        Returns:
            Finding if verification fails, None if passes
        """
        logger.debug(f"Verifying checksums for {package_path}")

        # Look for checksum files
        checksum_files = {
            'sha256': package_path.parent / f"{package_path.name}.sha256",
            'sha512': package_path.parent / f"{package_path.name}.sha512"
        }

        checksums_found = False
        for algo, checksum_file in checksum_files.items():
            if checksum_file.exists():
                checksums_found = True
                expected_checksum = checksum_file.read_text().strip().split()[0]
                actual_checksum = self._calculate_checksum(package_path, algo)

                if expected_checksum != actual_checksum:
                    return Finding(
                        severity=Severity.CRITICAL,
                        category="package_integrity",
                        title="Checksum Mismatch",
                        description=f"{algo.upper()} checksum does not match expected value",
                        remediation="Do not use this package. Download from trusted source.",
                        affected_component=str(package_path),
                        metadata={
                            "algorithm": algo,
                            "expected": expected_checksum,
                            "actual": actual_checksum
                        }
                    )
                else:
                    logger.info(f"{algo.upper()} checksum verified successfully")

        if not checksums_found:
            return Finding(
                severity=Severity.HIGH,
                category="package_integrity",
                title="No Checksum File Found",
                description="Package does not have accompanying checksum file for verification",
                remediation="Obtain checksum from trusted source and verify manually",
                affected_component=str(package_path)
            )

        return None

    def _calculate_checksum(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """
        Calculate checksum of a file.

        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, sha512)

        Returns:
            Hexadecimal checksum string
        """
        if algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'sha512':
            hasher = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)

        return hasher.hexdigest()

    def _verify_signatures(self, package_path: Path) -> list[Finding]:
        """
        Verify cryptographic signatures.

        Args:
            package_path: Path to package

        Returns:
            List of findings
        """
        findings = []

        # Check for GPG signature
        if "gpg" in self.config.allowed_signature_types:
            gpg_finding = self._verify_gpg_signature(package_path)
            if gpg_finding:
                findings.append(gpg_finding)

        # Check for Cosign/Sigstore signature
        if "cosign" in self.config.allowed_signature_types or "sigstore" in self.config.allowed_signature_types:
            cosign_finding = self._verify_cosign_signature(package_path)
            if cosign_finding:
                findings.append(cosign_finding)

        if not findings:
            # No signatures found
            findings.append(Finding(
                severity=Severity.HIGH,
                category="package_integrity",
                title="No Cryptographic Signature Found",
                description="Package is not signed with any recognized signature method",
                remediation="Obtain signed package from official source",
                affected_component=str(package_path)
            ))

        return findings

    def _verify_gpg_signature(self, package_path: Path) -> Optional[Finding]:
        """Verify GPG signature if present."""
        sig_file = package_path.parent / f"{package_path.name}.sig"
        asc_file = package_path.parent / f"{package_path.name}.asc"

        sig_path = sig_file if sig_file.exists() else (asc_file if asc_file.exists() else None)

        if not sig_path:
            return Finding(
                severity=Severity.MEDIUM,
                category="package_integrity",
                title="GPG Signature Not Found",
                description=f"No GPG signature file found for {package_path.name}",
                affected_component=str(package_path)
            )

        try:
            # Attempt GPG verification
            result = subprocess.run(
                ['gpg', '--verify', str(sig_path), str(package_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info("GPG signature verified successfully")
                return None
            else:
                return Finding(
                    severity=Severity.CRITICAL,
                    category="package_integrity",
                    title="GPG Signature Verification Failed",
                    description="GPG signature is invalid or from untrusted key",
                    remediation="Verify package source and obtain valid signature",
                    affected_component=str(package_path),
                    metadata={"gpg_output": result.stderr}
                )

        except FileNotFoundError:
            return Finding(
                severity=Severity.INFO,
                category="package_integrity",
                title="GPG Not Available",
                description="GPG is not installed - cannot verify signature",
                remediation="Install GPG to enable signature verification"
            )
        except Exception as e:
            return Finding(
                severity=Severity.MEDIUM,
                category="package_integrity",
                title="GPG Verification Error",
                description=f"Error during GPG verification: {str(e)}",
                affected_component=str(package_path)
            )

    def _verify_cosign_signature(self, package_path: Path) -> Optional[Finding]:
        """Verify Cosign/Sigstore signature if available."""
        try:
            # Check if cosign is available
            result = subprocess.run(
                ['cosign', 'verify-blob', '--signature', f"{package_path}.sig", str(package_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info("Cosign signature verified successfully")
                return None
            else:
                return Finding(
                    severity=Severity.HIGH,
                    category="package_integrity",
                    title="Cosign Signature Verification Failed",
                    description="Cosign signature verification failed",
                    affected_component=str(package_path),
                    metadata={"cosign_output": result.stderr}
                )

        except FileNotFoundError:
            return Finding(
                severity=Severity.INFO,
                category="package_integrity",
                title="Cosign Not Available",
                description="Cosign is not installed - cannot verify Sigstore signature",
                remediation="Install Cosign to enable Sigstore signature verification"
            )
        except Exception as e:
            logger.debug(f"Cosign verification skipped: {e}")
            return None

    def _check_sbom_presence(self, package_path: Path) -> Optional[Finding]:
        """Check if package has accompanying SBOM."""
        sbom_extensions = ['.spdx', '.spdx.json', '.cdx.json', '.sbom.json']

        for ext in sbom_extensions:
            sbom_path = package_path.parent / f"{package_path.name}{ext}"
            if sbom_path.exists():
                logger.info(f"SBOM found: {sbom_path}")
                return None

        return Finding(
            severity=Severity.MEDIUM,
            category="supply_chain",
            title="SBOM Not Found",
            description="Package does not have accompanying Software Bill of Materials",
            remediation="Request SBOM from package maintainer or generate one",
            affected_component=str(package_path),
            metadata={"required_by_config": self.config.require_sbom}
        )

    def _check_file_integrity(self, package_path: Path) -> list[Finding]:
        """Perform additional file integrity checks."""
        findings = []

        # Check file size (detect unusually large files that might be suspicious)
        file_size = package_path.stat().st_size
        if file_size > 1024 * 1024 * 1024:  # > 1GB
            findings.append(Finding(
                severity=Severity.INFO,
                category="package_integrity",
                title="Large Package Size",
                description=f"Package is unusually large: {file_size / (1024*1024):.2f} MB",
                affected_component=str(package_path),
                metadata={"size_bytes": file_size}
            ))

        # Check if file is readable
        if not package_path.is_file():
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category="package_integrity",
                title="Invalid Package File",
                description="Package path does not point to a regular file",
                affected_component=str(package_path)
            ))

        return findings
