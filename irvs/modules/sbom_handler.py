"""Software Bill of Materials (SBOM) generation and validation."""

import logging
import json
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

from irvs.core.result import VerificationResult, Finding, Severity


logger = logging.getLogger(__name__)


class SBOMHandler:
    """
    Handles SBOM generation and validation.

    Supports:
    - SPDX format
    - CycloneDX format
    - SBOM validation
    - Integration with Syft and other tools
    """

    def __init__(self):
        """Initialize SBOM handler."""
        self.supported_formats = ['spdx', 'cyclonedx', 'spdx-json', 'cyclonedx-json']

    def generate(self, target_path: str, output_format: str = 'spdx-json') -> str:
        """
        Generate SBOM for a target.

        Args:
            target_path: Path to analyze
            output_format: SBOM format (spdx, cyclonedx, etc.)

        Returns:
            Path to generated SBOM file
        """
        if output_format not in self.supported_formats:
            raise ValueError(f"Unsupported SBOM format: {output_format}")

        logger.info(f"Generating {output_format} SBOM for: {target_path}")

        # Try to use Syft if available
        try:
            sbom_content = self._generate_with_syft(target_path, output_format)
            if sbom_content:
                return self._save_sbom(sbom_content, target_path, output_format)
        except FileNotFoundError:
            logger.warning("Syft not found, using built-in SBOM generation")

        # Fallback to basic SBOM generation
        sbom_content = self._generate_basic_sbom(target_path, output_format)
        return self._save_sbom(sbom_content, target_path, output_format)

    def _generate_with_syft(self, target_path: str, output_format: str) -> Optional[str]:
        """Generate SBOM using Syft tool."""
        format_mapping = {
            'spdx-json': 'spdx-json',
            'spdx': 'spdx',
            'cyclonedx-json': 'cyclonedx-json',
            'cyclonedx': 'cyclonedx-xml'
        }

        syft_format = format_mapping.get(output_format, 'spdx-json')

        try:
            result = subprocess.run(
                ['syft', 'scan', target_path, '-o', syft_format],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                return result.stdout
            else:
                logger.error(f"Syft failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("Syft scan timed out")
            return None

    def _generate_basic_sbom(self, target_path: str, output_format: str) -> str:
        """Generate a basic SBOM when external tools aren't available."""
        logger.info("Generating basic SBOM")

        if output_format in ['spdx', 'spdx-json']:
            return self._generate_spdx(target_path)
        else:
            return self._generate_cyclonedx(target_path)

    def _generate_spdx(self, target_path: str) -> str:
        """Generate SPDX SBOM format."""
        from irvs.utils.parsers import DependencyParser

        path = Path(target_path)

        spdx = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"SBOM for {path.name}",
            "documentNamespace": f"https://sbom.irvs/{uuid.uuid4()}",
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: IRVS-SBOM-Generator"],
                "licenseListVersion": "3.20"
            },
            "packages": [],
            "relationships": []
        }

        # Add main package information
        main_package = {
            "SPDXID": f"SPDXRef-Package-{path.name}",
            "name": path.name,
            "versionInfo": "unknown",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION"
        }

        spdx["packages"].append(main_package)

        # Parse actual dependencies from manifest files
        dependencies_found = 0

        # Check if target is a directory
        if path.is_dir():
            # Python dependencies
            req_file = path / 'requirements.txt'
            if req_file.exists():
                try:
                    deps = DependencyParser.parse_requirements_txt(req_file)
                    for dep in deps:
                        pkg_id = f"SPDXRef-Package-{dep.name}-{dep.version or 'unknown'}"
                        spdx["packages"].append({
                            "SPDXID": pkg_id,
                            "name": dep.name,
                            "versionInfo": dep.version or "NOASSERTION",
                            "downloadLocation": "NOASSERTION",
                            "filesAnalyzed": False,
                            "supplier": "NOASSERTION"
                        })
                        # Add dependency relationship
                        spdx["relationships"].append({
                            "spdxElementId": f"SPDXRef-Package-{path.name}",
                            "relationshipType": "DEPENDS_ON",
                            "relatedSpdxElement": pkg_id
                        })
                        dependencies_found += 1
                    logger.info(f"Added {len(deps)} Python dependencies from requirements.txt")
                except Exception as e:
                    logger.warning(f"Error parsing requirements.txt: {e}")

            # Node.js dependencies
            pkg_file = path / 'package.json'
            if pkg_file.exists():
                try:
                    prod_deps, dev_deps = DependencyParser.parse_package_json(pkg_file)
                    for dep in prod_deps + dev_deps:
                        pkg_id = f"SPDXRef-Package-{dep.name}-{dep.version or 'unknown'}"
                        spdx["packages"].append({
                            "SPDXID": pkg_id,
                            "name": dep.name,
                            "versionInfo": dep.version or "NOASSERTION",
                            "downloadLocation": "NOASSERTION",
                            "filesAnalyzed": False,
                            "supplier": "NOASSERTION"
                        })
                        spdx["relationships"].append({
                            "spdxElementId": f"SPDXRef-Package-{path.name}",
                            "relationshipType": "DEPENDS_ON" if not dep.is_dev else "DEV_DEPENDENCY_OF",
                            "relatedSpdxElement": pkg_id
                        })
                        dependencies_found += 1
                    logger.info(f"Added {len(prod_deps)} production and {len(dev_deps)} dev dependencies from package.json")
                except Exception as e:
                    logger.warning(f"Error parsing package.json: {e}")

            # Go dependencies
            go_mod = path / 'go.mod'
            if go_mod.exists():
                try:
                    deps = DependencyParser.parse_go_mod(go_mod)
                    for dep in deps:
                        pkg_id = f"SPDXRef-Package-{dep.name.replace('/', '-')}-{dep.version or 'unknown'}"
                        spdx["packages"].append({
                            "SPDXID": pkg_id,
                            "name": dep.name,
                            "versionInfo": dep.version or "NOASSERTION",
                            "downloadLocation": "NOASSERTION",
                            "filesAnalyzed": False,
                            "supplier": "NOASSERTION"
                        })
                        spdx["relationships"].append({
                            "spdxElementId": f"SPDXRef-Package-{path.name}",
                            "relationshipType": "DEPENDS_ON",
                            "relatedSpdxElement": pkg_id
                        })
                        dependencies_found += 1
                    logger.info(f"Added {len(deps)} Go dependencies from go.mod")
                except Exception as e:
                    logger.warning(f"Error parsing go.mod: {e}")

            # Rust dependencies
            cargo_toml = path / 'Cargo.toml'
            if cargo_toml.exists():
                try:
                    deps = DependencyParser.parse_cargo_toml(cargo_toml)
                    for dep in deps:
                        pkg_id = f"SPDXRef-Package-{dep.name}-{dep.version or 'unknown'}"
                        spdx["packages"].append({
                            "SPDXID": pkg_id,
                            "name": dep.name,
                            "versionInfo": dep.version or "NOASSERTION",
                            "downloadLocation": "NOASSERTION",
                            "filesAnalyzed": False,
                            "supplier": "NOASSERTION"
                        })
                        spdx["relationships"].append({
                            "spdxElementId": f"SPDXRef-Package-{path.name}",
                            "relationshipType": "DEPENDS_ON",
                            "relatedSpdxElement": pkg_id
                        })
                        dependencies_found += 1
                    logger.info(f"Added {len(deps)} Rust dependencies from Cargo.toml")
                except Exception as e:
                    logger.warning(f"Error parsing Cargo.toml: {e}")

        if dependencies_found == 0:
            logger.warning("No dependency files found or parsed. SBOM will only contain main package.")

        return json.dumps(spdx, indent=2)

    def _generate_cyclonedx(self, target_path: str) -> str:
        """Generate CycloneDX SBOM format."""
        from irvs.utils.parsers import DependencyParser

        path = Path(target_path)

        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "IRVS",
                        "name": "IRVS SBOM Generator",
                        "version": "0.1.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": path.name,
                    "version": "unknown"
                }
            },
            "components": []
        }

        # Parse actual dependencies from manifest files
        dependencies_found = 0

        if path.is_dir():
            # Python dependencies
            req_file = path / 'requirements.txt'
            if req_file.exists():
                try:
                    deps = DependencyParser.parse_requirements_txt(req_file)
                    for dep in deps:
                        cyclonedx["components"].append({
                            "type": "library",
                            "name": dep.name,
                            "version": dep.version or "unknown",
                            "purl": f"pkg:pypi/{dep.name}@{dep.version}" if dep.version else f"pkg:pypi/{dep.name}"
                        })
                        dependencies_found += 1
                    logger.info(f"Added {len(deps)} Python dependencies")
                except Exception as e:
                    logger.warning(f"Error parsing requirements.txt: {e}")

            # Node.js dependencies
            pkg_file = path / 'package.json'
            if pkg_file.exists():
                try:
                    prod_deps, dev_deps = DependencyParser.parse_package_json(pkg_file)
                    for dep in prod_deps + dev_deps:
                        cyclonedx["components"].append({
                            "type": "library",
                            "name": dep.name,
                            "version": dep.version or "unknown",
                            "purl": f"pkg:npm/{dep.name}@{dep.version}" if dep.version else f"pkg:npm/{dep.name}"
                        })
                        dependencies_found += 1
                    logger.info(f"Added {len(prod_deps + dev_deps)} npm dependencies")
                except Exception as e:
                    logger.warning(f"Error parsing package.json: {e}")

            # Go dependencies
            go_mod = path / 'go.mod'
            if go_mod.exists():
                try:
                    deps = DependencyParser.parse_go_mod(go_mod)
                    for dep in deps:
                        cyclonedx["components"].append({
                            "type": "library",
                            "name": dep.name,
                            "version": dep.version or "unknown",
                            "purl": f"pkg:golang/{dep.name}@{dep.version}" if dep.version else f"pkg:golang/{dep.name}"
                        })
                        dependencies_found += 1
                    logger.info(f"Added {len(deps)} Go dependencies")
                except Exception as e:
                    logger.warning(f"Error parsing go.mod: {e}")

            # Rust dependencies
            cargo_toml = path / 'Cargo.toml'
            if cargo_toml.exists():
                try:
                    deps = DependencyParser.parse_cargo_toml(cargo_toml)
                    for dep in deps:
                        cyclonedx["components"].append({
                            "type": "library",
                            "name": dep.name,
                            "version": dep.version or "unknown",
                            "purl": f"pkg:cargo/{dep.name}@{dep.version}" if dep.version else f"pkg:cargo/{dep.name}"
                        })
                        dependencies_found += 1
                    logger.info(f"Added {len(deps)} Rust dependencies")
                except Exception as e:
                    logger.warning(f"Error parsing Cargo.toml: {e}")

        if dependencies_found == 0:
            logger.warning("No dependency files found or parsed. SBOM will only contain main component.")

        return json.dumps(cyclonedx, indent=2)

    def _save_sbom(self, content: str, target_path: str, output_format: str) -> str:
        """Save SBOM to file."""
        path = Path(target_path)
        ext_mapping = {
            'spdx': '.spdx',
            'spdx-json': '.spdx.json',
            'cyclonedx': '.cdx.xml',
            'cyclonedx-json': '.cdx.json'
        }

        extension = ext_mapping.get(output_format, '.sbom.json')
        output_file = path.parent / f"{path.name}{extension}"

        output_file.write_text(content)
        logger.info(f"SBOM saved to: {output_file}")

        return str(output_file)

    def verify(self, sbom_path: str) -> VerificationResult:
        """
        Verify and validate an SBOM.

        Args:
            sbom_path: Path to SBOM file

        Returns:
            VerificationResult with findings
        """
        result = VerificationResult()
        path = Path(sbom_path)

        if not path.exists():
            result.add_finding(Finding(
                severity=Severity.CRITICAL,
                category="sbom",
                title="SBOM File Not Found",
                description=f"SBOM file does not exist: {sbom_path}"
            ))
            return result

        logger.info(f"Verifying SBOM: {sbom_path}")

        try:
            content = path.read_text()
            data = json.loads(content)

            # Detect SBOM format
            if 'spdxVersion' in data:
                findings = self._verify_spdx(data, path)
            elif 'bomFormat' in data and data['bomFormat'] == 'CycloneDX':
                findings = self._verify_cyclonedx(data, path)
            else:
                result.add_finding(Finding(
                    severity=Severity.HIGH,
                    category="sbom",
                    title="Unknown SBOM Format",
                    description="SBOM format could not be determined",
                    affected_component=str(path)
                ))
                return result

            result.findings.extend(findings)

        except json.JSONDecodeError as e:
            result.add_finding(Finding(
                severity=Severity.HIGH,
                category="sbom",
                title="Invalid SBOM JSON",
                description=f"SBOM is not valid JSON: {str(e)}",
                affected_component=str(path)
            ))
        except Exception as e:
            result.add_finding(Finding(
                severity=Severity.MEDIUM,
                category="sbom",
                title="SBOM Verification Error",
                description=f"Error verifying SBOM: {str(e)}",
                affected_component=str(path)
            ))

        return result

    def _verify_spdx(self, data: Dict[str, Any], sbom_path: Path) -> list[Finding]:
        """Verify SPDX SBOM."""
        findings = []

        # Check required fields
        required_fields = ['spdxVersion', 'dataLicense', 'SPDXID', 'name', 'documentNamespace', 'creationInfo']

        for field in required_fields:
            if field not in data:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="sbom",
                    title=f"Missing SPDX Field: {field}",
                    description=f"Required SPDX field '{field}' is missing",
                    affected_component=str(sbom_path)
                ))

        # Check SPDX version
        if 'spdxVersion' in data:
            version = data['spdxVersion']
            if not version.startswith('SPDX-'):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category="sbom",
                    title="Invalid SPDX Version Format",
                    description=f"SPDX version format is invalid: {version}",
                    affected_component=str(sbom_path)
                ))

        # Check for packages
        packages = data.get('packages', [])
        if not packages:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="sbom",
                title="No Packages in SBOM",
                description="SBOM contains no package information",
                affected_component=str(sbom_path)
            ))

        # Validate package entries
        for idx, package in enumerate(packages):
            if 'name' not in package:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category="sbom",
                    title=f"Package Missing Name (index {idx})",
                    description="Package entry is missing required 'name' field",
                    affected_component=str(sbom_path),
                    metadata={"package_index": idx}
                ))

        return findings

    def _verify_cyclonedx(self, data: Dict[str, Any], sbom_path: Path) -> list[Finding]:
        """Verify CycloneDX SBOM."""
        findings = []

        # Check required fields
        required_fields = ['bomFormat', 'specVersion', 'version']

        for field in required_fields:
            if field not in data:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="sbom",
                    title=f"Missing CycloneDX Field: {field}",
                    description=f"Required CycloneDX field '{field}' is missing",
                    affected_component=str(sbom_path)
                ))

        # Verify bomFormat
        if data.get('bomFormat') != 'CycloneDX':
            findings.append(Finding(
                severity=Severity.HIGH,
                category="sbom",
                title="Invalid BOM Format",
                description=f"Expected 'CycloneDX', got '{data.get('bomFormat')}'",
                affected_component=str(sbom_path)
            ))

        # Check for components
        components = data.get('components', [])
        metadata_component = data.get('metadata', {}).get('component')

        if not components and not metadata_component:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="sbom",
                title="No Components in SBOM",
                description="SBOM contains no component information",
                affected_component=str(sbom_path)
            ))

        return findings
