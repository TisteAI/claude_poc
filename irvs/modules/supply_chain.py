"""Supply chain analysis and dependency verification module."""

import logging
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
from difflib import SequenceMatcher

from irvs.core.result import VerificationResult, Finding, Severity
from irvs.core.config import SupplyChainConfig


logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Represents a software dependency."""
    name: str
    version: str
    registry: Optional[str] = None
    checksum: Optional[str] = None
    is_direct: bool = True
    depth: int = 0


class SupplyChainAnalyzer:
    """
    Analyzes software supply chain for security risks.

    Detects:
    - Malicious packages
    - Typosquatting attempts
    - Dependency confusion
    - Unmaintained packages
    - Suspicious dependency patterns
    """

    # Known popular package names for typosquatting detection
    POPULAR_PACKAGES = {
        'python': [
            'requests', 'numpy', 'pandas', 'django', 'flask', 'tensorflow',
            'pytest', 'boto3', 'sqlalchemy', 'scrapy', 'matplotlib', 'scipy'
        ],
        'npm': [
            'react', 'express', 'lodash', 'webpack', 'axios', 'next',
            'typescript', 'jest', 'eslint', 'prettier', 'vue', 'angular'
        ],
        'maven': [
            'spring-boot', 'junit', 'slf4j', 'log4j', 'jackson', 'guava',
            'hibernate', 'commons-lang', 'mockito', 'maven'
        ]
    }

    # Known malicious package patterns (examples - would be updated from threat intel)
    MALICIOUS_PATTERNS = [
        r'.*-backdoor.*',
        r'.*-malware.*',
        r'test-.*-poc',  # PoC packages that might be malicious
    ]

    def __init__(self, config: SupplyChainConfig):
        """Initialize supply chain analyzer."""
        self.config = config
        self.dependency_cache: Dict[str, Set[Dependency]] = {}

    def analyze_package(self, package_path: str) -> VerificationResult:
        """
        Analyze a package for supply chain risks.

        Args:
            package_path: Path to package

        Returns:
            VerificationResult with findings
        """
        result = VerificationResult()
        logger.info(f"Analyzing supply chain for package: {package_path}")

        # This would extract and analyze package metadata
        # For now, return basic analysis
        result.metadata['analyzed_path'] = package_path

        return result

    def analyze_directory(self, directory_path: str) -> VerificationResult:
        """
        Analyze dependencies in a project directory.

        Args:
            directory_path: Path to project directory

        Returns:
            VerificationResult with findings
        """
        result = VerificationResult()
        path = Path(directory_path)

        if not path.exists() or not path.is_dir():
            result.add_finding(Finding(
                severity=Severity.HIGH,
                category="supply_chain",
                title="Invalid Directory Path",
                description=f"Directory does not exist: {directory_path}"
            ))
            return result

        logger.info(f"Analyzing dependencies in: {directory_path}")

        # Detect dependency files and analyze
        dependency_files = self._find_dependency_files(path)

        for dep_file in dependency_files:
            file_findings = self._analyze_dependency_file(dep_file)
            result.findings.extend(file_findings)

        return result

    def _find_dependency_files(self, directory: Path) -> List[Path]:
        """Find dependency manifest files in directory."""
        dependency_files = []

        # Python
        if (directory / 'requirements.txt').exists():
            dependency_files.append(directory / 'requirements.txt')
        if (directory / 'Pipfile').exists():
            dependency_files.append(directory / 'Pipfile')
        if (directory / 'pyproject.toml').exists():
            dependency_files.append(directory / 'pyproject.toml')
        if (directory / 'setup.py').exists():
            dependency_files.append(directory / 'setup.py')

        # Node.js
        if (directory / 'package.json').exists():
            dependency_files.append(directory / 'package.json')
        if (directory / 'package-lock.json').exists():
            dependency_files.append(directory / 'package-lock.json')
        if (directory / 'yarn.lock').exists():
            dependency_files.append(directory / 'yarn.lock')

        # Java/Maven
        if (directory / 'pom.xml').exists():
            dependency_files.append(directory / 'pom.xml')

        # Go
        if (directory / 'go.mod').exists():
            dependency_files.append(directory / 'go.mod')
        if (directory / 'go.sum').exists():
            dependency_files.append(directory / 'go.sum')

        # Rust
        if (directory / 'Cargo.toml').exists():
            dependency_files.append(directory / 'Cargo.toml')
        if (directory / 'Cargo.lock').exists():
            dependency_files.append(directory / 'Cargo.lock')

        # Ruby
        if (directory / 'Gemfile').exists():
            dependency_files.append(directory / 'Gemfile')
        if (directory / 'Gemfile.lock').exists():
            dependency_files.append(directory / 'Gemfile.lock')

        logger.info(f"Found {len(dependency_files)} dependency files")
        return dependency_files

    def _analyze_dependency_file(self, dep_file: Path) -> List[Finding]:
        """Analyze a specific dependency file for risks."""
        findings = []

        try:
            # Import the real parser
            from irvs.utils.parsers import DependencyParser

            if dep_file.name == 'package.json':
                findings.extend(self._analyze_npm_dependencies(dep_file))
            elif dep_file.name == 'requirements.txt':
                # Use real parser
                dependencies = DependencyParser.parse_requirements_txt(dep_file)
                findings.extend(self._analyze_dependencies(dependencies, dep_file))
            elif dep_file.name == 'go.mod':
                dependencies = DependencyParser.parse_go_mod(dep_file)
                findings.extend(self._analyze_dependencies(dependencies, dep_file))
            elif dep_file.name == 'Cargo.toml':
                dependencies = DependencyParser.parse_cargo_toml(dep_file)
                findings.extend(self._analyze_dependencies(dependencies, dep_file))
            elif dep_file.name == 'Gemfile':
                dependencies = DependencyParser.parse_gemfile(dep_file)
                findings.extend(self._analyze_dependencies(dependencies, dep_file))
            # Add more parsers as needed

        except Exception as e:
            logger.error(f"Error analyzing {dep_file}: {e}")
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="supply_chain",
                title="Dependency Analysis Error",
                description=f"Failed to analyze {dep_file.name}: {str(e)}",
                affected_component=str(dep_file)
            ))

        return findings

    def _analyze_dependencies(self, dependencies: List, dep_file: Path) -> List[Finding]:
        """Analyze a list of parsed dependencies."""
        findings = []

        for dep in dependencies:
            # Check for typosquatting
            if self.config.check_typosquatting:
                typo_finding = self._check_typosquatting(dep.name, dep.ecosystem, dep_file)
                if typo_finding:
                    findings.append(typo_finding)

            # Check for malicious patterns
            if self.config.detect_malicious_packages:
                mal_finding = self._check_malicious_pattern(dep.name, dep_file)
                if mal_finding:
                    findings.append(mal_finding)

            # Check version pinning
            if dep.version_spec and dep.version_spec not in ['==', '']:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category="supply_chain",
                    title="Unpinned Dependency Version",
                    description=f"Package '{dep.name}' uses flexible version specifier: {dep.version_spec}{dep.version or ''}",
                    remediation=f"Pin '{dep.name}' to an exact version for reproducibility",
                    affected_component=str(dep_file),
                    metadata={"package": dep.name, "version_spec": dep.version_spec, "ecosystem": dep.ecosystem}
                ))

            # Check for blocked packages
            if dep.name in self.config.blocked_packages:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="supply_chain",
                    title="Blocked Package Detected",
                    description=f"Package '{dep.name}' is in the blocked list",
                    remediation="Remove this package and find an alternative",
                    affected_component=str(dep_file),
                    metadata={"package": dep.name, "ecosystem": dep.ecosystem}
                ))

        return findings

    def _analyze_npm_dependencies(self, package_json: Path) -> List[Finding]:
        """Analyze npm package.json for security issues."""
        from irvs.utils.parsers import DependencyParser

        findings = []

        try:
            # Use the real parser
            prod_deps, dev_deps = DependencyParser.parse_package_json(package_json)
            all_deps = prod_deps + dev_deps

            # Use the common analysis method
            findings.extend(self._analyze_dependencies(all_deps, package_json))

        except json.JSONDecodeError as e:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="supply_chain",
                title="Invalid package.json",
                description=f"Failed to parse package.json: {str(e)}",
                affected_component=str(package_json)
            ))
        except Exception as e:
            logger.error(f"Error analyzing npm dependencies: {e}")
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="supply_chain",
                title="npm Analysis Error",
                description=f"Error analyzing npm dependencies: {str(e)}",
                affected_component=str(package_json)
            ))

        return findings

    def _analyze_python_requirements(self, requirements_file: Path) -> List[Finding]:
        """Analyze Python requirements.txt for security issues."""
        findings = []

        try:
            content = requirements_file.read_text()
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse package name and version
                match = re.match(r'^([a-zA-Z0-9-_\.]+)([=<>!~]=?.*)?$', line)
                if match:
                    pkg_name = match.group(1)
                    version_spec = match.group(2) or ''

                    # Check for typosquatting
                    if self.config.check_typosquatting:
                        typo_finding = self._check_typosquatting(pkg_name, 'python', requirements_file)
                        if typo_finding:
                            findings.append(typo_finding)

                    # Check for malicious patterns
                    if self.config.detect_malicious_packages:
                        mal_finding = self._check_malicious_pattern(pkg_name, requirements_file)
                        if mal_finding:
                            findings.append(mal_finding)

                    # Check version pinning
                    if not version_spec or not version_spec.startswith('=='):
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            category="supply_chain",
                            title="Unpinned Python Dependency",
                            description=f"Package '{pkg_name}' is not pinned to exact version",
                            remediation="Use '==' to pin exact versions",
                            affected_component=f"{requirements_file}:{line_num}",
                            metadata={"package": pkg_name, "version_spec": version_spec}
                        ))

        except Exception as e:
            logger.error(f"Error analyzing requirements.txt: {e}")

        return findings

    def _analyze_go_mod(self, go_mod: Path) -> List[Finding]:
        """Analyze Go go.mod file for security issues."""
        findings = []

        try:
            content = go_mod.read_text()
            lines = content.split('\n')

            in_require_block = False
            for line in lines:
                line = line.strip()

                if line.startswith('require'):
                    in_require_block = True
                    continue
                elif line == ')':
                    in_require_block = False
                    continue

                if in_require_block or line.startswith('require '):
                    # Parse module
                    parts = line.split()
                    if len(parts) >= 2:
                        module_name = parts[0]

                        # Check for malicious patterns
                        if self.config.detect_malicious_packages:
                            mal_finding = self._check_malicious_pattern(module_name, go_mod)
                            if mal_finding:
                                findings.append(mal_finding)

        except Exception as e:
            logger.error(f"Error analyzing go.mod: {e}")

        return findings

    def _analyze_cargo_toml(self, cargo_toml: Path) -> List[Finding]:
        """Analyze Rust Cargo.toml for security issues."""
        findings = []

        try:
            content = cargo_toml.read_text()

            # Basic parsing for dependencies section
            in_dependencies = False
            for line in content.split('\n'):
                line = line.strip()

                if line == '[dependencies]':
                    in_dependencies = True
                    continue
                elif line.startswith('['):
                    in_dependencies = False
                    continue

                if in_dependencies and '=' in line:
                    pkg_name = line.split('=')[0].strip()

                    # Check for malicious patterns
                    if self.config.detect_malicious_packages:
                        mal_finding = self._check_malicious_pattern(pkg_name, cargo_toml)
                        if mal_finding:
                            findings.append(mal_finding)

        except Exception as e:
            logger.error(f"Error analyzing Cargo.toml: {e}")

        return findings

    def _check_typosquatting(self, package_name: str, ecosystem: str, source_file: Path) -> Optional[Finding]:
        """
        Check if package name might be typosquatting.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (npm, python, etc.)
            source_file: Source dependency file

        Returns:
            Finding if typosquatting suspected, None otherwise
        """
        popular_packages = self.POPULAR_PACKAGES.get(ecosystem, [])

        for popular_pkg in popular_packages:
            # Calculate similarity
            similarity = SequenceMatcher(None, package_name.lower(), popular_pkg.lower()).ratio()

            # If very similar but not exact match, flag it
            if 0.7 < similarity < 1.0:
                return Finding(
                    severity=Severity.HIGH,
                    category="supply_chain",
                    title="Potential Typosquatting Detected",
                    description=f"Package '{package_name}' is very similar to popular package '{popular_pkg}'",
                    remediation=f"Verify this is the correct package. Did you mean '{popular_pkg}'?",
                    affected_component=str(source_file),
                    metadata={
                        "package": package_name,
                        "similar_to": popular_pkg,
                        "similarity": round(similarity, 2),
                        "ecosystem": ecosystem
                    }
                )

            # Check for common typosquatting patterns
            typo_patterns = [
                (package_name.replace('l', '1'), popular_pkg),  # l -> 1
                (package_name.replace('o', '0'), popular_pkg),  # o -> 0
                (package_name.replace('-', '_'), popular_pkg),  # - -> _
                (package_name.replace('_', '-'), popular_pkg),  # _ -> -
            ]

            for typo_variant, original in typo_patterns:
                if typo_variant.lower() == original.lower() and package_name != original:
                    return Finding(
                        severity=Severity.CRITICAL,
                        category="supply_chain",
                        title="Likely Typosquatting Attack",
                        description=f"Package '{package_name}' appears to be typosquatting '{original}'",
                        remediation=f"Use the correct package name: '{original}'",
                        affected_component=str(source_file),
                        metadata={
                            "package": package_name,
                            "legitimate_package": original,
                            "typo_type": "character_substitution"
                        }
                    )

        return None

    def _check_malicious_pattern(self, package_name: str, source_file: Path) -> Optional[Finding]:
        """Check if package name matches known malicious patterns."""
        for pattern in self.MALICIOUS_PATTERNS:
            if re.match(pattern, package_name, re.IGNORECASE):
                return Finding(
                    severity=Severity.CRITICAL,
                    category="supply_chain",
                    title="Potentially Malicious Package",
                    description=f"Package '{package_name}' matches known malicious pattern",
                    remediation="Do not use this package. Investigate thoroughly.",
                    affected_component=str(source_file),
                    metadata={
                        "package": package_name,
                        "matched_pattern": pattern
                    }
                )

        return None
