"""Dependency file parsers for various package ecosystems."""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Represents a parsed dependency."""
    name: str
    version: Optional[str] = None
    version_spec: Optional[str] = None  # e.g., >=, ==, ~=
    extras: List[str] = None
    is_dev: bool = False
    ecosystem: str = "unknown"

    def __post_init__(self):
        if self.extras is None:
            self.extras = []


class DependencyParser:
    """Parse dependency files from various package ecosystems."""

    @staticmethod
    def parse_requirements_txt(file_path: Path) -> List[Dependency]:
        """
        Parse Python requirements.txt file.

        Handles:
        - Simple packages: package-name==1.0.0
        - Version specifiers: package>=1.0.0,<2.0.0
        - Extras: package[extra1,extra2]==1.0.0
        - Comments and blank lines
        - -e editable installs
        - -r includes (recursive)
        """
        dependencies = []

        try:
            content = file_path.read_text()
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                # Remove comments
                line = line.split('#')[0].strip()

                # Skip empty lines
                if not line:
                    continue

                # Skip -r includes for now (would need recursive parsing)
                if line.startswith('-r '):
                    logger.debug(f"Skipping -r include: {line}")
                    continue

                # Handle -e editable installs
                if line.startswith('-e '):
                    line = line[3:].strip()

                # Parse the dependency
                dep = DependencyParser._parse_python_requirement(line)
                if dep:
                    dep.ecosystem = "python"
                    dependencies.append(dep)
                else:
                    logger.warning(f"Could not parse line {line_num}: {line}")

        except Exception as e:
            logger.error(f"Error parsing requirements.txt: {e}")

        return dependencies

    @staticmethod
    def _parse_python_requirement(requirement: str) -> Optional[Dependency]:
        """Parse a single Python requirement string."""
        # Pattern: package_name[extras]==version or package_name>=version
        # Handles: name, name[extra], name==1.0, name>=1.0,<2.0

        # Extract extras if present
        extras = []
        if '[' in requirement and ']' in requirement:
            match = re.match(r'^([a-zA-Z0-9_-]+)\[([^\]]+)\](.*)$', requirement)
            if match:
                name = match.group(1)
                extras = [e.strip() for e in match.group(2).split(',')]
                version_part = match.group(3)
            else:
                return None
        else:
            # No extras
            # Split on version specifiers
            match = re.match(r'^([a-zA-Z0-9_-]+)(.*)$', requirement)
            if match:
                name = match.group(1)
                version_part = match.group(2)
            else:
                return None

        # Parse version specifier
        version = None
        version_spec = None

        if version_part:
            version_part = version_part.strip()
            # Try to extract version specifier
            spec_match = re.match(r'^([=<>!~]+)(.+)$', version_part)
            if spec_match:
                version_spec = spec_match.group(1)
                version = spec_match.group(2).strip()
            else:
                # No specifier, just version
                version = version_part

        return Dependency(
            name=name,
            version=version,
            version_spec=version_spec,
            extras=extras,
            ecosystem="python"
        )

    @staticmethod
    def parse_package_json(file_path: Path) -> Tuple[List[Dependency], List[Dependency]]:
        """
        Parse Node.js package.json file.

        Returns:
            Tuple of (production_deps, dev_deps)
        """
        prod_deps = []
        dev_deps = []

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Parse production dependencies
            dependencies = data.get('dependencies', {})
            for name, version in dependencies.items():
                prod_deps.append(Dependency(
                    name=name,
                    version=DependencyParser._clean_npm_version(version),
                    version_spec=DependencyParser._get_npm_version_spec(version),
                    is_dev=False,
                    ecosystem="npm"
                ))

            # Parse dev dependencies
            dev_dependencies = data.get('devDependencies', {})
            for name, version in dev_dependencies.items():
                dev_deps.append(Dependency(
                    name=name,
                    version=DependencyParser._clean_npm_version(version),
                    version_spec=DependencyParser._get_npm_version_spec(version),
                    is_dev=True,
                    ecosystem="npm"
                ))

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in package.json: {e}")
        except Exception as e:
            logger.error(f"Error parsing package.json: {e}")

        return prod_deps, dev_deps

    @staticmethod
    def _clean_npm_version(version_str: str) -> str:
        """Extract clean version from npm version string."""
        # Remove ^, ~, >=, etc.
        return re.sub(r'^[^0-9]*', '', version_str)

    @staticmethod
    def _get_npm_version_spec(version_str: str) -> Optional[str]:
        """Extract version specifier from npm version string."""
        if version_str.startswith('^'):
            return '^'
        elif version_str.startswith('~'):
            return '~'
        elif version_str.startswith('>='):
            return '>='
        elif version_str.startswith('<='):
            return '<='
        elif version_str.startswith('>'):
            return '>'
        elif version_str.startswith('<'):
            return '<'
        elif version_str == '*' or version_str == 'latest':
            return '*'
        return None

    @staticmethod
    def parse_go_mod(file_path: Path) -> List[Dependency]:
        """Parse Go go.mod file."""
        dependencies = []

        try:
            content = file_path.read_text()
            lines = content.split('\n')

            in_require_block = False

            for line in lines:
                line = line.strip()

                # Start of require block
                if line.startswith('require ('):
                    in_require_block = True
                    continue

                # End of require block
                if in_require_block and line == ')':
                    in_require_block = False
                    continue

                # Parse require line
                if in_require_block or line.startswith('require '):
                    # Remove 'require' keyword
                    line = re.sub(r'^require\s+', '', line)

                    # Parse module and version
                    parts = line.split()
                    if len(parts) >= 2:
                        module = parts[0]
                        version = parts[1]

                        dependencies.append(Dependency(
                            name=module,
                            version=version,
                            ecosystem="go"
                        ))

        except Exception as e:
            logger.error(f"Error parsing go.mod: {e}")

        return dependencies

    @staticmethod
    def parse_cargo_toml(file_path: Path) -> List[Dependency]:
        """Parse Rust Cargo.toml file (basic parsing)."""
        dependencies = []

        try:
            content = file_path.read_text()
            lines = content.split('\n')

            in_dependencies = False

            for line in lines:
                line = line.strip()

                # Detect dependencies section
                if line == '[dependencies]':
                    in_dependencies = True
                    continue
                elif line.startswith('[') and line != '[dependencies]':
                    in_dependencies = False
                    continue

                # Parse dependency
                if in_dependencies and '=' in line:
                    parts = line.split('=', 1)
                    name = parts[0].strip()
                    version_part = parts[1].strip().strip('"').strip("'")

                    # Handle simple version
                    if version_part and not version_part.startswith('{'):
                        dependencies.append(Dependency(
                            name=name,
                            version=version_part,
                            ecosystem="rust"
                        ))

        except Exception as e:
            logger.error(f"Error parsing Cargo.toml: {e}")

        return dependencies

    @staticmethod
    def parse_pom_xml(file_path: Path) -> List[Dependency]:
        """Parse Maven pom.xml file using proper XML parsing."""
        import xml.etree.ElementTree as ET

        dependencies = []

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Maven uses namespaces, so we need to handle that
            # Default namespace for Maven POM
            namespace = {'mvn': 'http://maven.apache.org/POM/4.0.0'}

            # Try without namespace first (some POMs don't use it)
            deps_elem = root.find('.//dependencies')
            if deps_elem is None:
                # Try with namespace
                deps_elem = root.find('.//mvn:dependencies', namespace)

            if deps_elem is not None:
                # Find all dependency elements
                dep_elements = deps_elem.findall('.//dependency')
                if not dep_elements:
                    # Try with namespace
                    dep_elements = deps_elem.findall('.//mvn:dependency', namespace)

                for dep in dep_elements:
                    # Extract groupId, artifactId, version
                    group_id = dep.find('groupId')
                    if group_id is None:
                        group_id = dep.find('mvn:groupId', namespace)

                    artifact_id = dep.find('artifactId')
                    if artifact_id is None:
                        artifact_id = dep.find('mvn:artifactId', namespace)

                    version = dep.find('version')
                    if version is None:
                        version = dep.find('mvn:version', namespace)

                    # Extract text values
                    if group_id is not None and artifact_id is not None:
                        group_text = group_id.text.strip() if group_id.text else ''
                        artifact_text = artifact_id.text.strip() if artifact_id.text else ''
                        version_text = version.text.strip() if version is not None and version.text else None

                        # Skip if version is a property reference like ${some.version}
                        if version_text and version_text.startswith('${'):
                            version_text = None  # Can't resolve properties without full POM context

                        # Maven uses groupId:artifactId as package name
                        name = f"{group_text}:{artifact_text}"

                        dependencies.append(Dependency(
                            name=name,
                            version=version_text,
                            ecosystem="maven"
                        ))

            logger.debug(f"Parsed {len(dependencies)} dependencies from pom.xml")

        except ET.ParseError as e:
            logger.error(f"XML parse error in pom.xml: {e}")
        except Exception as e:
            logger.error(f"Error parsing pom.xml: {e}")

        return dependencies

    @staticmethod
    def parse_gemfile(file_path: Path) -> List[Dependency]:
        """Parse Ruby Gemfile (basic parsing)."""
        dependencies = []

        try:
            content = file_path.read_text()
            lines = content.split('\n')

            for line in lines:
                line = line.strip()

                # Match gem 'name', 'version'
                match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
                if match:
                    name = match.group(1)
                    version = match.group(2) if match.group(2) else None

                    dependencies.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem="ruby"
                    ))

        except Exception as e:
            logger.error(f"Error parsing Gemfile: {e}")

        return dependencies
