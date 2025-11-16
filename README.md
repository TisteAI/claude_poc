# Infrastructure Resilience Verification System (IRVS)

A comprehensive security tool for package and development pipeline verification designed for critical governmental software infrastructure.

## Overview

IRVS (Infrastructure Resilience Verification System) provides meticulous verification of software packages, development pipelines, and supply chain security to help governmental and critical infrastructure organizations stay ahead of sophisticated cyber threats.

## Features

### Core Capabilities

- **Package Integrity Verification**
  - Cryptographic signature validation (GPG/PGP, Sigstore/Cosign)
  - Checksum verification (SHA-256, SHA-512)
  - SBOM (Software Bill of Materials) validation
  - Reproducible build verification

- **CI/CD Pipeline Security**
  - GitHub Actions, GitLab CI, Jenkins analysis
  - Secret detection and exposure prevention
  - Permission and access control auditing
  - Dependency pinning verification
  - Third-party action security checks

- **Supply Chain Analysis**
  - Complete dependency graph construction
  - Malicious package detection
  - Typosquatting identification
  - Dependency confusion prevention
  - Unmaintained package detection

- **Vulnerability Assessment**
  - Integration with NVD, OSV, GitHub Security Advisories
  - CVE database correlation
  - CVSS scoring and prioritization
  - Exploitability analysis
  - Patch availability tracking

- **Provenance Verification**
  - SLSA (Supply-chain Levels for Software Artifacts) compliance
  - Build provenance attestation verification
  - Source integrity validation
  - in-toto framework support

- **Policy Engine**
  - Declarative security policies
  - Compliance templates (NIST, FedRAMP, FISMA)
  - Custom policy creation
  - Automated enforcement
  - Violation reporting

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system architecture documentation.

## Installation

### Prerequisites

- Python 3.8 or higher
- pip or pipenv

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/irvs.git
cd irvs

# Install dependencies
pip install -r requirements.txt

# Install IRVS
pip install -e .
```

### Optional External Tools

For enhanced functionality, install these optional tools:

```bash
# Syft - SBOM generation
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Grype - Vulnerability scanning
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Trivy - Security scanner
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Cosign - Signature verification
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
```

## Quick Start

### Initialize Configuration

```bash
# Create default configuration
irvs init-config config.yaml
```

### Verify a Package

```bash
# Verify package integrity and security
irvs verify-package /path/to/package.tar.gz

# With custom configuration
irvs --config config.yaml verify-package package.tar.gz

# Output to JSON file
irvs verify-package package.tar.gz --format json --output results.json
```

### Scan CI/CD Pipeline

```bash
# Scan GitHub Actions workflows
irvs verify-pipeline .github/workflows

# Scan GitLab CI
irvs verify-pipeline .gitlab-ci.yml
```

### Full Security Scan

```bash
# Comprehensive scan of entire project
irvs full-scan /path/to/project

# Results in SARIF format for tool integration
irvs full-scan . --format sarif --output results.sarif
```

### Generate SBOM

```bash
# Generate SPDX SBOM
irvs generate-sbom /path/to/project --format spdx-json

# Generate CycloneDX SBOM
irvs generate-sbom /path/to/project --format cyclonedx-json
```

### Verify Provenance

```bash
# Verify SLSA provenance
irvs verify-provenance artifact.tar.gz --provenance artifact.tar.gz.provenance.json
```

## Configuration

IRVS supports both YAML and JSON configuration files. See example configurations:

- [config/default.yaml](config/default.yaml) - Default settings
- [config/strict.yaml](config/strict.yaml) - High-security governmental settings

### Configuration Options

```yaml
# Policy engine
policy:
  enabled: true
  policy_dir: "policies"
  fail_on_policy_violation: true

# Package verification
package_verification:
  verify_signatures: true
  verify_checksums: true
  require_sbom: true

# Vulnerability scanning
vulnerability:
  enabled: true
  fail_on_critical: true
  fail_on_high: true

# Provenance verification
provenance:
  enabled: true
  require_slsa_level: 2

# Supply chain analysis
supply_chain:
  analyze_dependencies: true
  check_typosquatting: true
  detect_malicious_packages: true
```

## Security Policies

IRVS includes built-in security policies aligned with governmental compliance standards:

- NIST SP 800-53 - Security and Privacy Controls
- NIST SP 800-161 - Cybersecurity Supply Chain Risk Management
- FedRAMP - Federal Risk and Authorization Management Program
- FISMA - Federal Information Security Management Act
- Executive Order 14028 - Improving the Nation's Cybersecurity

Custom policies can be defined in YAML format. See [policies/default.yaml](policies/default.yaml) for examples.

## Compliance Standards

IRVS helps organizations meet various compliance requirements:

- **NIST SP 800-53**: Security and privacy controls
- **NIST SP 800-161**: Supply chain risk management
- **FedRAMP**: Federal cloud security
- **FISMA**: Federal information security
- **Executive Order 14028**: Cybersecurity improvements
- **SLSA Level 3+**: Supply chain security levels

## CLI Commands

### Main Commands

- `irvs verify-package` - Verify package integrity and security
- `irvs verify-pipeline` - Scan CI/CD pipeline configurations
- `irvs verify-provenance` - Verify build provenance
- `irvs verify-sbom` - Validate Software Bill of Materials
- `irvs full-scan` - Comprehensive security scan
- `irvs generate-sbom` - Generate SBOM
- `irvs init-config` - Initialize configuration file

### Global Options

- `--config, -c` - Path to configuration file
- `--log-level` - Set logging level (DEBUG, INFO, WARNING, ERROR)
- `--help` - Show help message

## Output Formats

IRVS supports multiple output formats:

- **text** - Human-readable text output (default)
- **json** - Machine-readable JSON
- **sarif** - SARIF format for CI/CD integration

## Integration

### CI/CD Integration

#### GitHub Actions

```yaml
- name: Security Verification
  run: |
    pip install irvs
    irvs full-scan . --format sarif --output results.sarif

- name: Upload Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

#### GitLab CI

```yaml
security_scan:
  script:
    - pip install irvs
    - irvs full-scan . --format json --output results.json
  artifacts:
    reports:
      security: results.json
```

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=irvs --cov-report=html
```

### Code Quality

```bash
# Format code
black irvs/

# Lint
flake8 irvs/

# Type checking
mypy irvs/
```

## Threat Model

IRVS protects against:

- Compromised dependencies and supply chain attacks
- Malicious packages and typosquatting
- Build system compromise
- Source code tampering
- Artifact substitution
- Dependency confusion attacks
- Pipeline injection attacks
- Exposed secrets and credentials

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Security

For security issues, please see [SECURITY.md](SECURITY.md).

## Support

- Documentation: [docs/](docs/)
- Issues: GitHub Issues
- Security: security@example.gov

## Acknowledgments

IRVS integrates with and builds upon excellent open-source security tools:

- [Syft](https://github.com/anchore/syft) - SBOM generation
- [Grype](https://github.com/anchore/grype) - Vulnerability scanning
- [Trivy](https://github.com/aquasecurity/trivy) - Security scanning
- [Sigstore](https://www.sigstore.dev/) - Keyless signing
- [SLSA](https://slsa.dev/) - Supply chain framework
- [in-toto](https://in-toto.io/) - Supply chain integrity
