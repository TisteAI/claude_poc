# CLAUDE.MD - IRVS Project Guide

## Project Overview

**IRVS (Infrastructure Resilience Verification System)** is a production-ready security verification system designed for critical governmental software infrastructure. It's a comprehensive Python tool that detects and prevents supply chain security threats through package verification, CI/CD pipeline analysis, vulnerability scanning, and compliance enforcement.

**Version:** 0.1.0
**Status:** Production Ready
**License:** Apache 2.0
**Python:** 3.8+

## Quick Stats

- **Total Lines of Code:** ~4,550+ Python LOC
- **Modules:** 7 security verification modules
- **Policies:** 13 built-in security policies
- **Test Coverage:** 12/12 tests passing
- **Supported Ecosystems:** Python, npm, Go, Rust, Ruby, Maven

## Project Structure

```
claude_poc/
├── irvs/                              # Main package directory
│   ├── core/                          # Core engine
│   │   ├── config.py                  # Configuration management
│   │   ├── result.py                  # Result data structures
│   │   └── verification.py            # Main orchestration engine
│   ├── modules/                       # 7 security modules
│   │   ├── package_verifier.py        # Signature & checksum verification
│   │   ├── pipeline_scanner.py        # CI/CD security analysis
│   │   ├── supply_chain.py            # Dependency analysis
│   │   ├── vulnerability_scanner.py   # CVE/vulnerability detection
│   │   ├── provenance_verifier.py     # SLSA framework compliance
│   │   ├── policy_engine.py           # Security policy enforcement
│   │   └── sbom_handler.py            # SBOM generation/validation
│   ├── utils/                         # Utilities
│   │   ├── parsers.py                 # Multi-language dependency parsers
│   │   └── reporters.py               # Report generators
│   ├── cli/                           # Command-line interface
│   │   └── main.py                    # Click-based CLI
│   └── tests/                         # Test suite
│       ├── test_core.py               # Unit tests
│       └── test_integration.py        # Integration tests
├── .github/workflows/                 # CI/CD automation
│   └── security-scan.yml              # Self-scanning workflow
├── config/                            # Configuration templates
│   ├── default.yaml                   # Standard configuration
│   └── strict.yaml                    # High-security config
├── policies/                          # Security policies
│   └── default.yaml                   # 13 built-in policies
├── docs/                              # Documentation
│   └── USAGE.md                       # Detailed user guide
├── examples/                          # Usage examples
│   └── example_scan.py                # Programmatic API examples
├── README.md                          # Main documentation
├── ARCHITECTURE.md                    # System architecture
├── PROJECT_SUMMARY.md                 # Comprehensive summary
└── DEMO.md                            # Demo guide
```

## Technology Stack

### Core
- **Language:** Python 3.8+
- **CLI Framework:** Click 8.1.0+
- **Configuration:** YAML/JSON
- **Testing:** pytest 7.0.0+, pytest-cov
- **Code Quality:** black, flake8, mypy

### Dependencies
```
click>=8.1.0          # CLI framework
pyyaml>=6.0           # Configuration parsing
python-dateutil>=2.8.0 # Date handling
```

### Optional External Tools
- **Syft** - SBOM generation
- **Grype** - Vulnerability scanning
- **Trivy** - Security scanning
- **Cosign** - Signature verification
- **in-toto** - Supply chain integrity

## Key Features

### 1. Package Verification (`package_verifier.py`)
- GPG/PGP signature validation
- Cosign/Sigstore support
- SHA-256/SHA-512 checksum validation
- SBOM presence checking
- File integrity analysis

### 2. Pipeline Security Scanner (`pipeline_scanner.py`)
- GitHub Actions workflow analysis
- GitLab CI scanning
- Jenkins pipeline verification
- Hardcoded secret detection (7 pattern types)
- Permission auditing
- Action/plugin pinning verification

### 3. Supply Chain Analyzer (`supply_chain.py`)
- Multi-language dependency parsing
- Typosquatting detection (85%+ similarity)
- Malicious package pattern matching
- Version pinning enforcement
- Dependency confusion prevention

### 4. Vulnerability Scanner (`vulnerability_scanner.py`)
- Grype and Trivy integration
- CVE database correlation (NVD, OSV, GitHub)
- CVSS scoring
- Configurable severity thresholds

### 5. Provenance Verifier (`provenance_verifier.py`)
- SLSA framework compliance (Levels 1-3)
- Build attestation validation
- Trusted builder verification

### 6. Policy Engine (`policy_engine.py`)
- 13 built-in security policies
- YAML-based policy definitions
- Compliance framework mapping
- Custom policy support

### 7. SBOM Handler (`sbom_handler.py`)
- SPDX format generation
- CycloneDX format generation
- SBOM validation
- Syft integration

## Installation & Setup

### Quick Install
```bash
# Clone repository
git clone https://github.com/TisteAI/claude_poc.git
cd claude_poc

# Install dependencies
pip install -r requirements.txt

# Install package in development mode
pip install -e .
```

### Development Setup
```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=irvs --cov-report=html

# Code formatting
black irvs/

# Linting
flake8 irvs/

# Type checking
mypy irvs/
```

## Usage

### CLI Commands

```bash
# Verify package integrity
irvs verify-package <path>

# Scan CI/CD pipelines
irvs verify-pipeline <path>

# Verify SLSA compliance
irvs verify-provenance <path>

# Validate SBOM
irvs verify-sbom <path>

# Comprehensive security scan
irvs full-scan <path>

# Generate SBOM
irvs generate-sbom <path>

# Initialize configuration
irvs init-config <path>
```

### Global Options
- `--config, -c` - Configuration file path
- `--log-level` - DEBUG, INFO, WARNING, ERROR
- `--format, -f` - json, text, sarif
- `--output, -o` - Output file

### Programmatic Usage

```python
from irvs.core.verification import VerificationEngine
from irvs.core.config import Config

# Load configuration
config = Config.from_yaml('config/default.yaml')

# Create engine
engine = VerificationEngine(config)

# Run verification
result = engine.verify_package('path/to/package')

# Check results
if result.passed:
    print("Verification passed!")
else:
    for finding in result.findings:
        print(f"{finding.severity}: {finding.title}")
```

## Testing

### Run All Tests
```bash
pytest
```

### Run Specific Tests
```bash
# Core tests
pytest irvs/tests/test_core.py

# Integration tests
pytest irvs/tests/test_integration.py

# With verbose output
pytest -v

# With coverage
pytest --cov=irvs --cov-report=html
```

### Test Structure
- **Unit Tests:** `irvs/tests/test_core.py` - Core component tests
- **Integration Tests:** `irvs/tests/test_integration.py` - Module integration tests
- **Fixtures:** `tests/fixtures/` - Test data and sample files

## Configuration

### Default Configuration (`config/default.yaml`)
Standard security settings for general use. Includes:
- Policy engine settings
- Package verification options
- Vulnerability thresholds
- Output formats

### Strict Configuration (`config/strict.yaml`)
High-security settings for governmental/critical infrastructure use. More aggressive policy enforcement.

### Custom Configuration
```yaml
policy_engine:
  enabled: true
  policies_dir: "./policies"
  strict_mode: true

package_verification:
  require_signature: true
  allowed_hash_algorithms: ["sha256", "sha512"]
  require_sbom: true

vulnerability_scanner:
  enabled: true
  max_severity: "HIGH"
  cvss_threshold: 7.0
```

## Security Policies

### Built-in Policies (`policies/default.yaml`)
1. No Critical Vulnerabilities
2. No High Severity Vulnerabilities
3. Package Signature Required
4. Software Bill of Materials Required
5. No Hardcoded Secrets
6. Minimum SLSA Level 2
7. Dependencies Must Be Pinned
8. No Blocked Packages
9. No Typosquatting
10. GitHub Actions Pinned to SHA
11. No Overly Permissive Workflows
12. Prevent Script Injection
13. Package Checksum Verification

## Compliance Frameworks

IRVS helps meet compliance requirements for:
- **NIST SP 800-53** - Security and Privacy Controls
- **NIST SP 800-161** - Cybersecurity Supply Chain Risk Management
- **FedRAMP** - Federal Risk and Authorization Management
- **FISMA** - Federal Information Security Management Act
- **Executive Order 14028** - Improving the Nation's Cybersecurity
- **SLSA Level 2+** - Supply-chain Levels for Software Artifacts
- **OWASP Top 10** - Application Security Risks
- **CIS Benchmarks** - Configuration best practices

## Supported Ecosystems

- **Python:** requirements.txt, setup.py, Pipfile
- **Node.js:** package.json
- **Go:** go.mod
- **Rust:** Cargo.toml
- **Ruby:** Gemfile
- **Java:** Maven pom.xml

## CI/CD Integration

### GitHub Actions
Workflow: `.github/workflows/security-scan.yml`
- Automated scanning on push/PR
- SARIF upload to GitHub Security tab
- Scheduled daily scans
- Actions pinned to SHA versions

### Triggers
- Push to main, master, develop, claude/** branches
- Pull requests to main, master, develop
- Daily schedule (2 AM UTC)
- Manual workflow dispatch

## Documentation

### Available Documentation
1. **README.md** - Installation, quick start, CLI commands
2. **ARCHITECTURE.md** - System design and security principles
3. **PROJECT_SUMMARY.md** - Comprehensive project metrics
4. **USAGE.md** - Detailed user guide and advanced features
5. **DEMO.md** - Step-by-step demonstrations
6. **CLAUDE.MD** (this file) - Claude AI project guide

## Common Tasks for AI Assistants

### Adding a New Security Module
1. Create module file in `irvs/modules/`
2. Inherit from base verification class
3. Implement verification logic
4. Add module to `VerificationEngine` in `core/verification.py`
5. Add tests in `irvs/tests/`
6. Update documentation

### Adding a New Policy
1. Add policy definition to `policies/default.yaml`
2. Implement policy check in `modules/policy_engine.py`
3. Add remediation guidance
4. Add tests
5. Update documentation

### Adding a New Parser
1. Add parser function to `utils/parsers.py`
2. Support new dependency file format
3. Add tests with sample files in `tests/fixtures/`
4. Update documentation

### Extending CI/CD Scanner
1. Update `modules/pipeline_scanner.py`
2. Add new pipeline format detection
3. Implement security checks
4. Add test fixtures
5. Update documentation

## Performance Characteristics

- **Dependency Parsing:** ~0.5 seconds for 100 iterations
- **Pipeline Scanning:** ~0.2 seconds for 2 workflows
- **Supply Chain Analysis:** ~0.3 seconds for 12 dependencies
- **Memory Usage:** < 50 MB for typical scans

## Threat Model

### Threats Addressed
- Compromised dependencies and supply chain attacks
- Malicious packages and typosquatting
- Build system compromise
- Source code tampering
- Artifact substitution
- Dependency confusion attacks
- Pipeline injection attacks
- Exposed secrets and credentials

## Development Workflow

### Making Changes
1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes
3. Run tests: `pytest`
4. Run linters: `black irvs/ && flake8 irvs/`
5. Commit changes: `git commit -m "description"`
6. Push: `git push origin feature/your-feature`
7. Create pull request

### Code Quality Standards
- All code must pass pytest tests
- Black formatting required
- Flake8 linting required
- Type hints required (mypy)
- Test coverage > 80%

## Troubleshooting

### Common Issues

**Import errors:**
```bash
# Ensure package is installed in editable mode
pip install -e .
```

**Missing dependencies:**
```bash
# Reinstall all dependencies
pip install -r requirements.txt
```

**Test failures:**
```bash
# Run with verbose output
pytest -v -s
```

**External tools not found:**
```bash
# Install optional tools
brew install syft grype trivy cosign  # macOS
# or use package manager on Linux
```

## Project Context for AI

### Primary Purpose
Security verification tool for governmental/critical infrastructure software supply chains.

### Target Users
- Government security teams
- DevSecOps engineers
- Compliance officers
- Security auditors

### Key Design Principles
1. **Defense in Depth:** Multiple verification layers
2. **Zero Trust:** Verify everything, trust nothing
3. **Compliance First:** Meet governmental requirements
4. **Extensibility:** Easy to add new modules and policies
5. **Automation:** CI/CD integration for continuous verification

### Important Constraints
- Must support air-gapped environments
- No internet dependencies for core functionality
- Must produce auditable reports
- Must support multiple compliance frameworks

## Additional Resources

- **Issue Tracker:** GitHub Issues
- **Documentation:** `/docs` directory
- **Examples:** `/examples` directory
- **Test Fixtures:** `/tests/fixtures` directory

---

**Last Updated:** 2025-11-16
**Project Status:** Production Ready
**Current Branch:** claude/create-claude-md-01PS5kj8WDyAT6RsZWamzepC
