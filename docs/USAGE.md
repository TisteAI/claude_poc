# IRVS Usage Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Configuration](#configuration)
5. [Policy Management](#policy-management)
6. [Integration Examples](#integration-examples)

## Getting Started

### Installation

```bash
pip install irvs
```

### First Run

```bash
# Initialize configuration
irvs init-config config.yaml

# Run your first scan
irvs verify-package /path/to/package.tar.gz
```

## Basic Usage

### Package Verification

Verify the integrity and security of a software package:

```bash
# Basic verification
irvs verify-package package.tar.gz

# With JSON output
irvs verify-package package.tar.gz --format json --output results.json

# Using custom configuration
irvs --config strict-config.yaml verify-package package.tar.gz
```

### Pipeline Security Scanning

Scan CI/CD pipeline configurations:

```bash
# GitHub Actions
irvs verify-pipeline .github/workflows

# GitLab CI
irvs verify-pipeline .gitlab-ci.yml

# Jenkins
irvs verify-pipeline Jenkinsfile
```

### SBOM Operations

Generate and verify Software Bill of Materials:

```bash
# Generate SBOM in SPDX format
irvs generate-sbom . --format spdx-json --output project.spdx.json

# Generate CycloneDX SBOM
irvs generate-sbom . --format cyclonedx-json --output project.cdx.json

# Verify existing SBOM
irvs verify-sbom project.spdx.json
```

### Provenance Verification

Verify build provenance and SLSA compliance:

```bash
# Verify with explicit provenance file
irvs verify-provenance artifact.tar.gz --provenance artifact.tar.gz.provenance.json

# Auto-detect provenance
irvs verify-provenance artifact.tar.gz
```

### Full Security Scan

Comprehensive security analysis:

```bash
# Scan entire project
irvs full-scan .

# With SARIF output for CI/CD
irvs full-scan . --format sarif --output results.sarif
```

## Advanced Features

### Custom Configuration

Create a custom configuration file:

```yaml
# custom-config.yaml
policy:
  enabled: true
  policy_dir: "custom-policies"
  fail_on_policy_violation: true

vulnerability:
  enabled: true
  max_cvss_score: 7.0
  fail_on_critical: true

supply_chain:
  blocked_packages:
    - "known-malicious-package"
    - "deprecated-library"
```

Use the custom configuration:

```bash
irvs --config custom-config.yaml full-scan .
```

### Filtering Results

Control output verbosity:

```bash
# Set log level
irvs --log-level DEBUG verify-package package.tar.gz

# Quiet mode (errors only)
irvs --log-level ERROR verify-package package.tar.gz
```

### Multiple Output Formats

Generate results in different formats:

```bash
# Human-readable text
irvs full-scan . --format text

# Machine-readable JSON
irvs full-scan . --format json --output results.json

# SARIF for tool integration
irvs full-scan . --format sarif --output results.sarif
```

## Configuration

### Configuration File Structure

```yaml
# Policy configuration
policy:
  enabled: true
  policy_dir: "policies"
  fail_on_policy_violation: true
  custom_policies:
    - "path/to/custom-policy.yaml"

# Package verification
package_verification:
  verify_signatures: true
  verify_checksums: true
  allowed_signature_types:
    - gpg
    - cosign
  require_sbom: true

# Vulnerability scanning
vulnerability:
  enabled: true
  sources:
    - nvd
    - osv
    - github
  max_cvss_score: 10.0
  fail_on_critical: true
  fail_on_high: true
  ignore_cves:
    - CVE-2023-12345  # Add CVEs to ignore

# Supply chain
supply_chain:
  analyze_dependencies: true
  check_typosquatting: true
  detect_malicious_packages: true
  blocked_packages:
    - malicious-package-name
```

### Environment Variables

Set configuration via environment variables:

```bash
export IRVS_CONFIG=/path/to/config.yaml
export IRVS_LOG_LEVEL=DEBUG
```

## Policy Management

### Using Built-in Policies

IRVS includes default policies for common security requirements:

```bash
# Policies are loaded automatically from policies/ directory
irvs full-scan .
```

### Creating Custom Policies

Create a custom policy file:

```yaml
# custom-policies/security-rules.yaml
policies:
  - id: custom-rule-1
    name: No Development Dependencies in Production
    description: Development dependencies must not be included in production builds
    severity: high
    enabled: true
    conditions:
      - finding_category: supply_chain
        finding_title: "*dev*dependency*"
    remediation: Remove development dependencies from production builds

  - id: custom-rule-2
    name: Minimum Package Version
    description: Packages must meet minimum version requirements
    severity: medium
    enabled: true
    conditions:
      - finding_category: supply_chain
    remediation: Update packages to required minimum versions
```

Use custom policies:

```bash
irvs --config config-with-custom-policies.yaml full-scan .
```

## Integration Examples

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install IRVS
        run: pip install irvs

      - name: Run Security Scan
        run: irvs full-scan . --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: python:3.11
  script:
    - pip install irvs
    - irvs full-scan . --format json --output results.json
  artifacts:
    reports:
      security: results.json
    paths:
      - results.json
    when: always
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install irvs'
                sh 'irvs full-scan . --format json --output results.json'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'results.json', fingerprint: true
        }
    }
}
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: irvs-scan
        name: IRVS Security Scan
        entry: irvs full-scan .
        language: system
        pass_filenames: false
```

## Troubleshooting

### Common Issues

**Issue**: "Grype not found" or "Syft not found"

**Solution**: Install optional external tools:

```bash
# Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
```

**Issue**: GPG signature verification fails

**Solution**: Import the required GPG keys:

```bash
gpg --import public-key.asc
```

**Issue**: High memory usage during scans

**Solution**: Limit the scan scope or increase available memory:

```bash
# Scan specific directory only
irvs verify-pipeline .github/workflows

# Instead of full scan
# irvs full-scan .
```

## Best Practices

1. **Use Configuration Files**: Maintain consistent settings across environments
2. **Enable All Checks**: Don't disable security checks unless absolutely necessary
3. **Regular Scans**: Integrate IRVS into your CI/CD pipeline
4. **Review Findings**: Don't ignore security findings - investigate and remediate
5. **Keep Policies Updated**: Review and update security policies regularly
6. **Pin Tool Versions**: Use specific versions of IRVS in production
7. **Store Results**: Archive scan results for compliance and auditing
8. **Automate Everything**: Automate scanning, reporting, and remediation where possible

## Performance Tips

1. **Use Caching**: IRVS caches results in `.irvs_cache/`
2. **Parallel Scanning**: Run different scan types in parallel in CI/CD
3. **Incremental Scans**: Scan only changed files when possible
4. **Optimize Configuration**: Disable unnecessary checks for faster scans
5. **Resource Allocation**: Provide adequate CPU and memory for large scans
