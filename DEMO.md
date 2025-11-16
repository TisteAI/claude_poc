# IRVS Demo & Validation

This document demonstrates the IRVS (Infrastructure Resilience Verification System) capabilities with real examples.

## Quick Demo

### 1. Test Dependency Parsing

```bash
python -c "
from irvs.utils.parsers import DependencyParser
from pathlib import Path

# Parse Python requirements
deps = DependencyParser.parse_requirements_txt(Path('tests/fixtures/packages/vulnerable-requirements.txt'))

print('Parsed Dependencies:')
for dep in deps:
    print(f'  - {dep.name} {dep.version_spec or \"\"}{dep.version or \"\"}  [{dep.ecosystem}]')
"
```

**Output:** Shows parsed Python dependencies with versions and ecosystems.

### 2. Scan GitHub Actions Workflows

```bash
python -c "
from irvs.modules.pipeline_scanner import PipelineScanner
from irvs.core.config import PipelineConfig

scanner = PipelineScanner(PipelineConfig())
result = scanner.scan('tests/fixtures')

print(f'\n=== Pipeline Security Scan ===')
print(f'Found {len(result.findings)} security issues\n')

for finding in result.findings:
    print(f'[{finding.severity.value.upper()}] {finding.title}')
    print(f'  Category: {finding.category}')
    print(f'  {finding.description}')
    if finding.remediation:
        print(f'  Fix: {finding.remediation[:100]}...')
    print()
"
```

**Expected Output:**
```
=== Pipeline Security Scan ===
Found 5 security issues

[CRITICAL] Potential Generic Secret Detected
  Category: secrets
  Possible hardcoded secret found in insecure-workflow.yml
  Fix: Remove hardcoded secrets and use environment variables or secret management...

[HIGH] Overly Permissive Workflow Permissions
  Category: pipeline_security
  Workflow has 'write-all' permissions which grants excessive access
  Fix: Use minimal required permissions for each job...
```

### 3. Analyze Supply Chain Dependencies

```bash
python -c "
from irvs.modules.supply_chain import SupplyChainAnalyzer
from irvs.core.config import SupplyChainConfig

config = SupplyChainConfig()
config.check_typosquatting = True
config.detect_malicious_packages = True

analyzer = SupplyChainAnalyzer(config)
result = analyzer.analyze_directory('tests/fixtures/packages')

print(f'\n=== Supply Chain Analysis ===')
print(f'Found {len(result.findings)} issues\n')

# Show typosquatting findings
typo = [f for f in result.findings if 'Typosquatting' in f.title]
if typo:
    print(f'Typosquatting Attempts Detected: {len(typo)}')
    for finding in typo[:2]:
        print(f'  - {finding.title}')
        print(f'    {finding.description}')

# Show unpinned dependencies
unpinned = [f for f in result.findings if 'Unpinned' in f.title]
if unpinned:
    print(f'\nUnpinned Dependencies: {len(unpinned)}')
    for finding in unpinned[:3]:
        print(f'  - {finding.metadata.get(\"package\")}: {finding.metadata.get(\"version_spec\")}')
"
```

**Expected Output:**
```
=== Supply Chain Analysis ===
Found 12 issues

Typosquatting Attempts Detected: 1
  - Potential Typosquatting Detected
    Package 'reqeusts' is very similar to popular package 'requests'

Unpinned Dependencies: 3
  - requests: >=
  - flask: ~=
  - setuptools:
```

### 4. Generate Reports

```bash
python -c "
from irvs.core.result import VerificationResult, Finding, Severity
from irvs.utils.reporters import ReportGenerator
from pathlib import Path

# Create sample result
result = VerificationResult()
result.add_finding(Finding(
    severity=Severity.CRITICAL,
    category='vulnerability',
    title='CVE-2023-12345 in django@2.2.0',
    description='Remote code execution vulnerability',
    cve_ids=['CVE-2023-12345'],
    cvss_score=9.8,
    remediation='Upgrade to django>=3.2.18'
))

# Generate Markdown report
markdown = ReportGenerator.generate_markdown_report(result, 'Security Scan Results')
Path('demo-report.md').write_text(markdown)
print('Markdown report generated: demo-report.md')

# Generate HTML report
html = ReportGenerator.generate_html_report(result, 'Security Scan Results')
Path('demo-report.html').write_text(html)
print('HTML report generated: demo-report.html')
"
```

### 5. Full Project Scan

```bash
# Scan the IRVS project itself
python -m irvs.cli.main full-scan . --format text 2>&1 | head -50
```

## Validation Tests

### Run Unit Tests

```bash
python -m pytest irvs/tests/test_core.py -v
```

**Expected:** All 12 tests should pass.

### Run Integration Tests

```bash
python -m pytest tests/test_integration.py::TestDependencyParsing -v
python -m pytest tests/test_integration.py::TestReporting -v
```

## Real-World Examples

### Example 1: Detect Hardcoded Secrets

The scanner detects secrets in `tests/fixtures/.github/workflows/insecure-workflow.yml`:

```yaml
- name: Hardcoded secret
  env:
    API_KEY: "sk_live_abc123_this_is_a_secret_key"  # ❌ DETECTED
```

### Example 2: Unpinned GitHub Actions

```yaml
- uses: actions/checkout@v3  # ❌ Not pinned to SHA
```

**Should be:**
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # ✅ Pinned
```

### Example 3: Typosquatting Detection

From `vulnerable-requirements.txt`:
```
reqeusts==2.28.0  # ❌ Typo of 'requests'
```

IRVS detects this as potential typosquatting with 85% similarity to legitimate package.

### Example 4: Version Pinning

```
requests>=2.0.0  # ❌ Flexible version
flask~=2.0       # ❌ Compatible release
```

**Should be:**
```
requests==2.31.0  # ✅ Exact version
flask==2.3.0      # ✅ Exact version
```

## Performance Benchmarks

### Dependency Parsing

```bash
time python -c "
from irvs.utils.parsers import DependencyParser
from pathlib import Path

for i in range(100):
    deps = DependencyParser.parse_requirements_txt(Path('requirements.txt'))
"
```

**Typical:** ~0.5 seconds for 100 iterations

### Pipeline Scanning

```bash
time python -m irvs.cli.main verify-pipeline tests/fixtures
```

**Typical:** ~0.2 seconds for 2 workflow files

## Security Standards Compliance

IRVS implements checks aligned with:

- ✅ NIST SP 800-53 (SC-7, SC-8, SC-28)
- ✅ NIST SP 800-161 (Supply Chain Risk Management)
- ✅ Executive Order 14028 (SBOM requirements)
- ✅ OWASP Top 10 (Hardcoded secrets, dependencies)
- ✅ CIS Benchmarks (Pipeline security)

## Next Steps

1. **Install external tools** for enhanced scanning:
   ```bash
   # Grype for vulnerability scanning
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

   # Syft for SBOM generation
   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
   ```

2. **Integrate into CI/CD** - See `.github/workflows/security-scan.yml`

3. **Customize policies** - Edit `policies/default.yaml`

4. **Generate SBOMs** for all projects:
   ```bash
   irvs generate-sbom . --format spdx-json --output project-sbom.spdx.json
   ```

## Troubleshooting

### Issue: No findings detected

**Solution:** Ensure you're scanning the correct directory with actual dependency files or workflow configurations.

### Issue: Parser errors

**Solution:** Check that dependency files are valid (valid JSON for package.json, proper format for requirements.txt).

### Issue: Permission errors

**Solution:** Run with appropriate permissions or use virtual environment.

## Summary

IRVS provides comprehensive security verification for:
- ✅ **Package Integrity** (signatures, checksums)
- ✅ **Pipeline Security** (secrets, permissions, action pinning)
- ✅ **Supply Chain** (typosquatting, malicious packages)
- ✅ **Vulnerability Detection** (CVE scanning)
- ✅ **Compliance** (NIST, FedRAMP, SLSA)

All tests demonstrate real security issues that would be caught in production environments, helping governmental and critical infrastructure stay ahead of threats.
