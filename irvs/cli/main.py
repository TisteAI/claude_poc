"""Main CLI entry point for IRVS."""

import click
import json
import sys
import logging
from pathlib import Path
from typing import Optional

from irvs.core.config import Config
from irvs.core.verification import VerificationEngine
from irvs.core.result import Severity


@click.group()
@click.version_option(version='0.1.0')
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to configuration file')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), default='INFO', help='Logging level')
@click.pass_context
def cli(ctx, config: Optional[str], log_level: str):
    """
    Infrastructure Resilience Verification System (IRVS)

    Comprehensive security verification for critical governmental software infrastructure.
    """
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Load configuration
    if config:
        ctx.obj = Config.from_file(config)
    else:
        ctx.obj = Config()

    ctx.obj.log_level = log_level


@cli.command()
@click.argument('package_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['json', 'text', 'sarif']), default='text', help='Output format')
@click.pass_obj
def verify_package(config: Config, package_path: str, output: Optional[str], format: str):
    """Verify a package for security issues."""
    click.echo(f"Verifying package: {package_path}")

    engine = VerificationEngine(config)
    result = engine.verify_package(package_path)

    _output_results(result, output, format)


@cli.command()
@click.argument('pipeline_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['json', 'text', 'sarif']), default='text', help='Output format')
@click.pass_obj
def verify_pipeline(config: Config, pipeline_path: str, output: Optional[str], format: str):
    """Verify CI/CD pipeline security."""
    click.echo(f"Verifying pipeline: {pipeline_path}")

    engine = VerificationEngine(config)
    result = engine.verify_pipeline(pipeline_path)

    _output_results(result, output, format)


@cli.command()
@click.argument('artifact_path', type=click.Path(exists=True))
@click.option('--provenance', '-p', type=click.Path(exists=True), help='Path to provenance attestation')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['json', 'text', 'sarif']), default='text', help='Output format')
@click.pass_obj
def verify_provenance(config: Config, artifact_path: str, provenance: Optional[str], output: Optional[str], format: str):
    """Verify build provenance and SLSA compliance."""
    click.echo(f"Verifying provenance for: {artifact_path}")

    engine = VerificationEngine(config)
    result = engine.verify_provenance(artifact_path, provenance)

    _output_results(result, output, format)


@cli.command()
@click.argument('target_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['json', 'text', 'sarif']), default='text', help='Output format')
@click.pass_obj
def full_scan(config: Config, target_path: str, output: Optional[str], format: str):
    """Perform comprehensive verification of all aspects."""
    click.echo(f"Performing full security scan: {target_path}")

    engine = VerificationEngine(config)
    result = engine.full_verification(target_path)

    _output_results(result, output, format)


@cli.command()
@click.argument('target_path', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['spdx', 'spdx-json', 'cyclonedx', 'cyclonedx-json']),
              default='spdx-json', help='SBOM format')
@click.option('--output', '-o', type=click.Path(), help='Output file for SBOM')
@click.pass_obj
def generate_sbom(config: Config, target_path: str, format: str, output: Optional[str]):
    """Generate Software Bill of Materials (SBOM)."""
    click.echo(f"Generating {format} SBOM for: {target_path}")

    engine = VerificationEngine(config)
    sbom_path = engine.generate_sbom(target_path, format)

    if output:
        Path(sbom_path).rename(output)
        click.echo(f"SBOM saved to: {output}")
    else:
        click.echo(f"SBOM saved to: {sbom_path}")


@cli.command()
@click.argument('sbom_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['json', 'text']), default='text', help='Output format')
@click.pass_obj
def verify_sbom(config: Config, sbom_path: str, output: Optional[str], format: str):
    """Verify and analyze an SBOM."""
    click.echo(f"Verifying SBOM: {sbom_path}")

    engine = VerificationEngine(config)
    result = engine.verify_sbom(sbom_path)

    _output_results(result, output, format)


@cli.command()
@click.argument('output_path', type=click.Path())
@click.option('--format', '-f', type=click.Choice(['yaml', 'json']), default='yaml', help='Configuration format')
def init_config(output_path: str, format: str):
    """Initialize a configuration file with defaults."""
    config = Config()
    config.save(output_path)
    click.echo(f"Configuration file created: {output_path}")


@cli.command()
@click.argument('verification_result', type=click.Path(exists=True))
@click.option('--framework', '-f', type=click.Choice(['NIST-800-53', 'NIST-800-161', 'FedRAMP', 'FISMA', 'EO-14028']),
              required=True, help='Compliance framework')
@click.option('--output', '-o', type=click.Path(), help='Output file for report')
@click.pass_obj
def compliance_report(config: Config, verification_result: str, framework: str, output: Optional[str]):
    """Generate compliance report for a specific framework."""
    click.echo(f"Generating {framework} compliance report")

    # Load verification result
    with open(verification_result, 'r') as f:
        result_data = json.load(f)

    # This would reconstruct VerificationResult from JSON
    # For now, show a message
    click.echo(f"Compliance report for {framework}")
    click.echo("Feature in development - use policy evaluation during scan")


def _output_results(result, output_file: Optional[str], format: str):
    """Output verification results in specified format."""
    if format == 'json':
        output_data = json.dumps(result.to_dict(), indent=2)
    elif format == 'sarif':
        output_data = _convert_to_sarif(result)
    else:  # text
        output_data = _format_text_output(result)

    if output_file:
        Path(output_file).write_text(output_data)
        click.echo(f"Results saved to: {output_file}")
    else:
        click.echo(output_data)

    # Exit with error code if verification failed
    if not result.passed:
        sys.exit(1)


def _format_text_output(result) -> str:
    """Format results as human-readable text."""
    lines = []
    lines.append("=" * 80)
    lines.append("IRVS Security Verification Results")
    lines.append("=" * 80)
    lines.append(f"Timestamp: {result.timestamp.isoformat()}")
    lines.append(f"Status: {'PASSED' if result.passed else 'FAILED'}")
    lines.append(f"Total Findings: {len(result.findings)}")
    lines.append("")

    summary = result.get_summary()
    lines.append("Severity Summary:")
    for severity, count in summary['severity_counts'].items():
        if count > 0:
            lines.append(f"  {severity.upper()}: {count}")
    lines.append("")

    if result.findings:
        lines.append("Findings:")
        lines.append("-" * 80)

        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_findings = result.get_findings_by_severity(severity)

            if severity_findings:
                lines.append(f"\n[{severity.value.upper()}]")
                for finding in severity_findings:
                    lines.append(f"\n  • {finding.title}")
                    lines.append(f"    Category: {finding.category}")
                    lines.append(f"    {finding.description}")

                    if finding.affected_component:
                        lines.append(f"    Affected: {finding.affected_component}")

                    if finding.remediation:
                        lines.append(f"    Remediation: {finding.remediation}")

                    if finding.cve_ids:
                        lines.append(f"    CVEs: {', '.join(finding.cve_ids)}")

                    if finding.cvss_score:
                        lines.append(f"    CVSS Score: {finding.cvss_score}")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)


def _convert_to_sarif(result) -> str:
    """Convert results to SARIF format for tool integration."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "IRVS",
                        "informationUri": "https://github.com/irvs/irvs",
                        "version": "0.1.0",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    # Convert findings to SARIF results
    for finding in result.findings:
        sarif_result = {
            "ruleId": finding.category,
            "level": _severity_to_sarif_level(finding.severity),
            "message": {
                "text": f"{finding.title}: {finding.description}"
            },
            "properties": {
                "severity": finding.severity.value,
                "category": finding.category
            }
        }

        if finding.affected_component:
            sarif_result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.affected_component
                    }
                }
            }]

        sarif["runs"][0]["results"].append(sarif_result)

    return json.dumps(sarif, indent=2)


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map Severity to SARIF level."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note"
    }
    return mapping.get(severity, "warning")


if __name__ == '__main__':
    cli(obj=None)
