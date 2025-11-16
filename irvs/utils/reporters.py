"""Report generation utilities."""

import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

from irvs.core.result import VerificationResult, Severity

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate formatted reports from verification results."""

    @staticmethod
    def generate_markdown_report(result: VerificationResult, title: str = "Security Verification Report") -> str:
        """Generate a Markdown formatted report."""
        lines = []

        # Header
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Status:** {'✅ PASSED' if result.passed else '❌ FAILED'}")
        lines.append("")

        # Summary
        summary = result.get_summary()
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Findings:** {summary['total_findings']}")
        lines.append(f"- **Verification Types:** {', '.join(summary.get('verification_types', []))}")
        lines.append("")

        # Severity breakdown
        lines.append("### Severity Breakdown")
        lines.append("")
        severity_counts = summary['severity_counts']

        # Create a table
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")

        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': '⚪'
        }

        for severity, count in severity_counts.items():
            if count > 0:
                icon = severity_icons.get(severity, '')
                lines.append(f"| {icon} {severity.upper()} | {count} |")

        lines.append("")

        # Detailed findings
        if result.findings:
            lines.append("## Detailed Findings")
            lines.append("")

            # Group by severity
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                severity_findings = result.get_findings_by_severity(severity)

                if severity_findings:
                    icon = severity_icons.get(severity.value, '')
                    lines.append(f"### {icon} {severity.value.upper()} Severity ({len(severity_findings)})")
                    lines.append("")

                    for idx, finding in enumerate(severity_findings, 1):
                        lines.append(f"#### {idx}. {finding.title}")
                        lines.append("")
                        lines.append(f"**Category:** {finding.category}")
                        lines.append("")
                        lines.append(f"**Description:** {finding.description}")
                        lines.append("")

                        if finding.affected_component:
                            lines.append(f"**Affected Component:** `{finding.affected_component}`")
                            lines.append("")

                        if finding.cve_ids:
                            lines.append(f"**CVEs:** {', '.join(finding.cve_ids)}")
                            lines.append("")

                        if finding.cvss_score:
                            lines.append(f"**CVSS Score:** {finding.cvss_score}")
                            lines.append("")

                        if finding.remediation:
                            lines.append(f"**Remediation:**")
                            lines.append("")
                            lines.append(finding.remediation)
                            lines.append("")

                        lines.append("---")
                        lines.append("")

        # Recommendations
        if not result.passed:
            lines.append("## Recommendations")
            lines.append("")
            lines.append("1. Review and address all CRITICAL and HIGH severity findings immediately")
            lines.append("2. Follow the remediation steps provided for each finding")
            lines.append("3. Re-run verification after fixes are applied")
            lines.append("4. Consider implementing automated verification in CI/CD pipeline")
            lines.append("")

        return '\n'.join(lines)

    @staticmethod
    def generate_html_report(result: VerificationResult, title: str = "Security Verification Report") -> str:
        """Generate an HTML formatted report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2em;
        }}
        .status {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            margin-top: 10px;
        }}
        .status.passed {{
            background-color: #10b981;
            color: white;
        }}
        .status.failed {{
            background-color: #ef4444;
            color: white;
        }}
        .summary {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .severity-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: bold;
            margin-right: 10px;
        }}
        .critical {{ background-color: #dc2626; color: white; }}
        .high {{ background-color: #f59e0b; color: white; }}
        .medium {{ background-color: #eab308; color: black; }}
        .low {{ background-color: #3b82f6; color: white; }}
        .info {{ background-color: #6b7280; color: white; }}
        .finding {{
            border-left: 4px solid #667eea;
            padding-left: 16px;
            margin: 16px 0;
        }}
        .metadata {{
            background-color: #f9fafb;
            padding: 12px;
            border-radius: 4px;
            margin: 8px 0;
            font-size: 0.9em;
        }}
        .remediation {{
            background-color: #ecfdf5;
            border-left: 4px solid #10b981;
            padding: 12px;
            margin: 8px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        th {{
            background-color: #f9fafb;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <span class="status {'passed' if result.passed else 'failed'}">
            {'✅ PASSED' if result.passed else '❌ FAILED'}
        </span>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Findings</td><td>{len(result.findings)}</td></tr>
            <tr><td>Critical</td><td>{result.get_critical_count()}</td></tr>
            <tr><td>High</td><td>{result.get_high_count()}</td></tr>
        </table>
    </div>
"""

        # Add findings
        if result.findings:
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                severity_findings = result.get_findings_by_severity(severity)

                if severity_findings:
                    html += f"""
    <div class="severity-card">
        <h2><span class="severity-badge {severity.value}">{severity.value.upper()}</span> ({len(severity_findings)} findings)</h2>
"""

                    for finding in severity_findings:
                        html += f"""
        <div class="finding">
            <h3>{finding.title}</h3>
            <p><strong>Category:</strong> {finding.category}</p>
            <p>{finding.description}</p>
"""
                        if finding.affected_component:
                            html += f"""
            <div class="metadata">
                <strong>Affected Component:</strong> <code>{finding.affected_component}</code>
            </div>
"""

                        if finding.remediation:
                            html += f"""
            <div class="remediation">
                <strong>Remediation:</strong><br>
                {finding.remediation}
            </div>
"""

                        html += "        </div>\n"

                    html += "    </div>\n"

        html += """
</body>
</html>
"""

        return html

    @staticmethod
    def save_report(content: str, output_path: Path) -> None:
        """Save report content to file."""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content)
            logger.info(f"Report saved to: {output_path}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")
