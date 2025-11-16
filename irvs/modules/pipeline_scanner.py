"""CI/CD pipeline security scanner module."""

import logging
import yaml
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from irvs.core.result import VerificationResult, Finding, Severity
from irvs.core.config import PipelineConfig


logger = logging.getLogger(__name__)


class PipelineScanner:
    """
    Scans CI/CD pipeline configurations for security vulnerabilities.

    Supports:
    - GitHub Actions workflows
    - GitLab CI configurations
    - Jenkins pipelines
    - Secret detection
    - Permission analysis
    - Action/plugin security checks
    """

    # Common secret patterns
    SECRET_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'aws_secret_access_key[\s]*=[\s]*[\'"][A-Za-z0-9/+=]{40}[\'"]',
        'github_token': r'gh[pousr]_[A-Za-z0-9]{36}',
        'private_key': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'generic_secret': r'(?i)(secret|password|token|api[_-]?key)[\s]*[:=][\s]*[\'"][^\'"]{8,}[\'"]',
        'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        'stripe_key': r'sk_live_[0-9a-zA-Z]{24,}',
    }

    def __init__(self, config: PipelineConfig):
        """Initialize pipeline scanner with configuration."""
        self.config = config

    def scan(self, pipeline_path: str) -> VerificationResult:
        """
        Scan pipeline configurations for security issues.

        Args:
            pipeline_path: Path to pipeline directory or file

        Returns:
            VerificationResult with findings
        """
        result = VerificationResult()
        path = Path(pipeline_path)

        if not path.exists():
            result.add_finding(Finding(
                severity=Severity.HIGH,
                category="pipeline_security",
                title="Pipeline Path Not Found",
                description=f"Pipeline path does not exist: {pipeline_path}"
            ))
            return result

        logger.info(f"Scanning pipeline: {pipeline_path}")

        # Scan GitHub Actions
        github_actions_path = path / '.github/workflows' if path.is_dir() else (
            path.parent / '.github/workflows' if path.name == 'workflows' else None
        )

        if github_actions_path and github_actions_path.exists():
            gh_findings = self._scan_github_actions(github_actions_path)
            result.findings.extend(gh_findings)

        # Scan GitLab CI
        gitlab_ci_files = []
        if path.is_dir():
            gitlab_ci_files = list(path.glob('.gitlab-ci.yml'))
        elif path.name == '.gitlab-ci.yml':
            gitlab_ci_files = [path]

        for gitlab_file in gitlab_ci_files:
            gl_findings = self._scan_gitlab_ci(gitlab_file)
            result.findings.extend(gl_findings)

        # Scan Jenkins
        jenkins_files = []
        if path.is_dir():
            jenkins_files = list(path.glob('**/Jenkinsfile'))
        elif path.name == 'Jenkinsfile':
            jenkins_files = [path]

        for jenkins_file in jenkins_files:
            jenkins_findings = self._scan_jenkinsfile(jenkins_file)
            result.findings.extend(jenkins_findings)

        return result

    def _scan_github_actions(self, workflows_dir: Path) -> List[Finding]:
        """Scan GitHub Actions workflows for security issues."""
        findings = []
        workflow_files = list(workflows_dir.glob('*.yml')) + list(workflows_dir.glob('*.yaml'))

        logger.info(f"Found {len(workflow_files)} GitHub Actions workflows")

        for workflow_file in workflow_files:
            try:
                with open(workflow_file, 'r') as f:
                    workflow = yaml.safe_load(f)

                # Check for secrets in workflow
                if self.config.detect_secrets:
                    secret_findings = self._detect_secrets_in_file(workflow_file)
                    findings.extend(secret_findings)

                # Check permissions
                if self.config.check_permissions:
                    perm_findings = self._check_github_permissions(workflow, workflow_file)
                    findings.extend(perm_findings)

                # Check action pinning
                if self.config.verify_action_pinning:
                    pin_findings = self._check_action_pinning(workflow, workflow_file)
                    findings.extend(pin_findings)

                # Check for dangerous patterns
                danger_findings = self._check_dangerous_patterns_github(workflow, workflow_file)
                findings.extend(danger_findings)

                # Check third-party actions
                action_findings = self._check_third_party_actions(workflow, workflow_file)
                findings.extend(action_findings)

            except yaml.YAMLError as e:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category="pipeline_security",
                    title="Invalid Workflow YAML",
                    description=f"Failed to parse workflow file: {workflow_file.name}",
                    affected_component=str(workflow_file),
                    metadata={"error": str(e)}
                ))
            except Exception as e:
                logger.error(f"Error scanning {workflow_file}: {e}")

        return findings

    def _check_github_permissions(self, workflow: Dict[str, Any], workflow_file: Path) -> List[Finding]:
        """Check GitHub Actions permissions for overly permissive settings."""
        findings = []

        # Check top-level permissions
        permissions = workflow.get('permissions', {})

        # If permissions is set to 'write-all', flag it
        if permissions == 'write-all':
            findings.append(Finding(
                severity=Severity.HIGH,
                category="pipeline_security",
                title="Overly Permissive Workflow Permissions",
                description="Workflow has 'write-all' permissions which grants excessive access",
                remediation="Use minimal required permissions for each job",
                affected_component=str(workflow_file),
                metadata={"permissions": permissions}
            ))

        # Check if specific permissions are overly broad
        if isinstance(permissions, dict):
            risky_perms = ['contents', 'packages', 'deployments']
            for perm in risky_perms:
                if permissions.get(perm) == 'write':
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category="pipeline_security",
                        title=f"Write Permission on {perm.title()}",
                        description=f"Workflow has write access to {perm}",
                        remediation=f"Review if write access to {perm} is necessary",
                        affected_component=str(workflow_file),
                        metadata={"permission": perm, "level": "write"}
                    ))

        # Check job-level permissions
        jobs = workflow.get('jobs', {})
        for job_name, job_config in jobs.items():
            job_perms = job_config.get('permissions', {})
            if job_perms == 'write-all':
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="pipeline_security",
                    title=f"Overly Permissive Job Permissions: {job_name}",
                    description=f"Job '{job_name}' has 'write-all' permissions",
                    remediation="Use minimal required permissions",
                    affected_component=str(workflow_file),
                    metadata={"job": job_name}
                ))

        return findings

    def _check_action_pinning(self, workflow: Dict[str, Any], workflow_file: Path) -> List[Finding]:
        """Check if actions are pinned to specific versions."""
        findings = []
        jobs = workflow.get('jobs', {})

        for job_name, job_config in jobs.items():
            steps = job_config.get('steps', [])
            for step_idx, step in enumerate(steps):
                if 'uses' in step:
                    action = step['uses']

                    # Check if action is pinned to commit SHA (most secure)
                    if '@' in action:
                        ref = action.split('@')[1]
                        # SHA should be 40 hex characters
                        if not re.match(r'^[a-f0-9]{40}$', ref):
                            severity = Severity.MEDIUM
                            if not any(tag in ref for tag in ['v', 'main', 'master']):
                                severity = Severity.HIGH

                            findings.append(Finding(
                                severity=severity,
                                category="pipeline_security",
                                title="Action Not Pinned to SHA",
                                description=f"Action '{action}' is not pinned to commit SHA",
                                remediation="Pin actions to specific commit SHAs for security",
                                affected_component=str(workflow_file),
                                metadata={
                                    "job": job_name,
                                    "step": step_idx,
                                    "action": action
                                }
                            ))
                    else:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category="pipeline_security",
                            title="Unpinned Action",
                            description=f"Action '{action}' has no version specified",
                            remediation="Always pin actions to specific versions or SHAs",
                            affected_component=str(workflow_file),
                            metadata={
                                "job": job_name,
                                "step": step_idx,
                                "action": action
                            }
                        ))

        return findings

    def _check_dangerous_patterns_github(self, workflow: Dict[str, Any], workflow_file: Path) -> List[Finding]:
        """Check for dangerous patterns in GitHub Actions workflows."""
        findings = []
        jobs = workflow.get('jobs', {})

        for job_name, job_config in jobs.items():
            steps = job_config.get('steps', [])

            for step_idx, step in enumerate(steps):
                # Check for pull_request_target with checkout
                if 'uses' in step and 'actions/checkout@' in step['uses']:
                    triggers = workflow.get('on', {})
                    if 'pull_request_target' in triggers or triggers.get('pull_request_target'):
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category="pipeline_security",
                            title="Dangerous pull_request_target with Checkout",
                            description="Using pull_request_target with code checkout can execute untrusted code",
                            remediation="Use pull_request trigger or carefully validate code before checkout",
                            affected_component=str(workflow_file),
                            metadata={"job": job_name, "step": step_idx}
                        ))

                # Check for script injection vulnerabilities
                if 'run' in step:
                    run_command = step['run']
                    # Look for GitHub context usage in run commands
                    if re.search(r'\$\{\{.*?(github\.event\.|github\.head_ref).*?\}\}', run_command):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category="pipeline_security",
                            title="Potential Script Injection",
                            description="Run command uses untrusted GitHub context that could allow script injection",
                            remediation="Sanitize inputs or use environment variables",
                            affected_component=str(workflow_file),
                            metadata={
                                "job": job_name,
                                "step": step_idx,
                                "command": run_command[:200]
                            }
                        ))

        return findings

    def _check_third_party_actions(self, workflow: Dict[str, Any], workflow_file: Path) -> List[Finding]:
        """Check security of third-party actions."""
        findings = []
        jobs = workflow.get('jobs', {})

        for job_name, job_config in jobs.items():
            steps = job_config.get('steps', [])

            for step_idx, step in enumerate(steps):
                if 'uses' in step:
                    action = step['uses']
                    action_name = action.split('@')[0] if '@' in action else action

                    # Check if action is in blocked list
                    if action_name in self.config.blocked_actions:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category="pipeline_security",
                            title="Blocked Action Used",
                            description=f"Action '{action_name}' is in the blocked list",
                            remediation="Remove this action or use an approved alternative",
                            affected_component=str(workflow_file),
                            metadata={"job": job_name, "action": action}
                        ))

                    # Check if action is from approved list (if allowlist is set)
                    if self.config.allowed_actions:
                        if not any(action_name.startswith(allowed) for allowed in self.config.allowed_actions):
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category="pipeline_security",
                                title="Unapproved Third-Party Action",
                                description=f"Action '{action_name}' is not in the approved list",
                                remediation="Use only approved actions or request approval",
                                affected_component=str(workflow_file),
                                metadata={"job": job_name, "action": action}
                            ))

        return findings

    def _scan_gitlab_ci(self, gitlab_file: Path) -> List[Finding]:
        """Scan GitLab CI configuration for security issues."""
        findings = []

        try:
            with open(gitlab_file, 'r') as f:
                config = yaml.safe_load(f)

            # Detect secrets
            if self.config.detect_secrets:
                secret_findings = self._detect_secrets_in_file(gitlab_file)
                findings.extend(secret_findings)

            # Check for privileged mode
            for job_name, job_config in config.items():
                if isinstance(job_config, dict) and 'services' in job_config:
                    for service in job_config['services']:
                        if isinstance(service, dict) and service.get('privileged'):
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category="pipeline_security",
                                title="Privileged Container Mode",
                                description=f"Job '{job_name}' uses privileged container mode",
                                remediation="Avoid privileged mode unless absolutely necessary",
                                affected_component=str(gitlab_file),
                                metadata={"job": job_name}
                            ))

        except Exception as e:
            logger.error(f"Error scanning GitLab CI: {e}")
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="pipeline_security",
                title="GitLab CI Scan Error",
                description=f"Failed to scan GitLab CI file: {str(e)}",
                affected_component=str(gitlab_file)
            ))

        return findings

    def _scan_jenkinsfile(self, jenkins_file: Path) -> List[Finding]:
        """Scan Jenkinsfile for security issues."""
        findings = []

        try:
            content = jenkins_file.read_text()

            # Detect secrets
            if self.config.detect_secrets:
                secret_findings = self._detect_secrets_in_file(jenkins_file)
                findings.extend(secret_findings)

            # Check for dangerous patterns
            dangerous_patterns = [
                (r'sh\s*[\'"].*\$\{.*\}.*[\'"]', "Shell Injection Risk",
                 "Shell commands with variable interpolation may be vulnerable"),
                (r'credentials\([\'"].*[\'"],\s*usernamePassword', "Credential Usage",
                 "Review credential usage for security"),
            ]

            for pattern, title, description in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category="pipeline_security",
                        title=title,
                        description=description,
                        affected_component=str(jenkins_file)
                    ))

        except Exception as e:
            logger.error(f"Error scanning Jenkinsfile: {e}")

        return findings

    def _detect_secrets_in_file(self, file_path: Path) -> List[Finding]:
        """Detect hardcoded secrets in a file."""
        findings = []

        try:
            content = file_path.read_text()

            for secret_type, pattern in self.SECRET_PATTERNS.items():
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    # Get line number
                    line_num = content[:match.start()].count('\n') + 1

                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category="secrets",
                        title=f"Potential {secret_type.replace('_', ' ').title()} Detected",
                        description=f"Possible hardcoded secret found in {file_path.name} at line {line_num}",
                        remediation="Remove hardcoded secrets and use environment variables or secret management",
                        affected_component=f"{file_path}:{line_num}",
                        metadata={
                            "secret_type": secret_type,
                            "line": line_num,
                            "matched_pattern": match.group()[:20] + "..."
                        }
                    ))

        except Exception as e:
            logger.error(f"Error detecting secrets in {file_path}: {e}")

        return findings
