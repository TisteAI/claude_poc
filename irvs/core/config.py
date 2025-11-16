"""Configuration management for IRVS."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import os
import json
import yaml
from pathlib import Path


@dataclass
class PolicyConfig:
    """Policy engine configuration."""
    enabled: bool = True
    policy_dir: str = "policies"
    fail_on_policy_violation: bool = True
    custom_policies: List[str] = field(default_factory=list)


@dataclass
class PackageVerificationConfig:
    """Package verification settings."""
    verify_signatures: bool = True
    verify_checksums: bool = True
    allowed_signature_types: List[str] = field(default_factory=lambda: ["gpg", "cosign", "sigstore"])
    trusted_keys: List[str] = field(default_factory=list)
    require_sbom: bool = True
    sbom_formats: List[str] = field(default_factory=lambda: ["spdx", "cyclonedx"])


@dataclass
class PipelineConfig:
    """Pipeline security scanner configuration."""
    scan_workflows: bool = True
    detect_secrets: bool = True
    check_permissions: bool = True
    verify_action_pinning: bool = True
    allowed_actions: List[str] = field(default_factory=list)
    blocked_actions: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityConfig:
    """Vulnerability scanning configuration."""
    enabled: bool = True
    sources: List[str] = field(default_factory=lambda: ["nvd", "osv", "github"])
    max_cvss_score: float = 10.0
    fail_on_critical: bool = True
    fail_on_high: bool = True
    ignore_cves: List[str] = field(default_factory=list)


@dataclass
class ProvenanceConfig:
    """Provenance verification configuration."""
    enabled: bool = True
    require_slsa_level: int = 2
    verify_build_environment: bool = True
    trusted_builders: List[str] = field(default_factory=list)
    in_toto_layout: Optional[str] = None


@dataclass
class SupplyChainConfig:
    """Supply chain analysis configuration."""
    analyze_dependencies: bool = True
    check_typosquatting: bool = True
    detect_malicious_packages: bool = True
    max_dependency_depth: int = 10
    allowed_registries: List[str] = field(default_factory=list)
    blocked_packages: List[str] = field(default_factory=list)


@dataclass
class Config:
    """Main IRVS configuration."""
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    package_verification: PackageVerificationConfig = field(default_factory=PackageVerificationConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    vulnerability: VulnerabilityConfig = field(default_factory=VulnerabilityConfig)
    provenance: ProvenanceConfig = field(default_factory=ProvenanceConfig)
    supply_chain: SupplyChainConfig = field(default_factory=SupplyChainConfig)

    output_format: str = "json"
    log_level: str = "INFO"
    cache_dir: str = ".irvs_cache"
    report_dir: str = "reports"

    @classmethod
    def from_file(cls, config_path: str) -> "Config":
        """Load configuration from file (JSON or YAML)."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(path, 'r') as f:
            if path.suffix in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            elif path.suffix == '.json':
                data = json.load(f)
            else:
                raise ValueError(f"Unsupported config format: {path.suffix}")

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create configuration from dictionary."""
        config = cls()

        if 'policy' in data:
            config.policy = PolicyConfig(**data['policy'])
        if 'package_verification' in data:
            config.package_verification = PackageVerificationConfig(**data['package_verification'])
        if 'pipeline' in data:
            config.pipeline = PipelineConfig(**data['pipeline'])
        if 'vulnerability' in data:
            config.vulnerability = VulnerabilityConfig(**data['vulnerability'])
        if 'provenance' in data:
            config.provenance = ProvenanceConfig(**data['provenance'])
        if 'supply_chain' in data:
            config.supply_chain = SupplyChainConfig(**data['supply_chain'])

        for key in ['output_format', 'log_level', 'cache_dir', 'report_dir']:
            if key in data:
                setattr(config, key, data[key])

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "policy": self.policy.__dict__,
            "package_verification": self.package_verification.__dict__,
            "pipeline": self.pipeline.__dict__,
            "vulnerability": self.vulnerability.__dict__,
            "provenance": self.provenance.__dict__,
            "supply_chain": self.supply_chain.__dict__,
            "output_format": self.output_format,
            "log_level": self.log_level,
            "cache_dir": self.cache_dir,
            "report_dir": self.report_dir
        }

    def save(self, config_path: str):
        """Save configuration to file."""
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            if path.suffix in ['.yaml', '.yml']:
                yaml.dump(self.to_dict(), f, default_flow_style=False)
            elif path.suffix == '.json':
                json.dump(self.to_dict(), f, indent=2)
            else:
                raise ValueError(f"Unsupported config format: {path.suffix}")
