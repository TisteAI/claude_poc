"""Core components of the IRVS system."""

from irvs.core.verification import VerificationEngine
from irvs.core.config import Config
from irvs.core.result import VerificationResult, Severity

__all__ = ["VerificationEngine", "Config", "VerificationResult", "Severity"]
