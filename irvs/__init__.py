"""
Infrastructure Resilience Verification System (IRVS)

A comprehensive security tool for package and development pipeline verification
for critical governmental software infrastructure.
"""

__version__ = "0.1.0"
__author__ = "IRVS Security Team"
__license__ = "Apache-2.0"

from irvs.core.verification import VerificationEngine
from irvs.core.config import Config

__all__ = ["VerificationEngine", "Config", "__version__"]
