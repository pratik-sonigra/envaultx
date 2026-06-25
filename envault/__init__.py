"""envault — What your LLM sees, stays safe."""

from .envault import Envault
from .vault import Vault
from .scanner import Scanner, ScanResult, Detection
from .exceptions import (
    EnvaultError,
    DetectionError,
    VaultError,
    RestoreError,
    VaultSerializationError,
    ConfigurationError,
    DependencyError,
)

__version__ = "0.1.0"
__all__ = [
    "Envault",
    "Vault",
    "Scanner",
    "ScanResult",
    "Detection",
    "EnvaultError",
    "DetectionError",
    "VaultError",
    "RestoreError",
    "VaultSerializationError",
    "ConfigurationError",
    "DependencyError",
]
