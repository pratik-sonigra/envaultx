import json
from typing import Iterator

from .exceptions import DependencyError, VaultSerializationError


class Vault:
    def __init__(self) -> None:
        self._placeholder_to_original: dict[str, str] = {}
        self._original_to_placeholder: dict[str, str] = {}
        self._type_counters: dict[str, int] = {}

    def add(self, original: str, placeholder_type: str) -> str:
        """Returns placeholder for original, creating one if new."""
        if original in self._original_to_placeholder:
            return self._original_to_placeholder[original]
        idx = self._type_counters.get(placeholder_type, 0) + 1
        self._type_counters[placeholder_type] = idx
        placeholder = f"[{placeholder_type}_{idx}]"
        self._placeholder_to_original[placeholder] = original
        self._original_to_placeholder[original] = placeholder
        return placeholder

    def get_original(self, placeholder: str) -> str | None:
        return self._placeholder_to_original.get(placeholder)

    def get_placeholder(self, original: str) -> str | None:
        return self._original_to_placeholder.get(original)

    def to_dict(self) -> dict[str, str]:
        return dict(self._placeholder_to_original)

    def to_encrypted_bytes(self, password: str) -> bytes:
        """Serialize vault to encrypted bytes. Requires cryptography package."""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            import os
        except ImportError:
            raise DependencyError(
                "Encryption requires the cryptography package: pip install envault[crypto]"
            )
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        payload = json.dumps(self._placeholder_to_original).encode()
        encrypted = f.encrypt(payload)
        return salt + encrypted

    @classmethod
    def from_encrypted_bytes(cls, data: bytes, password: str) -> "Vault":
        """Deserialize vault from encrypted bytes. Requires cryptography package."""
        try:
            from cryptography.fernet import Fernet, InvalidToken
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
        except ImportError:
            raise DependencyError(
                "Encryption requires the cryptography package: pip install envault[crypto]"
            )
        try:
            salt = data[:16]
            encrypted = data[16:]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            payload = f.decrypt(encrypted)
            mapping: dict[str, str] = json.loads(payload.decode())
        except (InvalidToken, json.JSONDecodeError, Exception) as e:
            raise VaultSerializationError(f"Failed to decrypt vault: {e}") from e
        vault = cls()
        for placeholder, original in mapping.items():
            vault._placeholder_to_original[placeholder] = original
            vault._original_to_placeholder[original] = placeholder
            # Reconstruct type counters
            try:
                inner = placeholder.strip("[]")
                parts = inner.rsplit("_", 1)
                if len(parts) == 2:
                    ptype, idx_str = parts
                    idx = int(idx_str)
                    current = vault._type_counters.get(ptype, 0)
                    vault._type_counters[ptype] = max(current, idx)
            except (ValueError, AttributeError):
                pass
        return vault

    @property
    def is_empty(self) -> bool:
        return len(self._placeholder_to_original) == 0

    @property
    def count(self) -> int:
        return len(self._placeholder_to_original)

    @property
    def categories(self) -> set[str]:
        result: set[str] = set()
        for placeholder in self._placeholder_to_original:
            try:
                inner = placeholder.strip("[]")
                parts = inner.rsplit("_", 1)
                if len(parts) == 2:
                    result.add(parts[0])
            except (AttributeError, ValueError):
                pass
        return result

    def __len__(self) -> int:
        return self.count

    def __contains__(self, placeholder: object) -> bool:
        return placeholder in self._placeholder_to_original

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._placeholder_to_original.items())
