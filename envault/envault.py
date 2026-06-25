from __future__ import annotations

from .scanner import Scanner, ScanResult
from .vault import Vault
from .exceptions import RestoreError


class Envault:
    def __init__(
        self,
        threshold: float = 0.5,
        categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        nlp: bool = False,
        llm_assist: bool = False,
        llm_client=None,
    ) -> None:
        if llm_assist:
            raise NotImplementedError(
                "llm_assist requires envault[llm] extra — not yet implemented in v1.0"
            )
        self._scanner = Scanner(nlp=nlp)
        self.threshold = threshold
        self.categories = categories
        self.exclude_categories = exclude_categories

    def scan(self, text: str) -> ScanResult:
        return self._scanner.scan(text, threshold=self.threshold)

    def scan_external(self, text: str, source: str = "unknown") -> ScanResult:
        return self._scanner.scan_external(text, source=source, threshold=self.threshold)

    def redact(
        self,
        text: str,
        vault: Vault | None = None,
        threshold: float | None = None,
        categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
    ) -> tuple[str, Vault]:
        """Redact secrets from text, returning (redacted_text, vault)."""
        effective_threshold = threshold if threshold is not None else self.threshold
        effective_categories = categories if categories is not None else self.categories
        effective_exclude = exclude_categories if exclude_categories is not None else self.exclude_categories

        result = self._scanner.scan(text, threshold=effective_threshold)
        if vault is None:
            vault = Vault()

        detections = result.detections
        if effective_categories:
            detections = [d for d in detections if d.category in effective_categories]
        if effective_exclude:
            detections = [d for d in detections if d.category not in effective_exclude]

        # Sort by span start descending so we can replace without offset shifting
        detections_sorted = sorted(detections, key=lambda d: d.span[0], reverse=True)

        redacted = text
        for det in detections_sorted:
            # Infer placeholder_type from category
            placeholder_type = det.category
            placeholder = vault.add(det.original, placeholder_type)
            start, end = det.span
            redacted = redacted[:start] + placeholder + redacted[end:]

        return redacted, vault

    def sanitize(
        self,
        text: str,
        placeholder: str = "[REDACTED]",
        threshold: float | None = None,
    ) -> str:
        """Redact secrets, replacing with a fixed placeholder (no vault)."""
        effective_threshold = threshold if threshold is not None else self.threshold
        result = self._scanner.scan(text, threshold=effective_threshold)
        detections_sorted = sorted(result.detections, key=lambda d: d.span[0], reverse=True)
        sanitized = text
        for det in detections_sorted:
            start, end = det.span
            sanitized = sanitized[:start] + placeholder + sanitized[end:]
        return sanitized

    def restore(self, text: str, vault: Vault) -> str:
        """Restore redacted text using the vault."""
        restored = text
        for ph, original in vault:
            restored = restored.replace(ph, original)
        return restored
