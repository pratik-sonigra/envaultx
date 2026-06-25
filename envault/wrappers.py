from __future__ import annotations

from typing import Any

from .envault import Envault
from .vault import Vault
from .exceptions import DependencyError


class AnthropicVault:
    """Wraps anthropic.Anthropic to auto-redact user messages before sending."""

    def __init__(
        self,
        threshold: float = 0.5,
        categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        **anthropic_kwargs: Any,
    ) -> None:
        try:
            import anthropic
        except ImportError:
            raise DependencyError(
                "AnthropicVault requires anthropic: pip install envault[anthropic]"
            )
        self._client = anthropic.Anthropic(**anthropic_kwargs)
        self._ev = Envault(threshold=threshold, categories=categories, exclude_categories=exclude_categories)
        self.messages = _AnthropicMessagesProxy(self._client, self._ev)


class _AnthropicMessagesProxy:
    def __init__(self, client: Any, ev: Envault) -> None:
        self._client = client
        self._ev = ev

    def create(self, messages: list[dict], **kwargs: Any) -> Any:
        vault = Vault()
        redacted_messages = []
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    redacted_content, vault = self._ev.redact(content, vault=vault)
                    redacted_messages.append({**msg, "content": redacted_content})
                elif isinstance(content, list):
                    redacted_parts = []
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            redacted_text, vault = self._ev.redact(part["text"], vault=vault)
                            redacted_parts.append({**part, "text": redacted_text})
                        else:
                            redacted_parts.append(part)
                    redacted_messages.append({**msg, "content": redacted_parts})
                else:
                    redacted_messages.append(msg)
            else:
                redacted_messages.append(msg)

        response = self._client.messages.create(messages=redacted_messages, **kwargs)
        response._vault = vault  # type: ignore[attr-defined]
        return response


class OpenAIVault:
    """Wraps openai.OpenAI to auto-redact user messages before sending."""

    def __init__(
        self,
        threshold: float = 0.5,
        categories: list[str] | None = None,
        exclude_categories: list[str] | None = None,
        **openai_kwargs: Any,
    ) -> None:
        try:
            import openai
        except ImportError:
            raise DependencyError(
                "OpenAIVault requires openai: pip install envault[openai]"
            )
        self._client = openai.OpenAI(**openai_kwargs)
        self._ev = Envault(threshold=threshold, categories=categories, exclude_categories=exclude_categories)
        self.chat = _OpenAIChatProxy(self._client, self._ev)


class _OpenAIChatProxy:
    def __init__(self, client: Any, ev: Envault) -> None:
        self._client = client
        self._ev = ev
        self.completions = _OpenAICompletionsProxy(client, ev)


class _OpenAICompletionsProxy:
    def __init__(self, client: Any, ev: Envault) -> None:
        self._client = client
        self._ev = ev

    def create(self, messages: list[dict], **kwargs: Any) -> Any:
        vault = Vault()
        redacted_messages = []
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    redacted_content, vault = self._ev.redact(content, vault=vault)
                    redacted_messages.append({**msg, "content": redacted_content})
                elif isinstance(content, list):
                    redacted_parts = []
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            redacted_text, vault = self._ev.redact(part["text"], vault=vault)
                            redacted_parts.append({**part, "text": redacted_text})
                        else:
                            redacted_parts.append(part)
                    redacted_messages.append({**msg, "content": redacted_parts})
                else:
                    redacted_messages.append(msg)
            else:
                redacted_messages.append(msg)

        response = self._client.chat.completions.create(messages=redacted_messages, **kwargs)
        response._vault = vault  # type: ignore[attr-defined]
        return response
