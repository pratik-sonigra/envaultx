"""
Tests for AnthropicVault and OpenAIVault wrappers.
Skipped if anthropic/openai are not installed.
Uses unittest.mock to intercept API calls.
"""
import pytest

anthropic = pytest.importorskip("anthropic")

from unittest.mock import MagicMock, patch
from envault.wrappers import AnthropicVault


def make_mock_response():
    resp = MagicMock()
    resp.content = [MagicMock(text="Sure, here is the answer.")]
    return resp


def test_anthropic_vault_redacts_user_message():
    """User message with a secret should be redacted before hitting the API."""
    captured = {}

    def fake_create(messages, **kwargs):
        captured["messages"] = messages
        return make_mock_response()

    with patch("anthropic.Anthropic") as MockClient:
        instance = MockClient.return_value
        instance.messages.create.side_effect = fake_create

        wrapper = AnthropicVault.__new__(AnthropicVault)
        import anthropic as _anthropic
        wrapper._client = instance
        from envault import Envault
        wrapper._ev = Envault()
        from envault.wrappers import _AnthropicMessagesProxy
        wrapper.messages = _AnthropicMessagesProxy(instance, wrapper._ev)

        secret_text = "My API key is sk-abcdefghijklmnopqrstuvwxyz1234567890"
        wrapper.messages.create(
            messages=[{"role": "user", "content": secret_text}],
            model="claude-3-opus-20240229",
            max_tokens=100,
        )

    sent = captured["messages"][0]["content"]
    assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in sent


def test_anthropic_vault_vault_attached_to_response():
    """Response should have _vault attribute after call."""
    from envault.wrappers import _AnthropicMessagesProxy
    from envault import Envault
    from envault.vault import Vault

    instance = MagicMock()
    instance.messages.create.return_value = make_mock_response()

    proxy = _AnthropicMessagesProxy(instance, Envault())
    response = proxy.create(
        messages=[{"role": "user", "content": "my key sk-abcdefghijklmnopqrstuvwxyz1234567890"}],
        model="claude-3-haiku-20240307",
        max_tokens=10,
    )
    assert hasattr(response, "_vault")
    assert isinstance(response._vault, Vault)


def test_anthropic_vault_non_user_messages_not_redacted():
    """System and assistant messages should pass through unchanged."""
    from envault.wrappers import _AnthropicMessagesProxy
    from envault import Envault

    captured = {}

    def fake_create(messages, **kwargs):
        captured["messages"] = messages
        return make_mock_response()

    instance = MagicMock()
    instance.messages.create.side_effect = fake_create

    proxy = _AnthropicMessagesProxy(instance, Envault())
    proxy.create(
        messages=[
            {"role": "system", "content": "You are a helpful assistant with key sk-abc123defghijklmnopqrstuvwxyz"},
            {"role": "user", "content": "Hello"},
        ],
        model="claude-3-haiku-20240307",
        max_tokens=10,
    )
    # System message should pass through unchanged
    system_msg = captured["messages"][0]["content"]
    assert "sk-abc123defghijklmnopqrstuvwxyz" in system_msg


# OpenAI tests (skip if not installed)
try:
    import openai as _openai_module
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


@pytest.mark.skipif(not HAS_OPENAI, reason="openai not installed")
def test_openai_vault_redacts_user_message():
    from envault.wrappers import _OpenAICompletionsProxy
    from envault import Envault

    captured = {}

    def fake_create(messages, **kwargs):
        captured["messages"] = messages
        resp = MagicMock()
        resp.choices = [MagicMock()]
        return resp

    instance = MagicMock()
    instance.chat.completions.create.side_effect = fake_create

    proxy = _OpenAICompletionsProxy(instance, Envault())
    proxy.create(
        messages=[{"role": "user", "content": "key is sk-abcdefghijklmnopqrstuvwxyz1234567890"}],
        model="gpt-4",
    )
    sent = captured["messages"][0]["content"]
    assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in sent
