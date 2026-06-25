import pytest
from envault.vault import Vault


def test_add_creates_placeholder():
    v = Vault()
    ph = v.add("mysecret", "API_KEY")
    assert ph == "[API_KEY_1]"


def test_add_deduplication():
    v = Vault()
    ph1 = v.add("mysecret", "API_KEY")
    ph2 = v.add("mysecret", "API_KEY")
    assert ph1 == ph2
    assert v.count == 1


def test_type_counters_increment():
    v = Vault()
    ph1 = v.add("secret1", "API_KEY")
    ph2 = v.add("secret2", "API_KEY")
    assert ph1 == "[API_KEY_1]"
    assert ph2 == "[API_KEY_2]"


def test_different_types_independent_counters():
    v = Vault()
    v.add("email@example.com", "EMAIL")
    v.add("sk-abc123", "OPENAI_KEY")
    assert "[EMAIL_1]" in v
    assert "[OPENAI_KEY_1]" in v


def test_contains():
    v = Vault()
    ph = v.add("mysecret", "TOKEN")
    assert ph in v
    assert "[NONEXISTENT_1]" not in v


def test_iter():
    v = Vault()
    v.add("a", "X")
    v.add("b", "Y")
    items = dict(v)
    assert len(items) == 2


def test_categories():
    v = Vault()
    v.add("foo", "EMAIL")
    v.add("bar", "API_KEY")
    cats = v.categories
    assert "EMAIL" in cats
    assert "API_KEY" in cats


def test_to_dict():
    v = Vault()
    v.add("secret", "TOKEN")
    d = v.to_dict()
    assert isinstance(d, dict)
    assert "[TOKEN_1]" in d
    assert d["[TOKEN_1]"] == "secret"


def test_get_original():
    v = Vault()
    ph = v.add("hello", "GREETING")
    assert v.get_original(ph) == "hello"
    assert v.get_original("[NONEXISTENT_1]") is None


def test_get_placeholder():
    v = Vault()
    ph = v.add("hello", "GREETING")
    assert v.get_placeholder("hello") == ph
    assert v.get_placeholder("unknown") is None


def test_is_empty():
    v = Vault()
    assert v.is_empty
    v.add("x", "T")
    assert not v.is_empty


def test_len():
    v = Vault()
    v.add("a", "T")
    v.add("b", "T")
    assert len(v) == 2
