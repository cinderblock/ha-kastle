"""Tests for diagnostics redaction."""

from __future__ import annotations

from custom_components.kastle.diagnostics import _redact


def test_redact_simple_keys():
    """Sensitive keys should be redacted."""
    data = {
        "email": "test@example.com",
        "security_token": "secret123",
        "readers": [{"reader_id": "123"}],
    }
    result = _redact(data)
    assert result["email"] == "**REDACTED**"
    assert result["security_token"] == "**REDACTED**"
    assert result["readers"] == [{"reader_id": "123"}]


def test_redact_nested_dicts():
    """Redaction should work on nested structures."""
    data = {
        "cards": [
            {"card_id": "abc", "external_number": "secret"},
        ],
    }
    result = _redact(data)
    assert result["cards"][0]["card_id"] == "abc"
    assert result["cards"][0]["external_number"] == "**REDACTED**"


def test_redact_preserves_non_sensitive():
    """Non-sensitive keys should pass through unchanged."""
    data = {
        "cardholder_id": 12345,
        "readers": [{"reader_id": "500", "description": "Main Door"}],
        "buildings": {"1": {"address": "123 St", "number": "B1"}},
    }
    result = _redact(data)
    assert result == data


def test_redact_all_sensitive_keys():
    """All defined sensitive keys should be redacted."""
    data = {
        "ipk_private_pem": "pem1",
        "pkoc_private_pem": "pem2",
        "security_token": "tok",
        "jwt_token": "jwt",
        "email": "a@b.c",
        "mobile_number": "555",
        "first_name": "John",
        "last_name": "Doe",
        "external_number": "ext",
        "cookies": {"a": "b"},
    }
    result = _redact(data)
    for key in data:
        assert result[key] == "**REDACTED**"


def test_redact_deep_nesting_limit():
    """Deeply nested structures should hit the depth limit."""
    data: dict = {"a": {}}
    current = data["a"]
    for _ in range(15):
        current["nested"] = {}
        current = current["nested"]
    current["email"] = "deep@example.com"

    result = _redact(data)
    # Should not raise, and deep values become **DEEP**
    assert "**DEEP**" in str(result)
