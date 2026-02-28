"""Diagnostics support for Kastle Access."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

REDACT_KEYS = {
    "ipk_private_pem",
    "pkoc_private_pem",
    "security_token",
    "jwt_token",
    "email",
    "mobile_number",
    "first_name",
    "last_name",
    "external_number",
    "cookies",
}


def _redact(data: Any, depth: int = 0) -> Any:
    """Recursively redact sensitive values."""
    if depth > 10:
        return "**DEEP**"
    if isinstance(data, dict):
        return {
            k: "**REDACTED**" if k in REDACT_KEYS else _redact(v, depth + 1)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [_redact(item, depth + 1) for item in data]
    return data


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    return {
        "entry_data": _redact(dict(entry.data)),
    }
