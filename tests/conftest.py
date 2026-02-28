"""Shared test fixtures and homeassistant mock setup."""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

# If homeassistant is not installed (local dev), mock it so imports don't fail.
# In CI, homeassistant will be installed and these mocks are skipped.
if "homeassistant" not in sys.modules:
    # Create mock module hierarchy
    ha = ModuleType("homeassistant")
    ha.core = MagicMock()  # type: ignore[attr-defined]
    ha.exceptions = MagicMock()  # type: ignore[attr-defined]
    ha.helpers = MagicMock()  # type: ignore[attr-defined]

    for mod_name in [
        "homeassistant",
        "homeassistant.config_entries",
        "homeassistant.core",
        "homeassistant.exceptions",
        "homeassistant.helpers",
        "homeassistant.helpers.aiohttp_client",
        "homeassistant.helpers.entity_platform",
        "homeassistant.components",
        "homeassistant.components.button",
    ]:
        sys.modules[mod_name] = MagicMock()
