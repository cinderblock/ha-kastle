"""Lock platform for the Kastle Access integration."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.lock import LockEntity, LockEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import KastleApi, KastleApiError, KastleAuthError
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Seconds to show "unlocking" state before reverting to "locked"
UNLOCK_DISPLAY_SECONDS = 5


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Kastle lock entities from a config entry."""
    api: KastleApi = hass.data[DOMAIN][entry.entry_id]["api"]

    readers = entry.data.get("readers", [])
    cards = entry.data.get("cards", [])
    buildings = entry.data.get("buildings", {})

    # Use the first card with format 32 (BLE), falling back to any card
    card = next((c for c in cards if c.get("card_format_id") == 32), None)
    if not card and cards:
        card = cards[0]

    entities: list[KastleLock] = []
    for reader in readers:
        if not reader.get("is_remote_unlock"):
            continue

        building_id = str(reader.get("building_id", ""))
        building = buildings.get(building_id, {})

        entities.append(
            KastleLock(
                api=api,
                entry=entry,
                reader=reader,
                card=card,
                building=building,
            )
        )

    if not entities:
        _LOGGER.warning("No remote-unlock readers found for %s", entry.title)

    async_add_entities(entities)


class KastleLock(LockEntity):
    """A Kastle access-controlled door."""

    _attr_has_entity_name = True
    _attr_supported_features = LockEntityFeature.OPEN
    _attr_should_poll = False

    def __init__(
        self,
        api: KastleApi,
        entry: ConfigEntry,
        reader: dict[str, Any],
        card: dict[str, Any] | None,
        building: dict[str, Any],
    ) -> None:
        """Initialize the lock."""
        self._api = api
        self._entry = entry
        self._reader = reader
        self._card = card
        self._building = building
        self._is_unlocking = False

        reader_id = reader["reader_id"]
        cardholder_id = entry.data.get("cardholder_id", "unknown")
        self._attr_unique_id = f"kastle_{cardholder_id}_{reader_id}"

        # Use the description as the name (more human-readable than designator)
        description = reader.get("description", "")
        designator = reader.get("reader_designator", "")
        self._attr_name = description or designator or f"Reader {reader_id}"

        # Extra state attributes
        self._attr_extra_state_attributes = {
            "reader_id": reader_id,
            "reader_designator": designator,
            "description": description,
            "floor": reader.get("floor_description", ""),
            "building_address": building.get("address", ""),
            "building_number": building.get("number", ""),
            "card_id": card["card_id"] if card else None,
            "external_number": card["external_number"] if card else None,
        }

    @property
    def device_info(self) -> dict[str, Any]:
        """Return device info to group entities by building."""
        building_num = self._building.get("number", "unknown")
        building_addr = self._building.get("address", "Kastle Building")
        return {
            "identifiers": {(DOMAIN, f"building_{building_num}")},
            "name": f"Kastle {building_num}",
            "manufacturer": "Kastle Systems",
            "model": building_addr,
        }

    @property
    def is_locked(self) -> bool:
        """Return True — Kastle doors auto-lock, state is always assumed locked."""
        return True

    @property
    def is_unlocking(self) -> bool:
        """Return True when an unlock command is in progress."""
        return self._is_unlocking

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock (unlatch) the door."""
        await self._do_unlatch()

    async def async_open(self, **kwargs: Any) -> None:
        """Open (unlatch) the door — same as unlock for Kastle."""
        await self._do_unlatch()

    async def _do_unlatch(self) -> None:
        """Send the UnlatchDoor command."""
        if not self._card:
            raise HomeAssistantError("No card available for this door")

        self._is_unlocking = True
        self.async_write_ha_state()

        try:
            await self._api.unlock_door(
                reader_designator=self._reader["reader_designator"],
                external_number=self._card["external_number"],
                reader_id=self._reader["reader_id"],
                card_id=self._card["card_id"],
                first_name=self._entry.data.get("first_name", ""),
                last_name=self._entry.data.get("last_name", ""),
            )
            _LOGGER.info("Unlocked %s", self._attr_name)
        except KastleAuthError as err:
            self._is_unlocking = False
            self.async_write_ha_state()
            _LOGGER.error("Auth error unlocking %s: %s", self._attr_name, err)
            self._entry.async_start_reauth(self.hass)
            raise HomeAssistantError(
                f"Authentication expired. Re-authentication required: {err}"
            ) from err
        except KastleApiError as err:
            self._is_unlocking = False
            self.async_write_ha_state()
            raise HomeAssistantError(f"Failed to unlock: {err}") from err
        except Exception:
            self._is_unlocking = False
            self.async_write_ha_state()
            raise

        # Briefly show "unlocking" then revert to locked
        await asyncio.sleep(UNLOCK_DISPLAY_SECONDS)
        self._is_unlocking = False
        self.async_write_ha_state()
