"""The Kastle Access integration."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    KastleApi,
    KastleApiError,
    KastleAuthError,
    deserialize_private_key,
)
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["button"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Kastle Access from a config entry."""
    session = async_get_clientsession(hass)

    try:
        ipk_private = deserialize_private_key(entry.data["ipk_private_pem"])
        pkoc_private = deserialize_private_key(entry.data["pkoc_private_pem"])
    except Exception as err:
        raise ConfigEntryAuthFailed("Invalid stored keys") from err

    api = KastleApi(
        session,
        ipk_private=ipk_private,
        pkoc_private=pkoc_private,
        security_token=entry.data.get("security_token"),
        jwt_token=entry.data.get("jwt_token"),
        cookies=dict(entry.data.get("cookies", {})),
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "api": api,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register rediscover service
    async def handle_rediscover(call: ServiceCall) -> None:
        """Rediscover readers for all Kastle entries."""
        for eid, data in hass.data.get(DOMAIN, {}).items():
            entry_obj = hass.config_entries.async_get_entry(eid)
            if entry_obj is None:
                continue
            entry_api: KastleApi = data["api"]
            try:
                readers_data = await entry_api.get_authorized_readers()
                readers = [
                    {
                        "reader_id": str(r["ReaderId"]),
                        "reader_designator": r.get("ReaderDesignator", ""),
                        "description": r.get("Description", ""),
                        "floor_description": r.get("FloorDescription", ""),
                        "is_remote_unlock": r.get("IsRemoteUnlock", False),
                        "building_id": r.get("BuildingId"),
                    }
                    for r in readers_data.get("AuthorizedReadersList", [])
                ]
                buildings = {
                    str(b["BuildingId"]): {
                        "address": b.get("BuildingAddress", ""),
                        "number": b.get("BuildingNumber", ""),
                    }
                    for b in readers_data.get("BuildingLocations", [])
                }

                # Also refresh cards
                cards = [
                    {
                        "card_id": c["CardID"],
                        "external_number": c["ExternalNumber"],
                        "card_format_id": c.get("CardFormatID"),
                    }
                    for c in readers_data.get("CardDetailsList", [])
                ]

                new_data = {
                    **entry_obj.data,
                    "readers": readers,
                    "buildings": buildings,
                    "cookies": entry_api.cookies,
                }
                if cards:
                    new_data["cards"] = cards

                hass.config_entries.async_update_entry(entry_obj, data=new_data)
                _LOGGER.info(
                    "Rediscovered %d readers for %s",
                    len(readers),
                    entry_obj.title,
                )

                # Reload to pick up new/removed readers
                await hass.config_entries.async_reload(eid)

            except KastleAuthError as err:
                _LOGGER.error("Auth error during rediscovery: %s", err)
                entry_obj.async_start_reauth(hass)
            except KastleApiError as err:
                _LOGGER.error("API error during rediscovery: %s", err)

    if not hass.services.has_service(DOMAIN, "rediscover_readers"):
        hass.services.async_register(DOMAIN, "rediscover_readers", handle_rediscover)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Kastle Access config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        # Remove service if no entries left
        if not hass.data.get(DOMAIN):
            hass.services.async_remove(DOMAIN, "rediscover_readers")
    return unload_ok
