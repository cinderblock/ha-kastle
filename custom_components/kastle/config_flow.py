"""Config flow for the Kastle Access integration."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp
import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    KastleApi,
    KastleApiError,
    KastleAuthError,
    serialize_private_key,
)
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required("email"): str,
        vol.Required("country_code", default="+1"): str,
        vol.Required("mobile_number"): str,
    }
)

STEP_PIN_SCHEMA = vol.Schema(
    {
        vol.Required("pin"): str,
    }
)


class KastleConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Kastle Access."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._email: str = ""
        self._country_code: str = "+1"
        self._mobile_number: str = ""
        self._api: KastleApi | None = None
        self._reauth_entry: ConfigEntry | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 1: Collect email and phone number."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._email = user_input["email"].strip()
            self._country_code = user_input["country_code"].strip()
            self._mobile_number = user_input["mobile_number"].strip()

            # Prevent duplicate entries for same email
            await self.async_set_unique_id(self._email.lower())
            if not self._reauth_entry:
                self._abort_if_unique_id_configured()

            session = async_get_clientsession(self.hass)
            self._api = KastleApi(session)

            try:
                result = await self._api.validate_identity(
                    self._email, self._country_code, self._mobile_number
                )
                pin_dest = (
                    "email"
                    if result.get("PinSendTo") == 2
                    else "phone"
                    if result.get("PinSendTo") == 1
                    else "email or phone"
                )
                _LOGGER.info("Kastle PIN sent to %s for %s", pin_dest, self._email)
                return await self.async_step_pin()
            except KastleApiError as err:
                _LOGGER.error("ValidateIdentity failed: %s", err)
                errors["base"] = "cannot_connect"
            except (aiohttp.ClientError, TimeoutError):
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_SCHEMA,
            errors=errors,
        )

    async def async_step_pin(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 2: Verify the PIN sent to user's email."""
        errors: dict[str, str] = {}

        if user_input is not None:
            pin = user_input["pin"].strip()
            assert self._api is not None

            try:
                # Verify PIN
                await self._api.validate_pin(self._email, pin)

                # Register our device
                reg_data = await self._api.register_identity(self._mobile_number)
                cardholder = reg_data.get("CardholderDetails", {})
                cardholder_id = cardholder.get("CardHolderId")

                # Create digital card
                card_data = await self._api.create_digital_card()
                cards = [
                    {
                        "card_id": c["CardID"],
                        "external_number": c["ExternalNumber"],
                        "card_format_id": c.get("CardFormatID"),
                    }
                    for c in card_data.get("CardDetailsList", [])
                ]

                # Fetch authorized readers
                readers_data = await self._api.get_authorized_readers()
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

                # Extract building info
                buildings = {
                    b["BuildingId"]: {
                        "address": b.get("BuildingAddress", ""),
                        "number": b.get("BuildingNumber", ""),
                    }
                    for b in readers_data.get("BuildingLocations", [])
                }

                entry_data = {
                    "email": self._email,
                    "country_code": self._country_code,
                    "mobile_number": self._mobile_number,
                    "ipk_private_pem": serialize_private_key(self._api.ipk_private),
                    "pkoc_private_pem": serialize_private_key(self._api.pkoc_private),
                    "security_token": self._api.security_token,
                    "jwt_token": self._api.jwt_token,
                    "cardholder_id": cardholder_id,
                    "first_name": cardholder.get("FirstName", ""),
                    "last_name": cardholder.get("LastName", ""),
                    "cards": cards,
                    "readers": readers,
                    "buildings": buildings,
                    "cookies": self._api.cookies,
                }

                title = f"Kastle - {cardholder.get('FirstName', self._email)}"

                if self._reauth_entry:
                    self.hass.config_entries.async_update_entry(
                        self._reauth_entry, data=entry_data
                    )
                    await self.hass.config_entries.async_reload(
                        self._reauth_entry.entry_id
                    )
                    return self.async_abort(reason="reauth_successful")

                return self.async_create_entry(title=title, data=entry_data)

            except KastleAuthError as err:
                _LOGGER.error("PIN verification failed: %s", err)
                errors["base"] = "invalid_auth"
            except KastleApiError as err:
                _LOGGER.error("Registration failed: %s", err)
                errors["base"] = "api_error"
            except (aiohttp.ClientError, TimeoutError):
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="pin",
            data_schema=STEP_PIN_SCHEMA,
            errors=errors,
            description_placeholders={"email": self._email},
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Handle re-authentication when token expires."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        self._email = entry_data.get("email", "")
        self._country_code = entry_data.get("country_code", "+1")
        self._mobile_number = entry_data.get("mobile_number", "")
        return await self.async_step_user()
