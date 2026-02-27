"""Async API client for the Kastle Access system."""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from typing import Any

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .const import (
    APPLICATION_GUID,
    BASE_URL,
    DOTNET_EPOCH_OFFSET,
    ERR_NOT_REGISTERED,
    REQUEST_TOKEN,
    USER_AGENT,
)

_LOGGER = logging.getLogger(__name__)


class KastleApiError(Exception):
    """Base exception for Kastle API errors."""

    def __init__(self, message: str, error_code: int = 0) -> None:
        super().__init__(message)
        self.error_code = error_code


class KastleAuthError(KastleApiError):
    """Authentication/token error — credentials need refresh."""


def generate_nonce() -> str:
    """Generate a fresh .NET DateTime.UtcNow.Ticks nonce."""
    unix_ms = int(time.time() * 1000)
    ticks = (unix_ms * 10000) + DOTNET_EPOCH_OFFSET
    return str(ticks)


def ec_sign_nonce(private_key: ec.EllipticCurvePrivateKey, nonce_str: str) -> str:
    """Sign a nonce with the Kastle double-hash ECDSA algorithm.

    1. SHA-256(nonce_str as UTF-8)
    2. Sign that hash with SHA256withECDSA (hashes again internally)
    3. Convert DER → raw r||s (64 bytes, uppercase hex)
    """
    sha256_nonce = hashlib.sha256(nonce_str.encode("utf-8")).digest()
    der_sig = private_key.sign(sha256_nonce, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return raw_sig.hex().upper()


def get_public_key_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Get uncompressed EC public key as uppercase hex (65 bytes, 04 prefix)."""
    return (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        .hex()
        .upper()
    )


def generate_ec_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate a fresh EC P-256 keypair."""
    return ec.generate_private_key(ec.SECP256R1())


def serialize_private_key(key: ec.EllipticCurvePrivateKey) -> str:
    """Serialize an EC private key to PEM string."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def deserialize_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    """Deserialize a PEM string to an EC private key."""
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        msg = "Expected EC private key"
        raise TypeError(msg)
    return key


class KastleApi:
    """Async client for the Kastle Access API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        ipk_private: ec.EllipticCurvePrivateKey | None = None,
        pkoc_private: ec.EllipticCurvePrivateKey | None = None,
        security_token: str | None = None,
        jwt_token: str | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        self._session = session
        self.ipk_private = ipk_private
        self.pkoc_private = pkoc_private
        self.security_token = security_token
        self.jwt_token = jwt_token
        self.cookies: dict[str, str] = cookies or {}

    async def _api_call(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make a POST API call and return parsed JSON."""
        url = f"{BASE_URL}/{path}"
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
            "requesttoken": REQUEST_TOKEN,
            "enterprisetype": "2",
        }
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if extra_headers:
            headers.update(extra_headers)

        _LOGGER.debug("API call: POST %s (headers: %s)", path, list(headers.keys()))

        async with self._session.post(
            url, json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=20)
        ) as resp:
            # Capture set-cookie headers
            for cookie_header in resp.headers.getall("Set-Cookie", []):
                cookie_str = cookie_header.split(";")[0]
                if "=" in cookie_str:
                    name, val = cookie_str.split("=", 1)
                    self.cookies[name.strip()] = val.strip()

            resp_text = await resp.text()
            _LOGGER.debug(
                "API response %s: HTTP %s, body=%s",
                path,
                resp.status,
                resp_text[:500],
            )

            try:
                import json as json_mod

                raw = json_mod.loads(resp_text)
            except (json_mod.JSONDecodeError, ValueError) as parse_err:
                raise KastleApiError(
                    f"Invalid JSON from {path}: {resp_text[:200]}"
                ) from parse_err

            # Handle unexpected response types (string, None, etc.)
            if not isinstance(raw, dict):
                resp_text = await resp.text() if not isinstance(raw, str) else raw
                _LOGGER.error(
                    "Kastle API %s returned non-dict (%s): %s",
                    path,
                    type(raw).__name__,
                    resp_text[:500],
                )
                raise KastleApiError(
                    f"Unexpected response from {path}: {resp_text[:200]}",
                )

            data: dict[str, Any] = raw

            if not data.get("IsSuccess", False):
                error_code = data.get("ErrorCode", 0)
                message = data.get("Message", f"HTTP {resp.status}")
                token_status = data.get("TokenStatus", "")

                if (
                    error_code == ERR_NOT_REGISTERED
                    or token_status.upper() == "INVALID"
                ):
                    raise KastleAuthError(message, error_code)

                raise KastleApiError(message, error_code)

            return data

    def generate_keys(self) -> tuple[str, str]:
        """Generate fresh IPK and PKOC keypairs. Returns (ipk_hex, pkoc_hex)."""
        self.ipk_private = generate_ec_keypair()
        self.pkoc_private = generate_ec_keypair()
        return (
            get_public_key_hex(self.ipk_private),
            get_public_key_hex(self.pkoc_private),
        )

    async def validate_identity(
        self,
        email: str,
        country_code: str,
        mobile_number: str,
    ) -> dict[str, Any]:
        """Step 1: Send email/phone to get JWT and trigger PIN email."""
        if not self.ipk_private:
            self.generate_keys()

        assert self.ipk_private is not None
        ipk_hex = get_public_key_hex(self.ipk_private)

        body = {
            "ApplicationName": "KastlePresence",
            "IPK": ipk_hex,
            "EmailId": email,
            "CountryCode": country_code,
            "MobileNumber": mobile_number,
            "ApplicationGuid": APPLICATION_GUID,
        }

        data = await self._api_call("IPK/ValidateIdentity", body)
        inner = data.get("Data", {})
        self.jwt_token = inner.get("JWTToken")
        return inner

    async def validate_pin(self, email: str, pin: str) -> None:
        """Step 2: Verify the 6-digit PIN from email."""
        headers: dict[str, str] = {}
        if self.jwt_token:
            headers["authorization"] = f"Bearer {self.jwt_token}"
        if self.ipk_private:
            headers["ipk"] = get_public_key_hex(self.ipk_private)
        headers["nonce"] = generate_nonce()
        headers["digitalsignature"] = ""

        body = {
            "Email": email,
            "EMailTempPin": int(pin),
            "MobileTempPin": 0,
        }

        await self._api_call("IPK/ValidateMobileTempPin", body, headers)

    async def get_available_keys(self) -> dict[str, Any]:
        """Fetch available keys (pre-registration). Returns CardholderId and details."""
        if not self.ipk_private:
            msg = "IPK key not generated"
            raise KastleApiError(msg)

        nonce = generate_nonce()
        ipk_nonce = generate_nonce()
        ipk_sig = ec_sign_nonce(self.ipk_private, ipk_nonce)

        headers = {
            "authorization": f"Bearer {self.jwt_token}",
            "ipk": get_public_key_hex(self.ipk_private),
            "ipk_nonce": ipk_nonce,
            "ipk_digitalsignature": ipk_sig,
            "nonce": nonce,
            "digitalsignature": "",
        }

        body = {"DeviceManufacturer": "Apple"}

        data = await self._api_call("IPK/GetAvailableKeys", body, headers)
        return data.get("Data", {})

    async def register_identity(
        self, mobile_number: str, cardholder_id: int | None = None
    ) -> dict[str, Any]:
        """Step 3: Register device with our PKOC keypair."""
        if not self.ipk_private or not self.pkoc_private:
            msg = "Keys not generated"
            raise KastleApiError(msg)

        nonce = generate_nonce()
        ipk_sig = ec_sign_nonce(self.ipk_private, nonce)

        headers = {
            "authorization": f"Bearer {self.jwt_token}",
            "ipk": get_public_key_hex(self.ipk_private),
            "ipk_nonce": nonce,
            "ipk_digitalsignature": ipk_sig,
        }

        now_str = time.strftime("%Y-%m-%dT%H:%M:%S.000%z")
        if len(now_str) > 5 and now_str[-5] != ":":
            now_str = now_str[:-2] + ":" + now_str[-2:]
        device_time = time.strftime("%Y-%m-%d %H:%M:%S")
        device_reg_id = uuid.uuid4().hex

        body: dict[str, Any] = {
            "MobileCarrier": "--",
            "AppVersion": "7.2.0",
            "DeviceModel": "iPhone",
            "VoIPDeviceRegistrationID": device_reg_id,
            "ApplicationName": "KastlePresence",
            "DeviceManufacturer": "Apple",
            "CountryId": 2,
            "SdkVersion": "4.3.1",
            "PKOC": get_public_key_hex(self.pkoc_private),
            "DeviceRegistrationID": device_reg_id,
            "UpdatedTime": now_str,
            "CountryCode": "",
            "WebApiVersion": "1.6",
            "IsAppStoreBuild": True,
            "DeviceOS": "26.3",
            "MobileNumber": mobile_number,
            "ApplicationBundleIdentifier": "com.KastleSystems.KastlePresence",
            "UserType": 0,
            "DeviceBuildId": "26.3",
            "DeviceTime": device_time,
        }

        if cardholder_id:
            body["CardholderId"] = cardholder_id
            body["UpdateBy"] = str(cardholder_id)

        data = await self._api_call("IPK/RegisterIdentity", body, headers)
        inner = data.get("Data", {})
        self.security_token = inner.get("SecurityToken")
        return inner

    async def create_digital_card(self) -> dict[str, Any]:
        """Step 4: Create digital card to get CardId/ExternalNumber."""
        if not self.pkoc_private:
            msg = "PKOC key not generated"
            raise KastleApiError(msg)

        nonce = generate_nonce()
        headers = {
            "authorization": f"Bearer {self.jwt_token}",
            "securitytoken": self.security_token or "",
            "nonce": nonce,
            "digitalsignature": "",
        }

        body = {
            "CardFormatId": [32, 53],
            "PKOC": get_public_key_hex(self.pkoc_private),
        }

        data = await self._api_call("4.3/CreateDigitalCard", body, headers)
        return data.get("Data", {})

    async def get_authorized_readers(self) -> dict[str, Any]:
        """Fetch authorized readers list. Returns full response Data."""
        if not self.pkoc_private or not self.security_token:
            msg = "Not registered"
            raise KastleApiError(msg)

        nonce = generate_nonce()
        sig = ec_sign_nonce(self.pkoc_private, nonce)

        headers = {
            "securitytoken": self.security_token,
            "nonce": nonce,
            "digitalsignature": sig,
        }

        body = {
            "DeviceManufacturer": "Apple",
            "WebApiVersion": "1.6",
            "AppVersion": "7.2.0",
            "PKOC": get_public_key_hex(self.pkoc_private),
            "SdkVersion": "4.3.1",
            "DeviceOS": "26.3",
            "IsAppUpdated": True,
            "IPK": get_public_key_hex(self.ipk_private) if self.ipk_private else "",
            "DeviceModel": "iPhone",
            "LastUpdateDateTime": time.strftime("%Y-%m-%d"),
        }

        data = await self._api_call("AuthorizedReadersList", body, headers)
        return data.get("Data", {})

    async def unlock_door(
        self,
        *,
        reader_designator: str,
        external_number: str,
        reader_id: str,
        card_id: str,
        first_name: str,
        last_name: str,
    ) -> dict[str, Any]:
        """Send an UnlatchDoor request with a properly signed nonce."""
        if not self.pkoc_private or not self.security_token:
            msg = "Not registered"
            raise KastleApiError(msg)

        nonce = generate_nonce()
        signature = ec_sign_nonce(self.pkoc_private, nonce)

        headers = {
            "securitytoken": self.security_token,
            "nonce": nonce,
            "digitalsignature": signature,
        }

        body = {
            "ReaderDesignator": reader_designator,
            "ExternalNumber": external_number,
            "FirstName": first_name,
            "LastName": last_name,
            "ReaderId": reader_id,
            "CardId": card_id,
        }

        return await self._api_call("UnlatchDoor", body, headers)
