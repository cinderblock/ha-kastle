"""Tests for Kastle crypto functions (signing, keys, serialization)."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from custom_components.kastle.api import (
    deserialize_private_key,
    ec_sign_nonce,
    generate_ec_keypair,
    generate_nonce,
    get_public_key_hex,
    serialize_private_key,
)
from custom_components.kastle.const import DOTNET_EPOCH_OFFSET


def test_generate_nonce_is_dotnet_ticks():
    """Nonce should be a .NET ticks string (large integer)."""
    nonce = generate_nonce()
    ticks = int(nonce)
    # Must be greater than the .NET epoch offset (i.e., after 1970)
    assert ticks > DOTNET_EPOCH_OFFSET
    # Should be roughly current time: within 10 seconds of now
    import time

    expected = (int(time.time() * 1000) * 10000) + DOTNET_EPOCH_OFFSET
    assert abs(ticks - expected) < 10_000_0000  # 10 seconds in ticks


def test_generate_keypair_is_p256():
    """Generated key should be an EC P-256 private key."""
    key = generate_ec_keypair()
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)


def test_public_key_hex_format():
    """Public key hex should be 130 chars (65 bytes), starting with 04."""
    key = generate_ec_keypair()
    hex_str = get_public_key_hex(key)
    assert len(hex_str) == 130
    assert hex_str.startswith("04")
    assert hex_str == hex_str.upper()


def test_serialize_deserialize_roundtrip():
    """Serializing then deserializing a key should produce an equivalent key."""
    original = generate_ec_keypair()
    pem = serialize_private_key(original)
    restored = deserialize_private_key(pem)

    assert get_public_key_hex(original) == get_public_key_hex(restored)


def test_serialize_produces_pem():
    """Serialized key should be a valid PEM string."""
    key = generate_ec_keypair()
    pem = serialize_private_key(key)
    assert pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert pem.strip().endswith("-----END PRIVATE KEY-----")


def test_ec_sign_nonce_produces_valid_signature():
    """Signature should be 128 hex chars (64 bytes r||s) and verifiable."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    key = generate_ec_keypair()
    nonce = "638789760000000000"

    sig_hex = ec_sign_nonce(key, nonce)

    # Should be uppercase hex, 128 chars = 64 bytes
    assert len(sig_hex) == 128
    assert sig_hex == sig_hex.upper()

    # Verify the double-hash: the signing algorithm does SHA256(SHA256(nonce))
    # We can verify by re-signing and checking the format is consistent
    sig_hex2 = ec_sign_nonce(key, nonce)
    # ECDSA is non-deterministic, so signatures differ but both should be valid length
    assert len(sig_hex2) == 128

    # Verify r and s are valid 32-byte big-endian integers
    r = int(sig_hex[:64], 16)
    s = int(sig_hex[64:], 16)
    assert r > 0
    assert s > 0

    # Reconstruct DER and verify with the public key
    der_sig = utils.encode_dss_signature(r, s)
    sha256_nonce = hashlib.sha256(nonce.encode("utf-8")).digest()
    # verify() with SHA256 will hash again internally, matching the double-hash
    key.public_key().verify(der_sig, sha256_nonce, ec.ECDSA(hashes.SHA256()))


def test_ec_sign_nonce_deterministic_length():
    """Signature should always be exactly 128 hex chars regardless of nonce."""
    key = generate_ec_keypair()
    for nonce in ["0", "1" * 100, "638789760000000000", "999999999999999999"]:
        sig = ec_sign_nonce(key, nonce)
        assert len(sig) == 128, f"Unexpected sig length for nonce={nonce}"


def test_ec_sign_nonce_different_keys_differ():
    """Two different keys should produce different signatures for the same nonce."""
    key1 = generate_ec_keypair()
    key2 = generate_ec_keypair()
    nonce = "638789760000000000"

    sig1 = ec_sign_nonce(key1, nonce)
    sig2 = ec_sign_nonce(key2, nonce)

    assert sig1 != sig2
