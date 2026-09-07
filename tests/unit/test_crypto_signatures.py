"""Unit tests for fairlend.crypto.signatures: real Ed25519 sign/verify,
tamper detection, wrong-key detection, and malformed-input handling."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from fairlend.core.exceptions import CredentialVerificationError
from fairlend.crypto.signatures import (
    SigningKeyPair,
    public_key_bytes,
    public_key_from_bytes,
    sign,
    verify,
)


def test_signing_key_pair_generates_ed25519_keys():
    pair = SigningKeyPair.generate()
    assert isinstance(pair.private_key, Ed25519PrivateKey)
    assert isinstance(pair.public_key, Ed25519PublicKey)


def test_valid_signature_verifies():
    pair = SigningKeyPair.generate()
    message = b"hello fairlend"
    signature = sign(pair.private_key, message)
    assert verify(pair.public_key, message, signature) is True


def test_tampered_message_fails_verification():
    pair = SigningKeyPair.generate()
    signature = sign(pair.private_key, b"original message")
    assert verify(pair.public_key, b"tampered message", signature) is False


def test_tampered_signature_fails_verification():
    pair = SigningKeyPair.generate()
    message = b"hello fairlend"
    signature = bytearray(sign(pair.private_key, message))
    signature[0] ^= 0xFF
    assert verify(pair.public_key, message, bytes(signature)) is False


def test_wrong_public_key_fails_verification():
    signer = SigningKeyPair.generate()
    other = SigningKeyPair.generate()
    message = b"hello fairlend"
    signature = sign(signer.private_key, message)
    assert verify(other.public_key, message, signature) is False


def test_malformed_signature_type_raises_explicit_error_not_silent_false():
    pair = SigningKeyPair.generate()
    with pytest.raises(CredentialVerificationError):
        verify(pair.public_key, b"message", "not-bytes")  # type: ignore[arg-type]


def test_signature_is_ed25519_fixed_64_bytes():
    pair = SigningKeyPair.generate()
    signature = sign(pair.private_key, b"any message")
    assert len(signature) == 64


def test_public_key_bytes_round_trip():
    pair = SigningKeyPair.generate()
    encoded = public_key_bytes(pair.public_key)
    assert len(encoded) == 32  # Ed25519 raw public key length
    restored = public_key_from_bytes(encoded)
    message = b"round trip check"
    signature = sign(pair.private_key, message)
    assert verify(restored, message, signature) is True
