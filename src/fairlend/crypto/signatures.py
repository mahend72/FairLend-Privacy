"""Digital signatures for Bank/CA/IP credential issuance.

Primitive chosen: **Ed25519** (RFC 8032), via the maintained
``cryptography`` package's ``hazmat.primitives.asymmetric.ed25519``.

This is an implementation choice, not a manuscript-specified algorithm --
the manuscript states only the abstract ``Sign``/``VerifySig`` interface
(Sec. 3.3, Sec. 4.3: ``sigma_b_i = Sign(sk_b_sig, uid_i || acc_i)`` etc.),
never a concrete scheme (see docs/MANUSCRIPT_EVIDENCE_STATUS.md). Ed25519
was chosen over RSA-PSS because it has fixed-size keys and signatures (32
and 64 bytes respectively), no padding/salt-length parameters to get
wrong, deterministic signing (no per-signature randomness the caller must
supply correctly), and is implemented directly in ``cryptography`` without
extra parameter choices -- properties that make it harder to misuse by
accident in exactly the way a hand-rolled or parameter-heavy scheme is
not.

This module provides ONLY signing/verification. It is deliberately not:
  - a hash function used as a stand-in for authentication (see
    ``fairlend.crypto.hashing`` for hashing, which proves nothing about
    *who* produced a message);
  - HMAC (a symmetric, shared-secret MAC) used as a substitute for public
    verifiability -- a Bank/CA/IP credential must be verifiable by the
    LPU using only a PUBLIC key, never a secret the LPU would have to
    share with the issuer;
  - the legacy 2023 prototype's Petlib-based ``NIZKP`` function (see
    docs/IMPLEMENTATION_GAPS.md item B.4) -- this module is not a proof
    system and makes no zero-knowledge claim.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from fairlend.core.exceptions import CredentialVerificationError


@dataclass(frozen=True)
class SigningKeyPair:
    """An Ed25519 keypair for one issuing role (Bank, CA, or IP)."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @staticmethod
    def generate() -> "SigningKeyPair":
        private_key = Ed25519PrivateKey.generate()
        return SigningKeyPair(private_key=private_key, public_key=private_key.public_key())


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """sigma = Sign(sk, message). ``message`` must already be canonical
    bytes -- see ``fairlend.crypto.serialization.canonical_encode``; this
    function does not itself impose any structure on ``message``."""
    return private_key.sign(message)


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """VerifySig(pk, message, sigma) -> bool.

    Returns True only if ``signature`` is a valid Ed25519 signature by the
    holder of the private key corresponding to ``public_key`` over exactly
    ``message`` -- a single-bit change in either ``message`` or
    ``signature``, or a signature produced by a different key, returns
    False. This is real cryptographic verification (``Ed25519PublicKey.
    verify``); nothing in this codebase is permitted to report a
    credential as verified via a bare boolean not backed by this call.

    Raises:
        CredentialVerificationError: if ``signature`` is not a ``bytes``-
            like object -- a malformed credential (wrong type/shape) is
            reported as an explicit error, distinct from a well-formed but
            cryptographically invalid signature (which returns False).
    """
    if not isinstance(signature, (bytes, bytearray)):
        raise CredentialVerificationError(
            f"signature must be bytes, got {type(signature)!r} -- malformed credential."
        )
    try:
        public_key.verify(bytes(signature), message)
        return True
    except InvalidSignature:
        return False


def public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    """Raw 32-byte public-key encoding, for transport/storage/comparison."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    """Inverse of ``public_key_bytes``."""
    return Ed25519PublicKey.from_public_bytes(data)
