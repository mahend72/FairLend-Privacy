"""Hashing helpers.

Manuscript Sec. 6.1.4: "We instantiate the cryptographic hash function
H(.) using SHA-256." Used for ciphertext digests (d_g_i), commitment
openings, and the application-binding hash (C_app_i, Phase 8).

This module is hashing ONLY -- a one-way, unkeyed digest with no
authentication semantics. It must never be used as a substitute for a
digital signature (a hash alone proves nothing about who produced the
input); see ``fairlend.crypto.signatures`` for authentication, and
``fairlend.crypto.serialization`` for how structured messages are turned
into bytes before either hashing or signing.
"""
from __future__ import annotations

import hashlib


def sha256_bytes(data: bytes) -> bytes:
    """H(data) = SHA-256(data), returned as raw digest bytes (32 bytes)."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """H(data) = SHA-256(data), returned as a lowercase hex string."""
    return sha256_bytes(data).hex()
