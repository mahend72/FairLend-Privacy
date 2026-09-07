"""Unit tests for fairlend.crypto.hashing: SHA-256 digest behaviour."""
from __future__ import annotations

import hashlib

from fairlend.crypto.hashing import sha256_bytes, sha256_hex


def test_sha256_bytes_matches_stdlib_hashlib():
    data = b"fairlend"
    assert sha256_bytes(data) == hashlib.sha256(data).digest()


def test_sha256_bytes_is_32_bytes():
    assert len(sha256_bytes(b"anything")) == 32


def test_sha256_hex_matches_bytes_hex():
    data = b"fairlend"
    assert sha256_hex(data) == sha256_bytes(data).hex()


def test_sha256_hex_is_lowercase_64_char_string():
    hex_digest = sha256_hex(b"fairlend")
    assert len(hex_digest) == 64
    assert hex_digest == hex_digest.lower()


def test_deterministic_for_same_input():
    data = b"repeatable"
    assert sha256_bytes(data) == sha256_bytes(data)
    assert sha256_hex(data) == sha256_hex(data)


def test_different_inputs_produce_different_digests():
    assert sha256_bytes(b"a") != sha256_bytes(b"b")


def test_empty_bytes_hashes_to_known_sha256_empty_digest():
    # Cross-checked against stdlib hashlib rather than a hand-transcribed
    # literal, to avoid a transcription error in the test itself.
    assert sha256_hex(b"") == hashlib.sha256(b"").hexdigest()
    assert len(sha256_hex(b"")) == 64
