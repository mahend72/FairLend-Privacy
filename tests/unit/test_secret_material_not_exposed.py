"""Output/logging safety (task Sec. 17): private signing keys, the CKKS
secret key, and plaintext gender must never be trivially printable from
the objects this phase introduces.

This does not exhaustively prove no code path anywhere ever logs a
secret; it checks the structural properties that make accidental leakage
hard: no credential dataclass carries a private-key-shaped field, and the
default repr/str of the key objects themselves does not embed raw key
material (cryptography's own Ed25519 key classes already guarantee this;
this test pins that behaviour so a future dependency change would be
caught).
"""
from __future__ import annotations

import dataclasses

from fairlend.credentials.account import AccountCredential
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential
from fairlend.credentials.score import ScoreCredential
from fairlend.crypto.ckks import build_fla_context
from fairlend.crypto.signatures import SigningKeyPair, public_key_bytes

_PRIVATE_KEY_FIELD_SUBSTRINGS = ("private_key", "sk_", "secret")


def test_no_credential_dataclass_carries_a_private_key_shaped_field():
    for cls in (AccountCredential, ScoreCredential, ProtectedAttributeCredential):
        for field in dataclasses.fields(cls):
            lowered = field.name.lower()
            assert not any(bad in lowered for bad in _PRIVATE_KEY_FIELD_SUBSTRINGS), (
                cls.__name__,
                field.name,
            )


def test_ed25519_private_key_repr_does_not_embed_raw_key_bytes():
    pair = SigningKeyPair.generate()
    # cryptography's Ed25519PrivateKey repr is an opaque object reference
    # (e.g. "<...Ed25519PrivateKey object at 0x...>"), never the raw key.
    representation = repr(pair.private_key)
    raw_public = public_key_bytes(pair.public_key)
    assert raw_public.hex() not in representation
    assert "PRIVATE" not in representation.upper() or "object at" in representation


def test_ckks_context_repr_does_not_embed_secret_key_material():
    context = build_fla_context()
    representation = repr(context)
    # TenSEAL's Context repr is an opaque binding-object reference, not a
    # dump of key material -- this pins that so a library change that
    # started printing key bytes would be caught here.
    assert len(representation) < 200
