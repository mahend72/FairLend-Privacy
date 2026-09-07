"""Scientific invariant tests for the IP-issued protected-attribute
credential: real CKKS encryption + real Ed25519 signing, tamper/forgery
resistance, CKKS-serialization stability under randomised re-encryption,
and the LPU-facing no-plaintext-gender / no-decryption invariants.

Uses real cryptography throughout -- no mocks. Ciphertext bytes are never
printed in assertions (see task Sec. 17: no secret/ciphertext dumps in
test output); failures below compare booleans/digest equality, not raw
bytes in assert messages.
"""
from __future__ import annotations

import dataclasses

import numpy as np
import pytest
import tenseal as ts

from fairlend.core.exceptions import CredentialVerificationError, KeyBoundaryError
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential
from fairlend.crypto.ckks import build_fla_context, context_can_decrypt, derive_lpu_context
from fairlend.crypto.hashing import sha256_bytes
from fairlend.crypto.signatures import SigningKeyPair
from fairlend.roles.fla import FairLendingAuditor
from fairlend.roles.identity_provider import FEMALE_ONE_HOT, MALE_ONE_HOT, IdentityProvider
from fairlend.roles.lpu import LoanProcessingUnit


@pytest.fixture()
def protocol():
    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)
    lpu = LoanProcessingUnit(lpu_context, ip_public_key=ip.public_key)
    fla = FairLendingAuditor(fla_context)
    return {"fla_context": fla_context, "lpu_context": lpu_context, "ip": ip, "lpu": lpu, "fla": fla}


# --- 1: valid credential verifies -------------------------------------------


def test_valid_credential_verifies(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    assert protocol["lpu"].verify_protected_attribute_credential(credential) is True


# --- 2/3/4/5: tamper detection ----------------------------------------------


def test_modified_uid_fails(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    tampered = dataclasses.replace(credential, uid="B002")
    assert protocol["lpu"].verify_protected_attribute_credential(tampered) is False


def test_modified_ciphertext_fails(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    tampered_bytes = bytearray(credential.ciphertext_bytes)
    tampered_bytes[0] ^= 0xFF
    tampered = dataclasses.replace(credential, ciphertext_bytes=bytes(tampered_bytes))
    assert protocol["lpu"].verify_protected_attribute_credential(tampered) is False


def test_modified_digest_fails(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    bad_digest = bytearray(credential.digest)
    bad_digest[0] ^= 0xFF
    tampered = dataclasses.replace(credential, digest=bytes(bad_digest))
    assert protocol["lpu"].verify_protected_attribute_credential(tampered) is False


def test_modified_signature_fails(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    bad_signature = bytearray(credential.signature)
    bad_signature[0] ^= 0xFF
    tampered = dataclasses.replace(credential, signature=bytes(bad_signature))
    assert protocol["lpu"].verify_protected_attribute_credential(tampered) is False


# --- 6: wrong IP public key --------------------------------------------------


def test_wrong_ip_public_key_fails(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    other_ip_keys = SigningKeyPair.generate()
    assert credential.verify(other_ip_keys.public_key) is False


# --- 7: re-encrypted substitute fails the ORIGINAL signature ----------------


def test_reencrypted_substitute_gender_ciphertext_fails_original_signature(protocol):
    """A borrower who tries to substitute a freshly-encrypted ciphertext of
    the SAME plaintext gender (hoping the LPU can't tell) must fail --
    CKKS randomises encryption, so the new ciphertext hashes differently,
    and the borrower cannot forge a new sigma_g_i without sk_IP_sig."""
    credential = protocol["ip"].issue_credential("B001", "female")
    substitute_ciphertext = ts.ckks_vector(protocol["lpu_context"], list(FEMALE_ONE_HOT)).serialize()
    assert substitute_ciphertext != credential.ciphertext_bytes  # randomised: bytes differ

    substituted = dataclasses.replace(credential, ciphertext_bytes=substitute_ciphertext)
    assert protocol["lpu"].verify_protected_attribute_credential(substituted) is False

    # Even if the borrower also recomputes a matching digest for the new
    # ciphertext (the digest step is a public re-hash, not a secret), the
    # OLD signature (over the OLD digest) still cannot validate a NEW one.
    forged_digest = sha256_bytes(substitute_ciphertext)
    fully_substituted = dataclasses.replace(
        credential, ciphertext_bytes=substitute_ciphertext, digest=forged_digest
    )
    assert protocol["lpu"].verify_protected_attribute_credential(fully_substituted) is False


# --- 8/9: LPU can verify without sk_HE and cannot decrypt -------------------


def test_lpu_can_verify_without_sk_he(protocol):
    assert protocol["lpu"].he_context.has_secret_key() is False
    credential = protocol["ip"].issue_credential("B001", "male")
    assert protocol["lpu"].verify_protected_attribute_credential(credential) is True


def test_lpu_remains_unable_to_decrypt_protected_attribute(protocol):
    credential = protocol["ip"].issue_credential("B001", "male")
    assert protocol["lpu"].can_decrypt_protected_attribute is False
    ciphertext_view = ts.ckks_vector_from(protocol["lpu"].he_context, credential.ciphertext_bytes)
    with pytest.raises(ValueError):
        ciphertext_view.decrypt()


def test_identity_provider_cannot_be_constructed_with_private_context(protocol):
    with pytest.raises(KeyBoundaryError):
        IdentityProvider(protocol["fla_context"])


# --- No plaintext gender anywhere on the LPU-facing credential --------------


def test_no_plaintext_gender_field_anywhere_in_credential(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    forbidden_substrings = (
        "male", "female", "gender", "probability_female", "one_hot", "sex",
    )
    field_names = [f.name for f in dataclasses.fields(credential)]
    for name in field_names:
        assert not any(bad in name.lower() for bad in forbidden_substrings), name
    # And the ciphertext bytes themselves (pseudo-random CKKS polynomial
    # coefficients) must not happen to literally spell out the plaintext
    # label -- a basic sanity guard, not a security property in itself.
    assert b"female" not in credential.ciphertext_bytes
    assert b"male" not in credential.ciphertext_bytes


def test_expected_lpu_facing_fields_only():
    expected = {"uid", "ciphertext_bytes", "digest", "signature", "credential_version"}
    actual = {f.name for f in dataclasses.fields(ProtectedAttributeCredential)}
    assert actual == expected


# --- CKKS serialization stability -------------------------------------------


def test_issued_ciphertext_serialization_hashes_consistently(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    assert sha256_bytes(credential.ciphertext_bytes) == credential.digest
    assert sha256_bytes(credential.ciphertext_bytes) == sha256_bytes(credential.ciphertext_bytes)


def test_fresh_reencryption_produces_different_bytes_but_original_still_verifies(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    fresh_ciphertext = ts.ckks_vector(protocol["lpu_context"], list(FEMALE_ONE_HOT)).serialize()
    assert fresh_ciphertext != credential.ciphertext_bytes
    # The ORIGINAL, untouched credential must be unaffected by the mere
    # existence of a fresh re-encryption elsewhere.
    assert protocol["lpu"].verify_protected_attribute_credential(credential) is True


def test_verification_hashes_the_supplied_ciphertext_not_a_regenerated_one(protocol):
    """Directly exercises ProtectedAttributeCredential.verify()'s first
    check: it must re-hash self.ciphertext_bytes (the retained, issued
    bytes), never regenerate/re-encrypt anything."""
    credential = protocol["ip"].issue_credential("B001", "male")
    # Swap in a same-plaintext-but-freshly-encrypted ciphertext while
    # leaving digest/signature untouched -- if verify() regenerated a
    # fresh ciphertext internally instead of hashing the supplied one,
    # this could spuriously pass; it must not.
    fresh = ts.ckks_vector(protocol["lpu_context"], list(MALE_ONE_HOT)).serialize()
    swapped = dataclasses.replace(credential, ciphertext_bytes=fresh)
    assert swapped.verify(protocol["ip"].public_key) is False


# --- FLA can still decrypt where authorised ---------------------------------


def test_fla_can_decrypt_the_issued_ciphertext(protocol):
    credential = protocol["ip"].issue_credential("B001", "female")
    ciphertext = ts.ckks_vector_from(protocol["fla_context"], credential.ciphertext_bytes)
    decrypted = np.array(ciphertext.decrypt())
    assert decrypted == pytest.approx(list(FEMALE_ONE_HOT), abs=1e-3)


def test_fla_decrypts_male_correctly(protocol):
    credential = protocol["ip"].issue_credential("B001", "male")
    ciphertext = ts.ckks_vector_from(protocol["fla_context"], credential.ciphertext_bytes)
    decrypted = np.array(ciphertext.decrypt())
    assert decrypted == pytest.approx(list(MALE_ONE_HOT), abs=1e-3)


def test_invalid_gender_label_rejected(protocol):
    with pytest.raises(ValueError):
        protocol["ip"].issue_credential("B001", "nonbinary")
