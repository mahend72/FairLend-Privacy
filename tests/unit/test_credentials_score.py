"""Unit tests for fairlend.credentials.score.ScoreCredential /
fairlend.roles.credit_agency.CreditAgency -- the CA-issued credit-score
credential."""
from __future__ import annotations

import dataclasses

import pytest

from fairlend.core.exceptions import CredentialVerificationError
from fairlend.credentials.score import _score_message
from fairlend.roles.credit_agency import CreditAgency


def test_valid_score_credential_verifies():
    ca = CreditAgency()
    credential = ca.issue_score_credential("B001", 720)
    assert credential.verify(ca.public_key) is True


def test_changed_uid_fails():
    ca = CreditAgency()
    credential = ca.issue_score_credential("B001", 720)
    tampered = dataclasses.replace(credential, uid="B002")
    assert tampered.verify(ca.public_key) is False


def test_changed_score_fails():
    ca = CreditAgency()
    credential = ca.issue_score_credential("B001", 720)
    tampered = dataclasses.replace(credential, score=721)
    assert tampered.verify(ca.public_key) is False


def test_changed_signature_fails():
    ca = CreditAgency()
    credential = ca.issue_score_credential("B001", 720)
    bad_signature = bytearray(credential.signature)
    bad_signature[0] ^= 0xFF
    tampered = dataclasses.replace(credential, signature=bytes(bad_signature))
    assert tampered.verify(ca.public_key) is False


def test_wrong_ca_key_fails():
    ca = CreditAgency()
    other_ca = CreditAgency()
    credential = ca.issue_score_credential("B001", 720)
    assert credential.verify(other_ca.public_key) is False


def test_malformed_credential_fails_explicitly():
    ca = CreditAgency()
    credential = ca.issue_score_credential("B001", 720)
    malformed = dataclasses.replace(credential, signature=1234)  # type: ignore[arg-type]
    with pytest.raises(CredentialVerificationError):
        malformed.verify(ca.public_key)


def test_score_encoding_is_deterministic():
    a = _score_message("B001", 720)
    b = _score_message("B001", 720)
    assert a == b


def test_score_encoding_distinguishes_different_scores():
    a = _score_message("B001", 720)
    b = _score_message("B001", 721)
    assert a != b


def test_ca_exposes_only_public_key_attribute_for_verification():
    ca = CreditAgency()
    assert hasattr(ca, "public_key")
    assert not hasattr(ca, "private_key")
    assert not hasattr(ca, "sk_c_sig")
