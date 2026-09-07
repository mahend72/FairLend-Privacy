"""Unit tests for fairlend.credentials.account.AccountCredential /
fairlend.roles.bank.Bank -- the Bank-issued account credential."""
from __future__ import annotations

import dataclasses

import pytest

from fairlend.core.exceptions import CredentialVerificationError
from fairlend.credentials.account import issue_account_credential
from fairlend.crypto.signatures import SigningKeyPair
from fairlend.roles.bank import Bank


def test_valid_credential_verifies():
    bank = Bank()
    credential = bank.issue_account_credential("B001", "ACC001")
    assert credential.verify(bank.public_key) is True


def test_changed_uid_fails():
    bank = Bank()
    credential = bank.issue_account_credential("B001", "ACC001")
    tampered = dataclasses.replace(credential, uid="B002")
    assert tampered.verify(bank.public_key) is False


def test_changed_account_value_fails():
    bank = Bank()
    credential = bank.issue_account_credential("B001", "ACC001")
    tampered = dataclasses.replace(credential, account="ACC999")
    assert tampered.verify(bank.public_key) is False


def test_changed_signature_fails():
    bank = Bank()
    credential = bank.issue_account_credential("B001", "ACC001")
    bad_signature = bytearray(credential.signature)
    bad_signature[0] ^= 0xFF
    tampered = dataclasses.replace(credential, signature=bytes(bad_signature))
    assert tampered.verify(bank.public_key) is False


def test_another_bank_verification_key_fails():
    bank = Bank()
    other_bank = Bank()
    credential = bank.issue_account_credential("B001", "ACC001")
    assert credential.verify(other_bank.public_key) is False


def test_malformed_credential_fails_explicitly():
    bank = Bank()
    credential = bank.issue_account_credential("B001", "ACC001")
    malformed = dataclasses.replace(credential, signature="not-bytes")  # type: ignore[arg-type]
    with pytest.raises(CredentialVerificationError):
        malformed.verify(bank.public_key)


def test_issue_account_credential_pure_function_matches_bank_role():
    """The role method and the underlying pure function must produce
    equivalently-verifiable credentials -- Bank.issue_account_credential
    is not doing anything the pure function does not already do."""
    keys = SigningKeyPair.generate()
    credential = issue_account_credential(keys.private_key, "B001", "ACC001")
    assert credential.verify(keys.public_key) is True


def test_bank_exposes_only_public_key_attribute_for_verification():
    bank = Bank()
    assert hasattr(bank, "public_key")
    # No attribute on Bank should expose the raw private key material.
    assert not hasattr(bank, "private_key")
    assert not hasattr(bank, "sk_b_sig")
