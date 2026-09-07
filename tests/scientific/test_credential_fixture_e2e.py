"""Small deterministic end-to-end credential fixture (task Sec. 16):

    uid = "B001", account = "ACC001", score = 720, gender = female

    Bank            -> AccountCredential
    Credit Agency   -> ScoreCredential
    Identity Provider -> ProtectedAttributeCredential (encrypted)
    Borrower        -> forwards all three unchanged
    LPU             -> verifies all three

No lending decision is made here (that is a later phase) -- only
credential issuance, forwarding, and verification.
"""
from __future__ import annotations

import dataclasses

import pytest

from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
from fairlend.roles.bank import Bank
from fairlend.roles.borrower import Borrower
from fairlend.roles.credit_agency import CreditAgency
from fairlend.roles.identity_provider import IdentityProvider
from fairlend.roles.lpu import LoanProcessingUnit

UID = "B001"
ACCOUNT = "ACC001"
SCORE = 720
GENDER = "female"


@pytest.fixture()
def issued_fixture():
    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)

    bank = Bank()
    ca = CreditAgency()
    ip = IdentityProvider(lpu_context)
    lpu = LoanProcessingUnit(
        lpu_context,
        bank_public_key=bank.public_key,
        ca_public_key=ca.public_key,
        ip_public_key=ip.public_key,
    )
    borrower = Borrower(uid=UID)

    borrower.receive_account_credential(bank.issue_account_credential(UID, ACCOUNT))
    borrower.receive_score_credential(ca.issue_score_credential(UID, SCORE))
    borrower.receive_protected_attribute_credential(ip.issue_credential(UID, GENDER))

    return {"bank": bank, "ca": ca, "ip": ip, "lpu": lpu, "borrower": borrower}


def test_all_three_credentials_verify_after_borrower_forwarding(issued_fixture):
    borrower = issued_fixture["borrower"]
    lpu = issued_fixture["lpu"]
    account_credential, score_credential, pa_credential = borrower.forward_credentials()

    account_valid = lpu.verify_account_credential(account_credential)
    score_valid = lpu.verify_score_credential(score_credential)
    protected_attribute_valid = lpu.verify_protected_attribute_credential(pa_credential)

    assert account_valid is True
    assert score_valid is True
    assert protected_attribute_valid is True


def test_forwarded_credentials_are_unchanged(issued_fixture):
    borrower = issued_fixture["borrower"]
    account_credential, score_credential, pa_credential = borrower.forward_credentials()
    assert account_credential.uid == UID and account_credential.account == ACCOUNT
    assert score_credential.uid == UID and score_credential.score == SCORE
    assert pa_credential.uid == UID


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: dataclasses.replace(c, uid="B999"),
        lambda c: dataclasses.replace(c, account="ACC999"),
        lambda c: dataclasses.replace(c, signature=bytes(bytearray(c.signature)[:-1] + b"\x00")),
    ],
)
def test_mutated_account_credential_is_rejected(issued_fixture, mutate):
    borrower = issued_fixture["borrower"]
    lpu = issued_fixture["lpu"]
    account_credential, _, _ = borrower.forward_credentials()
    mutated = mutate(account_credential)
    if mutated == account_credential:
        pytest.skip("mutation produced an identical credential by coincidence")
    assert lpu.verify_account_credential(mutated) is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: dataclasses.replace(c, uid="B999"),
        lambda c: dataclasses.replace(c, score=1),
        lambda c: dataclasses.replace(c, signature=bytes(bytearray(c.signature)[:-1] + b"\x00")),
    ],
)
def test_mutated_score_credential_is_rejected(issued_fixture, mutate):
    borrower = issued_fixture["borrower"]
    lpu = issued_fixture["lpu"]
    _, score_credential, _ = borrower.forward_credentials()
    mutated = mutate(score_credential)
    if mutated == score_credential:
        pytest.skip("mutation produced an identical credential by coincidence")
    assert lpu.verify_score_credential(mutated) is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: dataclasses.replace(c, uid="B999"),
        lambda c: dataclasses.replace(
            c, ciphertext_bytes=bytes(bytearray(c.ciphertext_bytes)[:-1] + b"\x00")
        ),
        lambda c: dataclasses.replace(c, digest=bytes(bytearray(c.digest)[:-1] + b"\x00")),
        lambda c: dataclasses.replace(c, signature=bytes(bytearray(c.signature)[:-1] + b"\x00")),
    ],
)
def test_mutated_protected_attribute_credential_is_rejected(issued_fixture, mutate):
    borrower = issued_fixture["borrower"]
    lpu = issued_fixture["lpu"]
    _, _, pa_credential = borrower.forward_credentials()
    mutated = mutate(pa_credential)
    if mutated == pa_credential:
        pytest.skip("mutation produced an identical credential by coincidence")
    assert lpu.verify_protected_attribute_credential(mutated) is False
