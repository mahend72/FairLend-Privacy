"""Scientific tests for the Phase 3 key-ownership matrix (task Sec. 10):

    Bank:     owns sk_b_sig,  exposes pk_b_sig
    CA:       owns sk_c_sig,  exposes pk_c_sig
    IP:       owns sk_IP_sig, has access to pk_HE, must NOT own sk_HE
    LPU:      holds Bank/CA/IP verification keys + public/eval CKKS
              context, does NOT receive sk_HE
    FLA:      owns sk_HE
    Borrower: owns no Bank/CA/IP signing key and no sk_HE

No test in this file prints or asserts against raw private-key/secret-key
byte contents (task Sec. 17) -- only structural presence/absence and
functional capability (can this role decrypt / can it produce a valid
signature) are checked.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
from fairlend.roles.bank import Bank
from fairlend.roles.borrower import Borrower
from fairlend.roles.credit_agency import CreditAgency
from fairlend.roles.fla import FairLendingAuditor
from fairlend.roles.identity_provider import IdentityProvider
from fairlend.roles.lpu import LoanProcessingUnit


def test_bank_owns_signing_key_and_exposes_only_public_key():
    bank = Bank()
    assert isinstance(bank.public_key, Ed25519PublicKey)
    assert not hasattr(bank, "private_key")
    assert not hasattr(bank, "sk_b_sig")
    # Functional check: the Bank CAN sign (proves it holds the private key
    # internally) without exposing it as a public attribute.
    credential = bank.issue_account_credential("B001", "ACC001")
    assert credential.verify(bank.public_key) is True


def test_ca_owns_signing_key_and_exposes_only_public_key():
    ca = CreditAgency()
    assert isinstance(ca.public_key, Ed25519PublicKey)
    assert not hasattr(ca, "private_key")
    assert not hasattr(ca, "sk_c_sig")
    credential = ca.issue_score_credential("B001", 720)
    assert credential.verify(ca.public_key) is True


def test_ip_owns_signing_key_has_pk_he_but_not_sk_he():
    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)

    assert isinstance(ip.public_key, Ed25519PublicKey)
    assert not hasattr(ip, "private_key")
    assert not hasattr(ip, "sk_ip_sig")
    # "has access to pk_HE" -- the IP can encrypt.
    credential = ip.issue_credential("B001", "female")
    assert credential.ciphertext_bytes  # non-empty: encryption succeeded
    # "must not own sk_HE".
    assert lpu_context.has_secret_key() is False


def test_lpu_receives_verification_keys_and_ckks_context_but_not_sk_he():
    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    bank, ca, ip = Bank(), CreditAgency(), IdentityProvider(lpu_context)
    lpu = LoanProcessingUnit(
        lpu_context,
        bank_public_key=bank.public_key,
        ca_public_key=ca.public_key,
        ip_public_key=ip.public_key,
    )

    assert lpu.he_context.has_secret_key() is False
    assert lpu.can_decrypt_protected_attribute is False
    # Functional check: the registered keys actually work for verification.
    account_credential = bank.issue_account_credential("B001", "ACC001")
    score_credential = ca.issue_score_credential("B001", 720)
    pa_credential = ip.issue_credential("B001", "female")
    assert lpu.verify_account_credential(account_credential) is True
    assert lpu.verify_score_credential(score_credential) is True
    assert lpu.verify_protected_attribute_credential(pa_credential) is True


def test_fla_owns_sk_he():
    fla_context = build_fla_context()
    fla = FairLendingAuditor(fla_context)
    assert fla.he_context.has_secret_key() is True


def test_borrower_owns_no_signing_key_and_no_sk_he():
    borrower = Borrower(uid="B001")
    assert not hasattr(borrower, "private_key")
    assert not hasattr(borrower, "sk_b_sig")
    assert not hasattr(borrower, "sk_c_sig")
    assert not hasattr(borrower, "sk_ip_sig")
    assert not hasattr(borrower, "he_context")
    assert not hasattr(borrower, "sk_he")


def test_lpu_cannot_verify_credentials_before_keys_are_registered():
    """No verification key registered -> explicit error, never a silent
    False that could be confused with 'checked and invalid'."""
    from fairlend.core.exceptions import CredentialVerificationError

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    lpu = LoanProcessingUnit(lpu_context)  # no verification keys registered
    bank = Bank()
    credential = bank.issue_account_credential("B001", "ACC001")
    try:
        lpu.verify_account_credential(credential)
        assert False, "expected CredentialVerificationError"
    except CredentialVerificationError:
        pass


def test_lpu_verification_keys_can_be_registered_after_construction():
    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    lpu = LoanProcessingUnit(lpu_context)
    bank = Bank()
    lpu.set_verification_keys(bank_public_key=bank.public_key)
    credential = bank.issue_account_credential("B001", "ACC001")
    assert lpu.verify_account_credential(credential) is True
