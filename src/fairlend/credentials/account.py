"""Bank-issued account credential (manuscript Sec. 4.3, Table 1):

    sigma_b_i = Sign(sk_b_sig, uid_i || acc_i)

``uid_i || acc_i`` is instantiated here as
``canonical_encode({"domain": DOMAIN, "uid": uid, "account": account})``
(see ``fairlend.crypto.serialization``) -- never naive string
concatenation, so distinct ``(uid, account)`` pairs can never collide into
the same signed message via a field-boundary ambiguity.

The Bank owns ``sk_b_sig`` (see ``fairlend.roles.bank``); the LPU
verifies using only ``pk_b_sig``. This module contains no Bank-role
behaviour itself -- ``issue_account_credential`` is a pure function over
an already-obtained private key, used by ``fairlend.roles.bank.Bank``.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from fairlend.crypto.serialization import canonical_encode
from fairlend.crypto.signatures import sign, verify

DOMAIN = "fairlend/account/v1"
CREDENTIAL_VERSION = 1


def _account_message(uid: str, account: str) -> bytes:
    return canonical_encode({"domain": DOMAIN, "uid": uid, "account": account})


@dataclass(frozen=True)
class AccountCredential:
    """The Bank-issued account credential, as forwarded by the borrower
    and verified by the LPU."""

    uid: str
    account: str
    signature: bytes
    credential_version: int = CREDENTIAL_VERSION

    def verify(self, bank_public_key: Ed25519PublicKey) -> bool:
        """VerifySig(pk_b_sig, uid_i || acc_i, sigma_b_i)."""
        message = _account_message(self.uid, self.account)
        return verify(bank_public_key, message, self.signature)


def issue_account_credential(
    bank_private_key: Ed25519PrivateKey, uid: str, account: str
) -> AccountCredential:
    """sigma_b_i = Sign(sk_b_sig, uid_i || acc_i)."""
    signature = sign(bank_private_key, _account_message(uid, account))
    return AccountCredential(uid=uid, account=account, signature=signature)
