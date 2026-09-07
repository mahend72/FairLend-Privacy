"""Bank role (manuscript Sec. 4.3).

Issues the signed account credential ``(acc_i, sigma_b_i)`` where
``sigma_b_i = Sign(sk_b_sig, uid_i || acc_i)``, using
``fairlend.crypto.signatures`` (real Ed25519, never a bare hash --
see docs/IMPLEMENTATION_GAPS.md item B.3).

The Bank owns ``sk_b_sig`` and exposes only ``pk_b_sig`` (``public_key``)
for the LPU to verify against.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fairlend.credentials.account import AccountCredential, issue_account_credential
from fairlend.crypto.signatures import SigningKeyPair


class Bank:
    """The Bank. Holds ``sk_b_sig`` privately; ``public_key`` is the only
    key material intended to leave this object."""

    def __init__(self, signing_key_pair: SigningKeyPair | None = None) -> None:
        self._keys = signing_key_pair or SigningKeyPair.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        """pk_b_sig -- safe to share with the LPU for verification."""
        return self._keys.public_key

    def issue_account_credential(self, uid: str, account: str) -> AccountCredential:
        """sigma_b_i = Sign(sk_b_sig, uid_i || acc_i)."""
        return issue_account_credential(self._keys.private_key, uid, account)
