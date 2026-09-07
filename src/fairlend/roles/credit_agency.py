"""Credit Agency (CA) role (manuscript Sec. 4.3).

Issues the signed credit-score credential ``(s_i, sigma_c_i)`` where
``sigma_c_i = Sign(sk_c_sig, uid_i || s_i)``, using
``fairlend.crypto.signatures``.

The scoring function itself (computing ``s_i`` from employment status,
salary, and credit history -- the legacy prototype's hardcoded
``CIBIL_score = 550`` is the defect being fixed, not a pattern to
reproduce; see docs/IMPLEMENTATION_GAPS.md item A.2) is a later phase;
this role accepts an already-computed integer score and only handles its
authenticated issuance.

The CA owns ``sk_c_sig`` and exposes only ``pk_c_sig`` (``public_key``)
for the LPU to verify against.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fairlend.credentials.score import ScoreCredential, issue_score_credential
from fairlend.crypto.signatures import SigningKeyPair


class CreditAgency:
    """The Credit Agency. Holds ``sk_c_sig`` privately; ``public_key`` is
    the only key material intended to leave this object."""

    def __init__(self, signing_key_pair: SigningKeyPair | None = None) -> None:
        self._keys = signing_key_pair or SigningKeyPair.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        """pk_c_sig -- safe to share with the LPU for verification."""
        return self._keys.public_key

    def issue_score_credential(self, uid: str, score: int) -> ScoreCredential:
        """sigma_c_i = Sign(sk_c_sig, uid_i || s_i)."""
        return issue_score_credential(self._keys.private_key, uid, score)
