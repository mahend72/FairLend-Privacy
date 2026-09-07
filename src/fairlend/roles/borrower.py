"""Borrower role (manuscript Sec. 4.3+).

Holds the credentials forwarded unchanged from the Bank, CA, and IP. This
class provides no method that constructs, mutates, or re-derives a
credential -- only storage and forwarding -- so "the borrower must not be
able to fabricate or alter the protected-attribute ciphertext without
invalidating sigma_g_i" (Threat 3) holds structurally: there is no API
surface through which a ``Borrower`` instance could produce an alternate
credential the LPU would accept, since every credential's authenticity is
checked against the ISSUING role's signature, not anything the borrower
does.

The borrower owns none of the Bank/CA/IP signing keys and no CKKS key
material -- see ``fairlend.roles.bank``/``credit_agency``/
``identity_provider``/``lpu``/``fla`` for where those actually live.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from fairlend.credentials.account import AccountCredential
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential
from fairlend.credentials.score import ScoreCredential


@dataclass
class Borrower:
    """Holds whatever credentials have been received so far. Any of the
    three may be ``None`` if not yet issued."""

    uid: str
    account_credential: Optional[AccountCredential] = None
    score_credential: Optional[ScoreCredential] = None
    protected_attribute_credential: Optional[ProtectedAttributeCredential] = None

    def receive_account_credential(self, credential: AccountCredential) -> None:
        self.account_credential = credential

    def receive_score_credential(self, credential: ScoreCredential) -> None:
        self.score_credential = credential

    def receive_protected_attribute_credential(self, credential: ProtectedAttributeCredential) -> None:
        self.protected_attribute_credential = credential

    def forward_credentials(
        self,
    ) -> Tuple[
        Optional[AccountCredential], Optional[ScoreCredential], Optional[ProtectedAttributeCredential]
    ]:
        """Returns exactly what was received, unchanged -- there is no
        transformation step here for the LPU to have to distrust."""
        return (self.account_credential, self.score_credential, self.protected_attribute_credential)
