"""Identity Provider (IP) role (manuscript Sec. 4.3, Algorithm: Protected-
Attribute Credential Issuance).

The IP is the ONLY entity in this codebase that ever turns a plaintext
protected-attribute label into ciphertext. Everything downstream of
``IdentityProvider.issue_credential`` -- the borrower, the LPU -- only
ever sees a ``ProtectedAttributeCredential``, which carries no plaintext
gender field (see ``fairlend.credentials.protected_attribute``).

Binary one-hot encoding only (Sec. 4.6, Table 1):

    male   = (1, 0)
    female = (0, 1)

The legacy four-category representation (Male/Female/Transgender/Other;
``legacy/secureloan_2023/source_code/*``) is not reused here.

Key ownership: the IP holds its own Ed25519 signing key (``sk_IP_sig``)
and a CKKS context with ``pk_HE`` (needed to encrypt) but MUST NOT hold
``sk_HE`` (Sec. 4.2/4.8: only the FLA holds ``sk_HE``) -- the IP only ever
encrypts, it never decrypts. This is enforced structurally the same way
``fairlend.roles.lpu.LoanProcessingUnit`` enforces it: construction raises
``KeyBoundaryError`` if given a secret-key-bearing context.
"""
from __future__ import annotations

import tenseal as ts
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fairlend.core.exceptions import KeyBoundaryError
from fairlend.credentials.protected_attribute import (
    ProtectedAttributeCredential,
    issue_protected_attribute_credential,
)
from fairlend.crypto.ckks import context_can_decrypt
from fairlend.crypto import bfv as bfv_crypto
from fairlend.crypto.signatures import SigningKeyPair

MALE_ONE_HOT = (1.0, 0.0)
FEMALE_ONE_HOT = (0.0, 1.0)
_LABEL_TO_ONE_HOT = {"male": MALE_ONE_HOT, "female": FEMALE_ONE_HOT}

# BFV plaintexts are integers, not floats (ts.bfv_vector requires int
# slots) -- otherwise the SAME one-hot encoding as CKKS above.
MALE_ONE_HOT_INT = (1, 0)
FEMALE_ONE_HOT_INT = (0, 1)
_LABEL_TO_ONE_HOT_INT = {"male": MALE_ONE_HOT_INT, "female": FEMALE_ONE_HOT_INT}


class IdentityProvider:
    """The IP. Constructible only with a CKKS context that has no secret
    key -- the same structural boundary ``LoanProcessingUnit`` enforces,
    for the same reason (this role must never be able to decrypt either)."""

    def __init__(
        self, he_public_context: ts.Context, signing_key_pair: SigningKeyPair | None = None
    ) -> None:
        if context_can_decrypt(he_public_context):
            raise KeyBoundaryError(
                "IdentityProvider must never be constructed with a CKKS "
                "context that holds sk_HE -- it only encrypts (Enc(pk_HE, "
                "...)) and never decrypts. Use "
                "fairlend.crypto.ckks.derive_lpu_context(fla_context) (or "
                "an equivalent public context) to obtain a correctly-"
                "stripped encryption-only context."
            )
        self._he_public_context = he_public_context
        self._keys = signing_key_pair or SigningKeyPair.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        """pk_IP_sig -- safe to share with the LPU for verification."""
        return self._keys.public_key

    def issue_credential(self, uid: str, gender_label: str) -> ProtectedAttributeCredential:
        """The full manuscript flow for one applicant:

            authenticated plaintext label
                -> one-hot encoding (male=(1,0), female=(0,1))
                -> CKKS encryption under pk_HE -> HE.g_i
                -> Serialize(HE.g_i)
                -> d_g_i = SHA256(...)
                -> sigma_g_i = Sign(sk_IP_sig, uid_i || d_g_i)
                -> ProtectedAttributeCredential

        Args:
            gender_label: The plaintext synthetic label ("male" or
                "female") -- this is the ONE place in the protocol path
                where a plaintext label is ever handled; the returned
                credential contains no trace of it (see
                ``fairlend.credentials.protected_attribute``'s module
                docstring). The evaluation harness may know this label
                before calling this method, since it is generating
                controlled experimental data (manuscript Sec. 6.1.1); once
                this method returns, only the credential exists on the
                protocol path.
        """
        if gender_label not in _LABEL_TO_ONE_HOT:
            raise ValueError(
                f"gender_label must be one of {sorted(_LABEL_TO_ONE_HOT)!r}, got {gender_label!r}"
            )
        one_hot = _LABEL_TO_ONE_HOT[gender_label]
        ciphertext = ts.ckks_vector(self._he_public_context, list(one_hot))
        ciphertext_bytes = ciphertext.serialize()
        return issue_protected_attribute_credential(self._keys.private_key, uid, ciphertext_bytes)


class IdentityProviderBFV:
    """PHASE 2 (active protocol): the SAME Identity Provider role as
    ``IdentityProvider`` above, issuing the SAME binary one-hot encoding
    (male=(1,0), female=(0,1)) and the SAME
    ``ProtectedAttributeCredential`` type -- BFV instead of CKKS is purely
    a change of which homomorphic scheme encrypts the one-hot vector; the
    credential's signature/digest construction, and every downstream
    consumer of ``ProtectedAttributeCredential``, is unchanged.

    Kept as an explicitly separate, clearly-named class (not a branch
    inside ``IdentityProvider``) so it is never ambiguous which scheme
    issued a given credential from the code alone -- see
    reviewer2_phase2_bfv_migration_report.md, "Create a clean BFV
    abstraction"."""

    def __init__(
        self, he_public_context: ts.Context, signing_key_pair: SigningKeyPair | None = None
    ) -> None:
        if bfv_crypto.context_can_decrypt(he_public_context):
            raise KeyBoundaryError(
                "IdentityProviderBFV must never be constructed with a BFV "
                "context that holds the secret key -- it only encrypts and "
                "never decrypts. Use "
                "fairlend.crypto.bfv.derive_lpu_context(fla_context) (or an "
                "equivalent public context) to obtain a correctly-stripped "
                "encryption-only context."
            )
        self._he_public_context = he_public_context
        self._keys = signing_key_pair or SigningKeyPair.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        """pk_IP_sig -- safe to share with the LPU for verification."""
        return self._keys.public_key

    def issue_credential(self, uid: str, gender_label: str) -> ProtectedAttributeCredential:
        """Identical contract to ``IdentityProvider.issue_credential``,
        BFV-encrypted instead of CKKS-encrypted. See that method's
        docstring for the full manuscript flow -- only the encryption
        primitive (``ts.bfv_vector`` on integer one-hot slots, instead of
        ``ts.ckks_vector`` on float slots) differs."""
        if gender_label not in _LABEL_TO_ONE_HOT_INT:
            raise ValueError(
                f"gender_label must be one of {sorted(_LABEL_TO_ONE_HOT_INT)!r}, got {gender_label!r}"
            )
        one_hot = _LABEL_TO_ONE_HOT_INT[gender_label]
        ciphertext = ts.bfv_vector(self._he_public_context, list(one_hot))
        ciphertext_bytes = ciphertext.serialize()
        return issue_protected_attribute_credential(self._keys.private_key, uid, ciphertext_bytes)
