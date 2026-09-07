"""Loan Processing Unit (LPU) role.

Security boundary (manuscript Sec. 3.3/3.4, Threat 1, Table
"leakage_profile"): the LPU may decrypt authorised operational
account/credit-score values and may perform the permitted homomorphic
operations on encrypted protected-attribute ciphertexts (compSim, Sec. 4.6),
but it must never possess ``sk_HE`` and must never decrypt a
protected-attribute ciphertext or similarity value.

Phase 4 implemented only the key-ownership boundary. Phase 6 (this
change) adds credential verification against Bank/CA/IP public keys --
purely additive: the constructor's key-boundary check above is unchanged,
the existing single-positional-argument construction
(``LoanProcessingUnit(context)``) still works exactly as before, and
verification never touches ``self._he_context``'s (nonexistent) secret
key. The decision rule and encrypted aggregate construction are added in
later phases.
"""
from __future__ import annotations

from typing import Optional

import tenseal as ts
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fairlend.core.exceptions import CredentialVerificationError, KeyBoundaryError
from fairlend.credentials.account import AccountCredential
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential
from fairlend.credentials.score import ScoreCredential
from fairlend.crypto.ckks import context_can_decrypt


class LoanProcessingUnit:
    """The LPU. Constructible only with a CKKS context that has no secret
    key.

    The constructor is the enforcement point for the LPU/FLA key-separation
    invariant: it is impossible to obtain an ``LoanProcessingUnit`` instance
    whose ``he_context`` can decrypt, because construction raises
    ``KeyBoundaryError`` otherwise. This is checked structurally via
    ``context.has_secret_key()``, not via a caller-supplied flag.

    Bank/CA/IP verification keys are optional, keyword-only, and may also
    be registered after construction via ``set_verification_keys`` --
    matching the protocol flow where the LPU receives ``pk_b_sig``/
    ``pk_c_sig``/``pk_IP_sig`` from those roles, not from the FLA/CKKS
    key-generation step this constructor already governs.
    """

    def __init__(
        self,
        he_context: ts.Context,
        *,
        bank_public_key: Optional[Ed25519PublicKey] = None,
        ca_public_key: Optional[Ed25519PublicKey] = None,
        ip_public_key: Optional[Ed25519PublicKey] = None,
    ) -> None:
        if context_can_decrypt(he_context):
            raise KeyBoundaryError(
                "LoanProcessingUnit must never be constructed with a CKKS "
                "context that holds sk_HE. Use "
                "fairlend.crypto.ckks.derive_lpu_context(fla_context) to "
                "obtain a correctly-stripped evaluation context."
            )
        self._he_context = he_context
        self._bank_public_key = bank_public_key
        self._ca_public_key = ca_public_key
        self._ip_public_key = ip_public_key

    @property
    def he_context(self) -> ts.Context:
        """The LPU's public CKKS evaluation context (pk_HE, evk_HE only)."""
        return self._he_context

    @property
    def can_decrypt_protected_attribute(self) -> bool:
        """Always False for any successfully constructed instance.

        This property reports the same structural fact the constructor
        already enforced (``context_can_decrypt``); it is provided for
        callers/tests that want to assert the invariant on an existing
        instance without reaching into ``he_context`` directly. It is not
        an independent source of truth and cannot be set to True.
        """
        return context_can_decrypt(self._he_context)

    def set_verification_keys(
        self,
        *,
        bank_public_key: Optional[Ed25519PublicKey] = None,
        ca_public_key: Optional[Ed25519PublicKey] = None,
        ip_public_key: Optional[Ed25519PublicKey] = None,
    ) -> None:
        """Register Bank/CA/IP verification keys received out-of-band
        (i.e. not via this constructor). Only non-``None`` arguments
        overwrite the corresponding stored key."""
        if bank_public_key is not None:
            self._bank_public_key = bank_public_key
        if ca_public_key is not None:
            self._ca_public_key = ca_public_key
        if ip_public_key is not None:
            self._ip_public_key = ip_public_key

    def verify_account_credential(self, credential: AccountCredential) -> bool:
        """VerifySig(pk_b_sig, uid_i || acc_i, sigma_b_i)."""
        if self._bank_public_key is None:
            raise CredentialVerificationError(
                "LPU has no Bank verification key registered; call "
                "set_verification_keys(bank_public_key=...) first."
            )
        return credential.verify(self._bank_public_key)

    def verify_score_credential(self, credential: ScoreCredential) -> bool:
        """VerifySig(pk_c_sig, uid_i || s_i, sigma_c_i)."""
        if self._ca_public_key is None:
            raise CredentialVerificationError(
                "LPU has no CA verification key registered; call "
                "set_verification_keys(ca_public_key=...) first."
            )
        return credential.verify(self._ca_public_key)

    def verify_protected_attribute_credential(self, credential: ProtectedAttributeCredential) -> bool:
        """VerifySig(pk_IP_sig, uid_i || d_g_i, sigma_g_i).

        This NEVER touches ``self._he_context`` -- credential verification
        is pure Ed25519 signature verification plus a SHA-256 re-hash of
        the credential's own retained ciphertext bytes (see
        ``ProtectedAttributeCredential.verify``); it does not decrypt
        anything, so it works identically regardless of whether
        ``self._he_context`` could ever decrypt (which, by this class's
        own constructor invariant, it never can).
        """
        if self._ip_public_key is None:
            raise CredentialVerificationError(
                "LPU has no IP verification key registered; call "
                "set_verification_keys(ip_public_key=...) first."
            )
        return credential.verify(self._ip_public_key)
