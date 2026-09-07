"""Exceptions for the FairLend prototype."""
from __future__ import annotations


class FairLendError(Exception):
    """Base class for all FairLend-specific errors."""


class KeyBoundaryError(FairLendError):
    """Raised when code would cross the LPU/FLA key-ownership boundary.

    Examples: constructing an ``LoanProcessingUnit`` with a CKKS context
    that holds ``sk_HE``, or constructing a ``FairLendingAuditor`` with a
    context that does not. This exception exists so the LPU/FLA
    key-separation invariant (manuscript Sec. 4.2, 4.8; Threat 1; Security
    Goal 1) is enforced structurally at object-construction time rather than
    only documented.
    """


class CredentialVerificationError(FairLendError):
    """Raised when a Bank/CA/IP-issued credential fails signature
    verification (Phases 5-6)."""


class ApplicationBindingError(FairLendError):
    """Raised when an application packet's components do not bind to a
    common application commitment C_app_i (Phase 8)."""


class MalformedCiphertextError(FairLendError):
    """Raised when a ciphertext fails a structural check before any
    homomorphic operation is attempted on it -- e.g. an unparseable byte
    string, or a ciphertext with the wrong number of slots for the
    operation being requested (``fairlend.audit.similarity``'s one-hot
    male/female vectors must have exactly 2 slots).

    This exists because TenSEAL does not reliably reject a ciphertext-size
    mismatch itself: a size-1 ciphertext dotted against a size-2 one can
    silently broadcast rather than raise, producing a numerically wrong
    result with no error at all. Code in this package must never rely on
    the library to catch that; it checks shape explicitly first.
    """
