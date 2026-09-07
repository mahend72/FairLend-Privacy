"""Scientific/security invariant tests for the LPU/FLA key-ownership
boundary (manuscript Sec. 3.3, 4.2, 4.8; Threat 1; Security Goal 1:
"Protected-attribute confidentiality from the LPU").

These are the first tests in the rebuilt prototype. They correspond to
audit checklist items 1-4 from the acceptance criteria ("LPU MUST NOT
possess sk_HE", "LPU cannot decrypt protected-attribute values") and are
tracked in docs/MANUSCRIPT_TO_CODE_TRACEABILITY.md.
"""
from __future__ import annotations

import pytest
import tenseal as ts

from fairlend.core.exceptions import KeyBoundaryError
from fairlend.crypto.ckks import (
    build_fla_context,
    context_can_decrypt,
    derive_lpu_context,
)
from fairlend.roles.fla import FairLendingAuditor
from fairlend.roles.lpu import LoanProcessingUnit


@pytest.fixture()
def fla_context() -> ts.Context:
    return build_fla_context()


@pytest.fixture()
def lpu_context(fla_context: ts.Context) -> ts.Context:
    return derive_lpu_context(fla_context)


def test_fla_context_holds_secret_key(fla_context: ts.Context) -> None:
    assert fla_context.has_secret_key() is True
    assert context_can_decrypt(fla_context) is True


def test_lpu_context_has_no_secret_key(lpu_context: ts.Context) -> None:
    assert lpu_context.has_secret_key() is False
    assert context_can_decrypt(lpu_context) is False


def test_derive_lpu_context_rejects_non_private_input(
    lpu_context: ts.Context,
) -> None:
    """derive_lpu_context() must require an FLA private context; calling it
    on an already-public context is a caller error and must raise, not
    silently produce another public context."""
    with pytest.raises(KeyBoundaryError):
        derive_lpu_context(lpu_context)


def test_lpu_decryption_fails_structurally(
    lpu_context: ts.Context, fla_context: ts.Context
) -> None:
    """The core invariant: attempt an ACTUAL decryption through the LPU's
    context and confirm it fails, rather than only checking a boolean
    flag (per the audit brief: "verify this structurally, not only via a
    boolean field")."""
    plaintext_male = ts.ckks_vector(fla_context, [1.0, 0.0])
    serialized = plaintext_male.serialize()

    # LPU receives only the ciphertext bytes plus its own public context.
    lpu_side_vector = ts.ckks_vector_from(lpu_context, serialized)

    with pytest.raises(ValueError):
        lpu_side_vector.decrypt()


def test_lpu_role_rejects_private_context(fla_context: ts.Context) -> None:
    """Constructing an LPU with a context that holds sk_HE must be
    impossible, not merely discouraged by convention."""
    with pytest.raises(KeyBoundaryError):
        LoanProcessingUnit(fla_context)


def test_fla_role_rejects_public_context(lpu_context: ts.Context) -> None:
    """Constructing an FLA with a context that lacks sk_HE must be
    impossible."""
    with pytest.raises(KeyBoundaryError):
        FairLendingAuditor(lpu_context)


def test_lpu_role_can_decrypt_protected_attribute_is_false(
    lpu_context: ts.Context,
) -> None:
    lpu = LoanProcessingUnit(lpu_context)
    assert lpu.can_decrypt_protected_attribute is False


def test_fla_role_holds_private_context(fla_context: ts.Context) -> None:
    fla = FairLendingAuditor(fla_context)
    assert fla.he_context.has_secret_key() is True


def test_lpu_can_evaluate_without_decrypting(
    fla_context: ts.Context, lpu_context: ts.Context
) -> None:
    """The LPU must be able to perform the permitted homomorphic operations
    (ciphertext x ciphertext multiplication + addition -- the shape of
    compSim, Sec. 4.6) without ever decrypting, and only the FLA's private
    context can recover the correct plaintext result.

    This exercises the raw TenSEAL operations compSim will wrap (Phase 7
    adds the typed API); it is included now because it is the clearest
    end-to-end demonstration of the key-separation boundary actually being
    useful, not just restrictive.
    """
    # FLA-side: encode borrower gender and reference vectors under pk_HE.
    g_male = ts.ckks_vector(fla_context, [1.0, 0.0])
    r_male = ts.ckks_vector(fla_context, [1.0, 0.0])
    r_female = ts.ckks_vector(fla_context, [0.0, 1.0])

    # Simulate transport of ciphertexts to the LPU (bytes only).
    g_male_lpu = ts.ckks_vector_from(lpu_context, g_male.serialize())
    r_male_lpu = ts.ckks_vector_from(lpu_context, r_male.serialize())
    r_female_lpu = ts.ckks_vector_from(lpu_context, r_female.serialize())

    sim_male = (g_male_lpu * r_male_lpu).sum()
    sim_female = (g_male_lpu * r_female_lpu).sum()

    # LPU cannot decrypt either result.
    with pytest.raises(ValueError):
        sim_male.decrypt()
    with pytest.raises(ValueError):
        sim_female.decrypt()

    # Only the FLA, using its private context, can recover the plaintext.
    sim_male_fla = ts.ckks_vector_from(fla_context, sim_male.serialize())
    sim_female_fla = ts.ckks_vector_from(fla_context, sim_female.serialize())

    assert sim_male_fla.decrypt()[0] == pytest.approx(1.0, abs=1e-3)
    assert sim_female_fla.decrypt()[0] == pytest.approx(0.0, abs=1e-3)
