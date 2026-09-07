"""compSim: encrypted protected-attribute similarity (manuscript Sec. 4.6).

    HE.g_i = (HE.Enc(g_i,m), HE.Enc(g_i,f))       -- one CKKS ciphertext,
                                                       2 SIMD slots
    HE.r_m = (HE.Enc(1), HE.Enc(0))
    HE.r_f = (HE.Enc(0), HE.Enc(1))

    compSim(HE.g_i, HE.r_k) = sum_j HE(g_i,j) (x) HE(r_k,j),  k in {m, f}

In this binary one-hot setting the vectors are already unit-norm, so the
manuscript's cosine similarity reduces EXACTLY to this inner product --
this module deliberately implements NOTHING beyond the inner product: no
norm computation, no inverse square root, no encrypted division, no
polynomial approximation, no cosine denominator, and no plaintext
shortcut. Adding any of those would be adding cryptographic machinery the
manuscript does not claim and this one-hot setting does not need.

TENSEAL BEHAVIOUR (verified empirically against this codebase's exact
CKKS configuration -- ``fairlend.core.config.CKKSConfig`` defaults,
poly_modulus_degree=8192, coeff_mod_bit_sizes=[60,40,40,60],
global_scale=2**40 -- not merely asserted from the manuscript text):

  - ``ts.Context`` has three boolean flags, all ``True`` by default on
    every context this codebase creates: ``auto_relin``, ``auto_rescale``,
    ``auto_mod_switch``. TenSEAL's Python API performs relinearisation,
    rescaling, and modulus-switching AUTOMATICALLY after every
    ciphertext-ciphertext multiplication; there is no manual
    relinearise/rescale call exposed on ``CKKSVector`` for this codebase
    to invoke, and none is implemented here, because there is nothing to
    invoke.
  - ``CKKSVector.dot(other)`` works directly for CIPHERTEXT x CIPHERTEXT
    (not just ciphertext x plaintext) and is exactly ``sum_j
    self[j]*other[j]`` -- confirmed by comparing its output bit-for-bit
    against a manual ``(self * other).sum()`` on this codebase's context.
    This module uses ``.dot()`` directly rather than hand-rolling
    multiply+sum, since they are the same operation and ``.dot()`` is the
    library's own name for it.
  - ``.dot()``'s internal sum-reduction uses ciphertext ROTATIONS (a
    rotate-and-add tree), which require Galois keys -- NOT an extra
    multiplicative level. ``fairlend.crypto.ckks.build_fla_context``
    already calls ``generate_galois_keys()`` once; ``derive_lpu_context``
    copies the FLA's context (which carries those already-generated,
    PUBLIC Galois keys) and only strips the secret key
    (``make_context_public(generate_galois_keys=False)`` means "do not
    generate NEW ones", not "remove the existing public ones"). Verified:
    ``derive_lpu_context(...).has_galois_keys()`` and
    ``.has_relin_keys()`` are both ``True`` even though the LPU context
    has no secret key -- this is exactly why compSim can run entirely on
    the LPU's public context.
  - Multiplicative depth: one ciphertext-ciphertext multiplication per
    reference vector (``g_i * r_k``, evaluated via ``.dot()``), for each
    of the two references -- the two per-reference multiplications are
    independent of each other (same level, not chained), matching the
    manuscript's "effective multiplicative depth one" claim for this
    specific operation. This was verified by running the operation
    end-to-end rather than assumed from the manuscript's prose.
  - TenSEAL does NOT reliably reject a ciphertext with the wrong number
    of slots: a size-1 ciphertext ``.dot()``-ed against a size-2 one was
    observed to silently return a wrong-but-not-erroring result (evidently
    broadcasting) rather than raising -- only a size-0 (empty) ciphertext
    was observed to raise ``ValueError: can't compute on vectors of
    different sizes``. This module therefore checks ``.size()`` against
    the expected slot count itself, explicitly, before calling ``.dot()``
    on anything (``_assert_expected_size``) -- note the expected size
    differs for a one-hot vector (``GENDER_VECTOR_SIZE = 2``) versus a
    similarity-score ciphertext (``SIMILARITY_SCORE_SIZE = 1``, since
    ``.dot()`` collapses to a single slot) -- and never relies on TenSEAL
    to catch a shape mismatch.

ROLE BOUNDARY: ``comp_sim`` is the ONLY production entry point in this
module. It:
  - accepts a ``ProtectedAttributeCredential`` (never a plaintext "male"/
    "female" string, never a plaintext one-hot vector) and the issuing
    IP's public key, and verifies the credential's signature BEFORE
    evaluating anything -- an unverified, tampered, or substituted
    credential never reaches a homomorphic operation;
  - requires its ``lpu_context`` argument to NOT hold ``sk_HE`` (checked
    structurally, same pattern as ``fairlend.roles.lpu``/
    ``fairlend.roles.identity_provider``);
  - returns an ``EncryptedSimilarityPair`` of ciphertexts -- it NEVER
    decrypts anything and never returns a plaintext float.

Decryption of a similarity pair is a SEPARATE, clearly-named diagnostic
function (``decrypt_similarity_pair_for_diagnostics``) that requires a
private (``sk_HE``-holding) context and is never called from LPU-side
production code. This module also does not implement argmax/delta*/
matched-unmatched classification -- ``comp_sim`` returns encrypted scores
only; classification is a later, separate evaluation layer.

Reference vectors (``HE.r_m``, ``HE.r_f``) are generated ONCE by the FLA
during setup (``generate_encrypted_references``) and are stable,
serializable protocol objects (``EncryptedReferenceVectors``) reused
across every borrower -- never regenerated per borrower.
"""
from __future__ import annotations

from dataclasses import dataclass

import tenseal as ts
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fairlend.core.exceptions import CredentialVerificationError, KeyBoundaryError, MalformedCiphertextError
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential
from fairlend.crypto.ckks import context_can_decrypt

# One-hot slot layout: (male, female) -- matches
# fairlend.roles.identity_provider.MALE_ONE_HOT / FEMALE_ONE_HOT exactly.
MALE_REFERENCE = (1.0, 0.0)
FEMALE_REFERENCE = (0.0, 1.0)
GENDER_VECTOR_SIZE = 2

# CKKSVector.dot() returns a SINGLE-slot ciphertext (verified empirically:
# `.dot()` on two size-2 vectors has `.size() == 1`, not 2) -- a
# similarity score is a scalar, not a one-hot pair, and must be checked
# against a DIFFERENT expected size than g_i/r_m/r_f. Conflating these two
# checks was caught during implementation and is exactly the kind of
# TenSEAL-shape assumption this module's docstring warns against making
# without verifying against the real library.
SIMILARITY_SCORE_SIZE = 1


def _assert_expected_size(vector: ts.CKKSVector, expected_size: int, label: str) -> None:
    """Explicit shape guard -- see this module's TenSEAL-behaviour note:
    the library does not reliably reject a slot-count mismatch itself."""
    if vector.size() != expected_size:
        raise MalformedCiphertextError(
            f"{label} ciphertext has {vector.size()} slot(s); expected exactly "
            f"{expected_size}."
        )


def _deserialize_with_expected_size(
    context: ts.Context, data: bytes, expected_size: int, label: str
) -> ts.CKKSVector:
    """Deserialize ``data`` into ``context``, translating TenSEAL's parse
    failure into this codebase's own explicit error type, then check
    shape. Never decrypts."""
    try:
        vector = ts.ckks_vector_from(context, data)
    except ValueError as exc:
        raise MalformedCiphertextError(f"{label}: failed to parse ciphertext bytes ({exc}).") from exc
    _assert_expected_size(vector, expected_size, label)
    return vector


def _deserialize_gender_vector(context: ts.Context, data: bytes, label: str) -> ts.CKKSVector:
    return _deserialize_with_expected_size(context, data, GENDER_VECTOR_SIZE, label)


def _deserialize_similarity_score(context: ts.Context, data: bytes, label: str) -> ts.CKKSVector:
    return _deserialize_with_expected_size(context, data, SIMILARITY_SCORE_SIZE, label)


# --- Encrypted reference vectors (FLA setup; stable across all borrowers) --


@dataclass(frozen=True)
class EncryptedReferenceVectors:
    """The manuscript's ``HE.r_m``/``HE.r_f``, as stable, transportable
    bytes -- generated ONCE by the FLA (``generate_encrypted_references``)
    and reused, unchanged, across every borrower's ``comp_sim`` call. Not
    regenerated per borrower."""

    male_reference_bytes: bytes
    female_reference_bytes: bytes


def generate_encrypted_references(fla_context: ts.Context) -> EncryptedReferenceVectors:
    """FLA setup step (Algorithm 1: ``FLA -> LPU: send(pk_HE, evk_HE,
    HE.r_m, HE.r_f)``). Requires the FLA's private (``sk_HE``-holding)
    context, per task Sec. 4 ("The FLA should generate/encrypt the
    reference values during setup using the private-capable context.") --
    though encryption itself only ever needs ``pk_HE``, using the FLA's
    own context here keeps reference generation structurally tied to the
    role that owns protocol setup, not to an arbitrary caller.
    """
    if not context_can_decrypt(fla_context):
        raise KeyBoundaryError(
            "generate_encrypted_references must be called with the FLA's "
            "private CKKS context (see fairlend.crypto.ckks.build_fla_context)."
        )
    male = ts.ckks_vector(fla_context, list(MALE_REFERENCE))
    female = ts.ckks_vector(fla_context, list(FEMALE_REFERENCE))
    return EncryptedReferenceVectors(
        male_reference_bytes=male.serialize(), female_reference_bytes=female.serialize()
    )


@dataclass(frozen=True)
class LoadedReferenceVectors:
    """``EncryptedReferenceVectors`` deserialized into a specific context
    (the LPU's public context for production ``comp_sim`` calls, or the
    FLA's private context for diagnostics) -- live ``ts.CKKSVector``
    objects, not bytes."""

    male: ts.CKKSVector
    female: ts.CKKSVector


def load_reference_vectors(references: EncryptedReferenceVectors, context: ts.Context) -> LoadedReferenceVectors:
    """Deserialize the stable reference bytes into ``context``. Works for
    either an LPU public context or an FLA private context -- the
    reference vectors themselves are not borrower data and carry no
    secret; only ``comp_sim`` (below) restricts which kind of context its
    OWN ``lpu_context`` argument may be."""
    male = _deserialize_gender_vector(context, references.male_reference_bytes, "reference (male)")
    female = _deserialize_gender_vector(context, references.female_reference_bytes, "reference (female)")
    return LoadedReferenceVectors(male=male, female=female)


# --- compSim (production, LPU-side) ----------------------------------------


@dataclass(frozen=True)
class EncryptedSimilarityPair:
    """compSim's output: s_i,m and s_i,f, both still ciphertexts. Neither
    is decryptable by the LPU (it never holds ``sk_HE``); decryption is
    FLA/diagnostic-only (``decrypt_similarity_pair_for_diagnostics``)."""

    male_score_ciphertext: ts.CKKSVector
    female_score_ciphertext: ts.CKKSVector

    def serialize(self) -> "SerializedSimilarityPair":
        return SerializedSimilarityPair(
            male_score_bytes=self.male_score_ciphertext.serialize(),
            female_score_bytes=self.female_score_ciphertext.serialize(),
        )


@dataclass(frozen=True)
class SerializedSimilarityPair:
    """Transportable form of ``EncryptedSimilarityPair`` -- what the LPU
    actually sends to the FLA."""

    male_score_bytes: bytes
    female_score_bytes: bytes


def comp_sim(
    credential: ProtectedAttributeCredential,
    ip_public_key: Ed25519PublicKey,
    references: LoadedReferenceVectors,
    lpu_context: ts.Context,
) -> EncryptedSimilarityPair:
    """compSim(HE.g_i, HE.r_k) = sum_j HE(g_i,j) (x) HE(r_k,j), k in {m, f}.

    Args:
        credential: The IP-issued ``ProtectedAttributeCredential`` --
            NEVER a plaintext "male"/"female" string or a plaintext
            one-hot vector. Its signature is verified here, before any
            homomorphic operation, using ``ip_public_key``; an invalid
            signature (wrong key, tampered ciphertext/digest/signature,
            or a substituted ciphertext) raises
            ``CredentialVerificationError`` and computes nothing.
        ip_public_key: The issuing IP's Ed25519 public key (``pk_IP_sig``).
        references: ``HE.r_m``/``HE.r_f`` already loaded into
            ``lpu_context`` (see ``load_reference_vectors``) -- the SAME
            stable reference objects reused across every borrower.
        lpu_context: The LPU's public CKKS context. Must NOT hold
            ``sk_HE`` -- checked structurally; raises ``KeyBoundaryError``
            otherwise, the same invariant
            ``fairlend.roles.lpu.LoanProcessingUnit`` enforces at
            construction.

    Returns:
        An ``EncryptedSimilarityPair`` -- both scores remain ciphertexts.
        This function never decrypts anything and never returns a float.
    """
    if context_can_decrypt(lpu_context):
        raise KeyBoundaryError(
            "comp_sim's lpu_context must not hold sk_HE -- this is the LPU-side "
            "production evaluation path. Use "
            "decrypt_similarity_pair_for_diagnostics with the FLA's private "
            "context for diagnostic decryption instead."
        )
    if not credential.verify(ip_public_key):
        raise CredentialVerificationError(
            "protected-attribute credential failed IP signature verification; "
            "refusing to evaluate compSim on unauthenticated ciphertext."
        )

    g_i = _deserialize_gender_vector(lpu_context, credential.ciphertext_bytes, "borrower protected-attribute (g_i)")
    _assert_expected_size(references.male, GENDER_VECTOR_SIZE, "reference (r_m)")
    _assert_expected_size(references.female, GENDER_VECTOR_SIZE, "reference (r_f)")

    male_score = g_i.dot(references.male)
    female_score = g_i.dot(references.female)
    return EncryptedSimilarityPair(male_score_ciphertext=male_score, female_score_ciphertext=female_score)


# --- Diagnostic decryption (FLA/evaluator-only; NEVER LPU production) ------


@dataclass(frozen=True)
class DecryptedSimilarityPair:
    """Plaintext form of a similarity pair -- produced ONLY by
    ``decrypt_similarity_pair_for_diagnostics``, never by ``comp_sim`` or
    any LPU-side code."""

    male_score: float
    female_score: float


def decrypt_similarity_pair_for_diagnostics(
    serialized: SerializedSimilarityPair, fla_context: ts.Context
) -> DecryptedSimilarityPair:
    """FLA/EVALUATOR-ONLY. Exercises the real protocol boundary: the
    serialized scores (as the LPU would actually send them) are
    deserialized into the FLA's PRIVATE context and decrypted here. This
    is the only function in this module that ever produces a plaintext
    float, and it must never be called from LPU-side production code.

    Raises:
        KeyBoundaryError: if ``fla_context`` does not hold ``sk_HE``.
        MalformedCiphertextError: if either serialized score fails to parse.
    """
    if not context_can_decrypt(fla_context):
        raise KeyBoundaryError(
            "decrypt_similarity_pair_for_diagnostics requires the FLA's "
            "private (sk_HE-holding) context; this is diagnostic/evaluator-"
            "only code, never part of the LPU production path."
        )
    male = _deserialize_similarity_score(fla_context, serialized.male_score_bytes, "similarity score (male)")
    female = _deserialize_similarity_score(fla_context, serialized.female_score_bytes, "similarity score (female)")
    return DecryptedSimilarityPair(male_score=male.decrypt()[0], female_score=female.decrypt()[0])
