"""Plaintext aggregate sufficient statistics: C_k, A_k, P_k, TP_k, N_k, FP_k
(manuscript Sec. 4.7/4.8, Algorithm 5's plaintext analogue).

This module is deliberately model-decision-agnostic: it consumes a
DataFrame of already-decided, already-grouped audit records (one row per
TEST application, one ``model`` at a time) and counts. It does not fit,
predict, or otherwise touch a credit-decision model -- see
``evaluation/run_plaintext_audit.py``, which reads the FROZEN
``model_predictions.parquet`` written by
``evaluation/train_credit_models.py`` (Phase 1) and never calls
``.fit()``/``.predict()`` again.

Population rules (manuscript Sec. 4.7/4.8; see
``fairlend.data.audit_scope`` for where these populations are computed):

    C_k: every valid held-out TEST application in group k, regardless of
         approval decision or outcome resolution.
    A_k: the subset of C_k with an approval decision (y_pred == 1).
    P_k, N_k, TP_k, FP_k: computed ONLY over the RESOLVED-outcome subset
         of C_k (test_eo_index) -- an unresolved-outcome TEST row
         contributes to C_k/A_k but must never contribute here.

``build_audit_frame`` is the identity-integrity join step (predictions x
synthetic protected attribute, checked against the split's TEST/TRAIN/
VALIDATION index files); ``compute_plaintext_audit`` is the pure counting
step. Keeping them separate lets tests exercise counting logic against a
small hand-built DataFrame without needing a real join.

---

ENCRYPTED PATH -- three conceptually distinguishable implementations are
defined below, per reviewer2_phase2_bfv_migration_report.md:

    1. LEGACY   (Phase 5): CKKS + compSim.
    2. PHASE-1 BASELINE:   CKKS + direct additive aggregation.
    3. ACTIVE   (Phase 2): BFV + direct additive aggregation.

Nothing above this point (the plaintext API) is modified by any of them,
and its behaviour/tests are unaffected. ``compute_encrypted_audit`` (no
suffix) is the ACTIVE path as of Phase 2 -- BFV, not CKKS; the Phase 1
CKKS-direct baseline is retained under its own explicit
``*_ckks_direct``/``CKKSDirect*`` names (renamed from Phase 1's bare
canonical names when Phase 2 introduced BFV as the new active scheme) for
the CKKS-vs-BFV differential comparison this report documents.

PHASE 1 (production, ``compute_encrypted_audit`` / ``EncryptedAuditPacket``
/ ``EncryptedAuditCounts``): reviewer2_implementation_gap_audit.md
established that, given the manuscript's own reference-vector definitions
(``HE.r_m = Enc(1,0)``, ``HE.r_f = Enc(0,1)``), compSim's output is
provably identical to the credential's own ciphertext slot --
``compSim(HE.g_i, HE.r_m) = Enc(g_i,m)`` -- so multiplying against a
reference vector to "recompute" a value already present in the ciphertext
is unnecessary. This path therefore accumulates each row's own 2-slot
``HE.g_i`` credential ciphertext DIRECTLY into six 2-slot running-total
ciphertexts (one per statistic, both groups packed in the same
ciphertext's two SIMD slots) via ADDITION ONLY:

    HE.C  += HE.g_i                          (always)
    HE.A  += HE.g_i     iff y_pred == 1
    HE.P  += HE.g_i     iff resolved and y_true == 1
    HE.N  += HE.g_i     iff resolved and y_true == 0
    HE.TP += HE.g_i     iff resolved and y_true == 1 and y_pred == 1
    HE.FP += HE.g_i     iff resolved and y_true == 0 and y_pred == 1

Decrypting any one of these six 2-slot ciphertexts yields ``[stat_m,
stat_f]`` directly -- e.g. ``Dec(HE.C) = [C_m, C_f]`` -- with no
reference vectors, no ciphertext-ciphertext multiplication, no
relinearisation, and no rescaling anywhere in this path (multiplicative
depth 0; see reviewer2_phase1_compsim_removal_report.md's "Complexity
change" section for the measured comparison against the legacy path).
This also halves the aggregate packet's ciphertext count (6, one per
statistic, versus the legacy path's 12, one per statistic PER group).

Per-record group-membership ciphertexts are obtained EXCLUSIVELY via
``fairlend.audit.similarity.load_verified_protected_attribute_vector`` on
a real, IP-issued, LPU-verified ``ProtectedAttributeCredential`` (see
``EncryptedTestRecord`` below) -- this module never accepts, and never
internally constructs, a ciphertext from a plaintext gender label.
Producing that credential in the first place (i.e. deciding which label
to ask the IP to encrypt for a given TEST row) is the EVALUATION
HARNESS's job (``evaluation/run_encrypted_audit.py``), exactly as
``fairlend.roles.identity_provider.IdentityProvider.issue_credential``'s
own docstring describes -- the harness may know a row's synthetic label
(it generated the controlled experiment), but nothing in this module ever
does.

Conditional accumulation uses plain Python ``if`` statements on PLAINTEXT
``y_pred``/``y_true`` (the LPU's own legitimate operational data -- a
loan decision and a repayment outcome are not secret; only the protected
attribute is) to decide WHETHER to homomorphically add a given row's
credential ciphertext into a given aggregate -- never a ciphertext-
plaintext multiplication by a 0/1 indicator, since a plain Python
conditional skip achieves the identical result with strictly less
homomorphic work and no multiplicative depth at all.

ENCRYPTED-ZERO INITIALISATION: every accumulator here is initialised as a
fresh, top-level 2-slot zero ciphertext (``ts.ckks_vector(context, [0.0,
0.0])``), and every ``HE.g_i`` added to it is ALSO fresh and top-level
(never multiplied by anything in this path) -- so, unlike the legacy
path below, there is no level mismatch to reconcile at all; addition
between two top-level ciphertexts needs no ``auto_mod_switch`` help.

LEGACY (``compute_encrypted_audit_legacy_compsim`` /
``LegacyEncryptedAuditPacket`` / ``LegacyEncryptedGroupAuditCounts``,
Phase 5; manuscript Algorithm 5 as originally implemented): every
group-membership contribution is an ENCRYPTED similarity score
(``fairlend.audit.similarity.comp_sim``'s output, one ciphertext-
ciphertext multiplication per reference vector) rather than the
credential's own ciphertext -- the LPU never learns which group a row is
in; it homomorphically adds the SAME similarity-weighted ciphertext to a
row's contribution for EVERY group, and only decryption (FLA-only,
diagnostic in this phase) reveals the resulting per-group tallies. This
path is RETAINED, unchanged in behaviour, exclusively for the Phase 1
equivalence check (``evaluation/run_compsim_removal_equivalence_check.py``)
and historical/reproducibility tests
(``tests/scientific/test_encrypted_aggregation.py``,
``test_encrypted_aggregation_privacy.py``) -- it is no longer called by
any evaluation script that represents the active production path.

LEGACY ENCRYPTED-ZERO INITIALISATION (verified empirically, not assumed):
TenSEAL's ``auto_mod_switch=True`` (default on every context this
codebase creates) automatically reconciles the level mismatch between a
FRESH, top-level zero ciphertext (``ts.ckks_vector(context, [0.0])``) and
a post-``comp_sim`` ciphertext (which has gone through one
multiplication + automatic rescale, and is therefore one level lower).
This was verified directly: adding a fresh zero to a compSim output, and
accumulating 38 sequential compSim outputs into a fresh-zero-initialised
accumulator, both produced numerically correct results (absolute error
~2-3e-6, consistent with Phase 4's measured compSim noise) with no
error and no manual level/rescale handling. Legacy aggregates in this
module are therefore initialised as fresh top-level zero ciphertexts --
NOT by copying the first contributing ciphertext (an alternative this
module's design note originally considered) and NOT by decrypting/
re-encrypting to "fix" a level mismatch, since no such fix is needed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Optional, Sequence, Tuple

import tenseal as ts
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fairlend.audit.similarity import LoadedReferenceVectors, comp_sim, load_verified_protected_attribute_vector
from fairlend.core.config import BFVConfig
from fairlend.core.exceptions import (
    BFVOverflowError,
    CredentialVerificationError,
    KeyBoundaryError,
    MalformedCiphertextError,
)
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential
from fairlend.crypto.ckks import context_can_decrypt
from fairlend.crypto import bfv as bfv_crypto

if TYPE_CHECKING:
    # pandas is an evaluation-extra dependency (see pyproject.toml), not a
    # core dependency: this module's actual encrypted-compute functions
    # (compute_encrypted_audit, build_encrypted_aggregate_packet,
    # decrypt_audit_packet_for_diagnostics) never touch a DataFrame. Only
    # the plaintext-oracle helpers below (build_audit_frame,
    # compute_group_counts, compute_plaintext_audit) operate on pandas
    # objects, and `from __future__ import annotations` (above) already
    # makes every `pd.DataFrame`/`pd.Index` annotation in this file a
    # lazily-evaluated string -- so importing pandas only under
    # TYPE_CHECKING costs nothing at runtime and keeps
    # `fairlend.secure_compute`/`fairlend.audit` importable with only the
    # core dependency set.
    import pandas as pd

GROUP_MALE = "male"
GROUP_FEMALE = "female"
GROUPS: Tuple[str, ...] = (GROUP_MALE, GROUP_FEMALE)

# fairlend.data.synthetic_gender.SyntheticGenderResult.label: 0 = male, 1 = female.
_SYNTHETIC_LABEL_TO_GROUP = {0: GROUP_MALE, 1: GROUP_FEMALE}

REQUIRED_AUDIT_FRAME_COLUMNS = {"row_index", "group", "y_true", "y_pred"}


@dataclass(frozen=True)
class GroupAuditCounts:
    """Plaintext sufficient statistics for one protected-attribute group.

    ``P``/``N``/``TP``/``FP`` are computed over the RESOLVED-outcome
    subset of ``C`` only -- an unresolved-outcome record is counted in
    ``C``/``A`` (if approved) and nowhere else.
    """

    group: str
    C: int
    A: int
    P: int
    TP: int
    N: int
    FP: int

    def __post_init__(self) -> None:
        if self.group not in GROUPS:
            raise ValueError(f"group must be one of {GROUPS!r}, got {self.group!r}")
        for name, value in (("C", self.C), ("A", self.A), ("P", self.P),
                            ("TP", self.TP), ("N", self.N), ("FP", self.FP)):
            if value < 0:
                raise ValueError(f"{name} must be >= 0 for group {self.group!r}, got {value}")
        if self.A > self.C:
            raise ValueError(
                f"group {self.group!r}: A_k ({self.A}) must be <= C_k ({self.C})."
            )
        if self.TP > self.P:
            raise ValueError(
                f"group {self.group!r}: TP_k ({self.TP}) must be <= P_k ({self.P})."
            )
        if self.FP > self.N:
            raise ValueError(
                f"group {self.group!r}: FP_k ({self.FP}) must be <= N_k ({self.N})."
            )


@dataclass(frozen=True)
class PlaintextAuditResult:
    """Both groups' counts for ONE model, plus the TEST population
    accounting that produced them."""

    model_name: str
    groups: Dict[str, GroupAuditCounts]
    full_test_n: int
    resolved_test_n: int
    unresolved_test_n: int

    def group(self, name: str) -> GroupAuditCounts:
        return self.groups[name]

    def male(self) -> GroupAuditCounts:
        return self.groups[GROUP_MALE]

    def female(self) -> GroupAuditCounts:
        return self.groups[GROUP_FEMALE]

    def assert_consistent(self) -> None:
        """Cross-group / population-level invariants (task Sec. 8)."""
        m, f = self.male(), self.female()
        if self.full_test_n != self.resolved_test_n + self.unresolved_test_n:
            raise ValueError(
                f"full_test_n ({self.full_test_n}) != resolved_test_n "
                f"({self.resolved_test_n}) + unresolved_test_n "
                f"({self.unresolved_test_n})."
            )
        if m.C + f.C != self.full_test_n:
            raise ValueError(
                f"C_m + C_f ({m.C} + {f.C} = {m.C + f.C}) != full_test_n "
                f"({self.full_test_n})."
            )
        if (m.P + f.P + m.N + f.N) != self.resolved_test_n:
            raise ValueError(
                f"P_m + P_f + N_m + N_f ({m.P}+{f.P}+{m.N}+{f.N} = "
                f"{m.P + f.P + m.N + f.N}) != resolved_test_n "
                f"({self.resolved_test_n})."
            )


def build_audit_frame(
    predictions: pd.DataFrame,
    synthetic_gender: pd.DataFrame,
    test_dp_index: pd.Index,
    test_eo_index: pd.Index,
    train_index: pd.Index,
    validation_index: pd.Index,
) -> pd.DataFrame:
    """Join one model's frozen TEST predictions to the synthetic
    protected-attribute assignment, with identity-integrity assertions.

    Args:
        predictions: One model's rows from ``model_predictions.parquet``
            (columns ``row_index``, ``y_true``, ``y_pred`` at minimum).
        synthetic_gender: The generated protected attribute (columns
            ``row_index``, ``synthetic_gender_label``).
        test_dp_index: The full TEST population (resolved + unresolved) --
            ``predictions["row_index"]`` must equal this set EXACTLY.
        test_eo_index: The resolved-outcome subset of TEST -- used only to
            cross-check against ``y_true`` nullability already present in
            ``predictions`` (defence-in-depth, not the primary source of
            truth for which rows are resolved).
        train_index, validation_index: Used only to assert no leakage.

    Raises:
        ValueError: on any duplicate identity, any predictions row not in
            (or missing from) the TEST population, any train/validation
            leakage, any record with no protected-attribute assignment, or
            any disagreement between ``test_eo_index`` and ``y_true``
            nullability.
    """
    if predictions["row_index"].duplicated().any():
        raise ValueError("duplicate row_index in predictions for a single model.")
    if synthetic_gender["row_index"].duplicated().any():
        raise ValueError("duplicate row_index in the synthetic-gender table.")

    prediction_ids = set(predictions["row_index"])
    test_ids = set(test_dp_index)
    missing = test_ids - prediction_ids
    extra = prediction_ids - test_ids
    if missing or extra:
        raise ValueError(
            "predictions row_index set does not exactly match the TEST "
            f"(demographic-parity) population: {len(missing)} TEST row(s) "
            f"missing a prediction, {len(extra)} prediction(s) outside TEST."
        )

    leaked = (set(train_index) | set(validation_index)) & prediction_ids
    if leaked:
        raise ValueError(
            f"{len(leaked)} train/validation row(s) present in audit "
            "predictions -- train/validation records must never enter the "
            "final audit."
        )

    merged = predictions.merge(
        synthetic_gender[["row_index", "synthetic_gender_label"]],
        on="row_index",
        how="left",
        validate="one_to_one",
    )
    if merged["synthetic_gender_label"].isna().any():
        n_missing = int(merged["synthetic_gender_label"].isna().sum())
        raise ValueError(
            f"{n_missing} audit record(s) have no synthetic protected-"
            "attribute assignment -- every prediction must map to exactly "
            "one protected-attribute label."
        )
    merged["group"] = merged["synthetic_gender_label"].astype(int).map(_SYNTHETIC_LABEL_TO_GROUP)
    if merged["group"].isna().any():
        raise ValueError("synthetic_gender_label contained a value other than 0 or 1.")

    resolved_by_split = merged["row_index"].isin(set(test_eo_index))
    resolved_by_outcome = merged["y_true"].notna()
    if not resolved_by_split.equals(resolved_by_outcome):
        disagreement = int((resolved_by_split != resolved_by_outcome).sum())
        raise ValueError(
            f"{disagreement} record(s) disagree between test_eo_index "
            "membership and y_true nullability in the frozen predictions -- "
            "these must be derived from the same underlying dataset."
        )

    return merged


def compute_group_counts(audit_frame: pd.DataFrame, group: str) -> GroupAuditCounts:
    """Count C/A/P/TP/N/FP for one group from an already-joined,
    already-validated audit frame (see ``build_audit_frame``)."""
    missing_columns = REQUIRED_AUDIT_FRAME_COLUMNS - set(audit_frame.columns)
    if missing_columns:
        raise ValueError(f"audit_frame is missing required column(s): {sorted(missing_columns)!r}")

    subset = audit_frame[audit_frame["group"] == group]
    C = int(len(subset))
    A = int((subset["y_pred"].astype(int) == 1).sum())

    resolved = subset[subset["y_true"].notna()]
    y_true = resolved["y_true"].astype(int)
    y_pred = resolved["y_pred"].astype(int)
    P = int((y_true == 1).sum())
    N = int((y_true == 0).sum())
    TP = int(((y_true == 1) & (y_pred == 1)).sum())
    FP = int(((y_true == 0) & (y_pred == 1)).sum())

    return GroupAuditCounts(group=group, C=C, A=A, P=P, TP=TP, N=N, FP=FP)


def compute_plaintext_audit(audit_frame: pd.DataFrame, model_name: str) -> PlaintextAuditResult:
    """Compute both groups' counts for one model and check cross-group
    consistency (Sec. 8 assertions)."""
    groups = {group: compute_group_counts(audit_frame, group) for group in GROUPS}
    full_test_n = int(len(audit_frame))
    resolved_test_n = int(audit_frame["y_true"].notna().sum())
    unresolved_test_n = full_test_n - resolved_test_n

    result = PlaintextAuditResult(
        model_name=model_name,
        groups=groups,
        full_test_n=full_test_n,
        resolved_test_n=resolved_test_n,
        unresolved_test_n=unresolved_test_n,
    )
    result.assert_consistent()
    return result


# ============================================================================
# ENCRYPTED PATH (Phase 5) -- see module docstring's "ENCRYPTED PATH" section
# ============================================================================

_STAT_NAMES: Tuple[str, ...] = ("C", "A", "P", "TP", "N", "FP")

# LEGACY (Phase 5, compSim-based) packet's protocol-version string is
# unchanged (``PROTOCOL_VERSION`` below); the NEW direct-addition packet
# uses a distinct version string so a reader/consumer can always tell
# which aggregation path produced a given wire packet from its own
# metadata, never by guessing from field shape alone.
PROTOCOL_VERSION_DIRECT = "fairlend/encrypted-audit-ckks-direct/v1"
PROTOCOL_VERSION_BFV = "fairlend/encrypted-audit-bfv-direct/v1"


@dataclass(frozen=True)
class EncryptedTestRecord:
    """One TEST row's ALREADY-ISSUED protected-attribute credential plus
    the LPU's own plaintext operational data for that row (its decision,
    and the realised outcome if resolved).

    ``row_index`` is retained here ONLY as intermediate join/validation
    metadata for constructing this list (see
    ``evaluation/run_encrypted_audit.py``) -- it is never copied into
    ``EncryptedAuditPacket`` (the actual LPU->FLA transport object), which
    contains no per-record field at all.

    Contains NO plaintext gender, one-hot vector, or probability -- the
    only gender-related content is ``credential.ciphertext_bytes``, an
    opaque CKKS ciphertext.
    """

    row_index: int
    credential: ProtectedAttributeCredential
    y_pred: int
    y_true: Optional[int]  # None if this TEST row's outcome is unresolved


@dataclass(frozen=True)
class LegacyEncryptedGroupAuditCounts:
    """LEGACY (Phase 5, compSim-based). One group's encrypted sufficient
    statistics. All six fields are live ``ts.CKKSVector`` ciphertexts
    (size 1) -- never decrypted here."""

    C: ts.CKKSVector
    A: ts.CKKSVector
    P: ts.CKKSVector
    TP: ts.CKKSVector
    N: ts.CKKSVector
    FP: ts.CKKSVector


@dataclass(frozen=True)
class LegacyEncryptedAuditResult:
    """LEGACY (Phase 5, compSim-based). LPU-side working result:
    ciphertexts still live under the LPU's context. Convert to a
    transportable ``LegacyEncryptedAuditPacket`` via
    ``build_encrypted_aggregate_packet_legacy_compsim`` before sending to
    the FLA."""

    male: LegacyEncryptedGroupAuditCounts
    female: LegacyEncryptedGroupAuditCounts
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int


def compute_encrypted_audit_legacy_compsim(
    records: Sequence[EncryptedTestRecord],
    ip_public_key: Ed25519PublicKey,
    references: LoadedReferenceVectors,
    lpu_context: ts.Context,
    model_name: str,
) -> LegacyEncryptedAuditResult:
    """LEGACY (Phase 5, compSim-based) manuscript Algorithm 5 encrypted
    aggregation: for every TEST record, compute its encrypted group-
    membership similarity (``comp_sim``, which itself verifies the IP's
    signature before computing anything -- an invalid/tampered/
    substituted credential aborts this whole call), then homomorphically
    add that similarity into every aggregate the row's PLAINTEXT
    decision/outcome make it eligible for:

        always:                       C_k += s_i,k
        if y_pred == 1:                A_k += s_i,k
        if resolved and Y == 1:        P_k += s_i,k
        if resolved and Y == 0:        N_k += s_i,k
        if resolved and Y==1, pred==1: TP_k += s_i,k
        if resolved and Y==0, pred==1: FP_k += s_i,k

    for BOTH k in {male, female} every time -- the LPU never branches on
    which group a row is actually in (it cannot; ``s_i,k`` is a
    ciphertext), so structurally there is no code path where group
    membership influences control flow.

    RETAINED ONLY for the Phase 1 equivalence check
    (``evaluation/run_compsim_removal_equivalence_check.py``) and
    historical/reproducibility tests -- the active production path is
    ``compute_encrypted_audit`` (below), which does not call this
    function or ``comp_sim``.

    Args:
        records: One ``EncryptedTestRecord`` per TEST row for this model,
            covering the TEST population exactly (validated by the
            caller -- see ``evaluation/run_encrypted_audit.py`` -- before
            this function ever runs).
        lpu_context: The LPU's public CKKS context. Must NOT hold
            ``sk_HE`` -- checked structurally, same invariant as
            ``fairlend.audit.similarity.comp_sim``.

    Returns:
        A ``LegacyEncryptedAuditResult`` whose six-times-two ciphertexts
        have never been decrypted.
    """
    if context_can_decrypt(lpu_context):
        raise KeyBoundaryError(
            "compute_encrypted_audit_legacy_compsim's lpu_context must not hold "
            "sk_HE -- this is the LPU-side production aggregation path."
        )

    accumulators: Dict[str, Dict[str, ts.CKKSVector]] = {
        group: {stat: ts.ckks_vector(lpu_context, [0.0]) for stat in _STAT_NAMES} for group in GROUPS
    }
    resolved_test_n = 0

    for record in records:
        pair = comp_sim(record.credential, ip_public_key, references, lpu_context)
        scores = {GROUP_MALE: pair.male_score_ciphertext, GROUP_FEMALE: pair.female_score_ciphertext}

        for group in GROUPS:
            s = scores[group]
            accumulators[group]["C"] = accumulators[group]["C"] + s
            if record.y_pred == 1:
                accumulators[group]["A"] = accumulators[group]["A"] + s
            if record.y_true is not None:
                if record.y_true == 1:
                    accumulators[group]["P"] = accumulators[group]["P"] + s
                    if record.y_pred == 1:
                        accumulators[group]["TP"] = accumulators[group]["TP"] + s
                elif record.y_true == 0:
                    accumulators[group]["N"] = accumulators[group]["N"] + s
                    if record.y_pred == 1:
                        accumulators[group]["FP"] = accumulators[group]["FP"] + s

        if record.y_true is not None:
            resolved_test_n += 1

    full_test_n = len(records)
    return LegacyEncryptedAuditResult(
        male=LegacyEncryptedGroupAuditCounts(**accumulators[GROUP_MALE]),
        female=LegacyEncryptedGroupAuditCounts(**accumulators[GROUP_FEMALE]),
        model=model_name,
        test_population_n=full_test_n,
        resolved_test_n=resolved_test_n,
        unresolved_test_n=full_test_n - resolved_test_n,
    )


@dataclass(frozen=True)
class LegacySerializedGroupAuditCounts:
    """LEGACY (Phase 5, compSim-based). Serialized ciphertext bytes for
    one group's six aggregates."""

    C: bytes
    A: bytes
    P: bytes
    TP: bytes
    N: bytes
    FP: bytes


PROTOCOL_VERSION = "fairlend/encrypted-audit/v1"


@dataclass(frozen=True)
class LegacyEncryptedAuditPacket:
    """LEGACY (Phase 5, compSim-based). The LPU -> FLA transport object.

    Contains ONLY: serialized ciphertext bytes for the six aggregate
    statistics, per group (12 ciphertexts total), plus POPULATION-COUNT
    metadata (how many TEST rows total/resolved/unresolved contributed --
    an aggregate count, not per-record data) and a model name/protocol
    version string.

    Deliberately absent (see tests/scientific/test_encrypted_aggregation_
    privacy.py for the exhaustive field-enumeration proof): uid, id,
    row_index, plaintext gender, synthetic gender label,
    probability_female, account data, credit score, or any per-borrower
    y_true/y_pred/similarity value. Nothing in this dataclass's fields, at
    any nesting depth, is per-record.
    """

    male: LegacySerializedGroupAuditCounts
    female: LegacySerializedGroupAuditCounts
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int
    protocol_version: str = PROTOCOL_VERSION


def _serialize_group_legacy(counts: LegacyEncryptedGroupAuditCounts) -> LegacySerializedGroupAuditCounts:
    return LegacySerializedGroupAuditCounts(
        C=counts.C.serialize(),
        A=counts.A.serialize(),
        P=counts.P.serialize(),
        TP=counts.TP.serialize(),
        N=counts.N.serialize(),
        FP=counts.FP.serialize(),
    )


def build_encrypted_aggregate_packet_legacy_compsim(result: LegacyEncryptedAuditResult) -> LegacyEncryptedAuditPacket:
    """LEGACY (Phase 5, compSim-based). Serialize a
    ``LegacyEncryptedAuditResult`` into the transportable, aggregate-only
    ``LegacyEncryptedAuditPacket``. Does not decrypt anything; does not
    touch ``lpu_context``; does not add any new field beyond what
    ``LegacyEncryptedAuditPacket`` declares."""
    return LegacyEncryptedAuditPacket(
        male=_serialize_group_legacy(result.male),
        female=_serialize_group_legacy(result.female),
        model=result.model,
        test_population_n=result.test_population_n,
        resolved_test_n=result.resolved_test_n,
        unresolved_test_n=result.unresolved_test_n,
    )


# ============================================================================
# PHASE 1 (production): direct encrypted-additive aggregation, no compSim
# ============================================================================


@dataclass(frozen=True)
class CKKSDirectAuditCounts:
    """PHASE 1 BASELINE (CKKS, direct addition -- no longer the ACTIVE
    protocol as of Phase 2, retained for the CKKS-vs-BFV differential
    comparison). The six aggregate sufficient statistics, EACH a live,
    still-encrypted 2-slot ``ts.CKKSVector`` (slot 0 = male, slot 1 =
    female) -- never decrypted here. Six ciphertexts total (half of the
    legacy path's twelve), since both groups are packed into the same
    accumulator per statistic."""

    C: ts.CKKSVector
    A: ts.CKKSVector
    P: ts.CKKSVector
    TP: ts.CKKSVector
    N: ts.CKKSVector
    FP: ts.CKKSVector


@dataclass(frozen=True)
class CKKSDirectAuditResult:
    """PHASE 1 BASELINE. LPU-side working result: ciphertexts still live
    under the LPU's context. Convert to a transportable
    ``CKKSDirectAuditPacket`` via
    ``build_encrypted_aggregate_packet_ckks_direct`` before sending to
    the FLA."""

    counts: CKKSDirectAuditCounts
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int


def compute_encrypted_audit_ckks_direct(
    records: Sequence[EncryptedTestRecord],
    ip_public_key: Ed25519PublicKey,
    lpu_context: ts.Context,
    model_name: str,
) -> CKKSDirectAuditResult:
    """PHASE 1 BASELINE (CKKS, direct encrypted-additive aggregation --
    superseded as the ACTIVE protocol by the BFV implementation below in
    Phase 2, retained unchanged as the CKKS side of the CKKS-vs-BFV
    differential comparison; see
    reviewer2_phase2_bfv_migration_report.md).

    For every TEST record, load and verify its protected-attribute
    credential's own 2-slot ciphertext ``HE.g_i`` (via
    ``fairlend.audit.similarity.load_verified_protected_attribute_vector``
    -- an invalid/tampered/substituted credential aborts this whole call,
    exactly as the legacy path's ``comp_sim`` call did), then
    homomorphically ADD that ciphertext -- unmodified, no multiplication,
    no reference vector -- into every aggregate the row's PLAINTEXT
    decision/outcome make it eligible for:

        always:                       HE.C  += HE.g_i
        if y_pred == 1:                HE.A  += HE.g_i
        if resolved and Y == 1:        HE.P  += HE.g_i
        if resolved and Y == 0:        HE.N  += HE.g_i
        if resolved and Y==1, pred==1: HE.TP += HE.g_i
        if resolved and Y==0, pred==1: HE.FP += HE.g_i

    Each accumulator's two SIMD slots track both groups simultaneously --
    ``Dec(HE.C) = [C_m, C_f]`` -- so there is no group-keyed branching at
    all: the LPU never learns, and never needs to know, which slot
    corresponds to which group's actual count for a given row.

    Multiplicative depth is 0 throughout this function: every ciphertext
    involved (``HE.g_i`` and every accumulator) is a fresh, unmultiplied,
    top-level CKKS ciphertext, so no relinearisation and no rescaling
    occurs anywhere in this call.

    Args:
        records: One ``EncryptedTestRecord`` per TEST row for this model,
            covering the TEST population exactly (validated by the
            caller -- see ``evaluation/run_encrypted_audit.py`` -- before
            this function ever runs).
        lpu_context: The LPU's public CKKS context. Must NOT hold
            ``sk_HE`` -- checked structurally, same invariant as the
            legacy path.

    Returns:
        A ``CKKSDirectAuditResult`` whose six ciphertexts have never been
        decrypted.
    """
    if context_can_decrypt(lpu_context):
        raise KeyBoundaryError(
            "compute_encrypted_audit_ckks_direct's lpu_context must not hold "
            "sk_HE -- this is the LPU-side production aggregation path."
        )

    accumulators: Dict[str, ts.CKKSVector] = {
        stat: ts.ckks_vector(lpu_context, [0.0, 0.0]) for stat in _STAT_NAMES
    }
    resolved_test_n = 0

    for record in records:
        g_i = load_verified_protected_attribute_vector(record.credential, ip_public_key, lpu_context)

        accumulators["C"] = accumulators["C"] + g_i
        if record.y_pred == 1:
            accumulators["A"] = accumulators["A"] + g_i
        if record.y_true is not None:
            if record.y_true == 1:
                accumulators["P"] = accumulators["P"] + g_i
                if record.y_pred == 1:
                    accumulators["TP"] = accumulators["TP"] + g_i
            elif record.y_true == 0:
                accumulators["N"] = accumulators["N"] + g_i
                if record.y_pred == 1:
                    accumulators["FP"] = accumulators["FP"] + g_i
            resolved_test_n += 1

    full_test_n = len(records)
    return CKKSDirectAuditResult(
        counts=CKKSDirectAuditCounts(**accumulators),
        model=model_name,
        test_population_n=full_test_n,
        resolved_test_n=resolved_test_n,
        unresolved_test_n=full_test_n - resolved_test_n,
    )


@dataclass(frozen=True)
class SerializedCKKSDirectAuditCounts:
    """Serialized ciphertext bytes for the six 2-slot aggregate
    statistics (Phase 1 baseline, CKKS direct addition)."""

    C: bytes
    A: bytes
    P: bytes
    TP: bytes
    N: bytes
    FP: bytes


@dataclass(frozen=True)
class CKKSDirectAuditPacket:
    """PHASE 1 BASELINE. The LPU -> FLA transport object.

    Contains ONLY: serialized ciphertext bytes for the six aggregate
    statistics (each a single 2-slot ciphertext covering BOTH groups --
    six ciphertexts total, half of the legacy packet's twelve), plus
    POPULATION-COUNT metadata (how many TEST rows total/resolved/
    unresolved contributed -- an aggregate count, not per-record data)
    and a model name/protocol version string.

    Deliberately absent (mirrors the legacy packet's privacy proof, see
    tests/scientific/test_encrypted_aggregation_direct.py): uid, id,
    row_index, plaintext gender, synthetic gender label,
    probability_female, account data, credit score, or any per-borrower
    y_true/y_pred value. Nothing in this dataclass's fields is
    per-record. There is no ``male``/``female`` nesting at all -- group
    separation lives entirely in each ciphertext's own two SIMD slots,
    never in the packet's field structure.
    """

    C: bytes
    A: bytes
    P: bytes
    TP: bytes
    N: bytes
    FP: bytes
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int
    protocol_version: str = PROTOCOL_VERSION_DIRECT


def build_encrypted_aggregate_packet_ckks_direct(result: CKKSDirectAuditResult) -> CKKSDirectAuditPacket:
    """PHASE 1 BASELINE. Serialize a ``CKKSDirectAuditResult`` into the
    transportable, aggregate-only ``CKKSDirectAuditPacket``. Does not
    decrypt anything; does not touch ``lpu_context``; does not add any
    new field beyond what ``CKKSDirectAuditPacket`` declares."""
    counts = result.counts
    return CKKSDirectAuditPacket(
        C=counts.C.serialize(),
        A=counts.A.serialize(),
        P=counts.P.serialize(),
        TP=counts.TP.serialize(),
        N=counts.N.serialize(),
        FP=counts.FP.serialize(),
        model=result.model,
        test_population_n=result.test_population_n,
        resolved_test_n=result.resolved_test_n,
        unresolved_test_n=result.unresolved_test_n,
    )


@dataclass(frozen=True)
class DecryptedGroupAuditCounts:
    """FLA/EVALUATOR-ONLY plaintext form of one group's six aggregates."""

    C: float
    A: float
    P: float
    TP: float
    N: float
    FP: float

    def rounded(self) -> Dict[str, int]:
        return {stat: round(getattr(self, stat)) for stat in _STAT_NAMES}


@dataclass(frozen=True)
class DecryptedAuditPacket:
    """FLA/EVALUATOR-ONLY plaintext form of an ``EncryptedAuditPacket``."""

    male: DecryptedGroupAuditCounts
    female: DecryptedGroupAuditCounts
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int


def _decrypt_group_legacy(
    serialized: LegacySerializedGroupAuditCounts, fla_context: ts.Context
) -> DecryptedGroupAuditCounts:
    """LEGACY (Phase 5, compSim-based): each field is a size-1 ciphertext
    (one group's share of one statistic)."""

    def _one(data: bytes, label: str) -> float:
        try:
            vector = ts.ckks_vector_from(fla_context, data)
        except ValueError as exc:
            raise MalformedCiphertextError(f"aggregate {label}: failed to parse ciphertext bytes ({exc}).") from exc
        if vector.size() != 1:
            raise MalformedCiphertextError(f"aggregate {label} has {vector.size()} slot(s); expected 1.")
        return vector.decrypt()[0]

    return DecryptedGroupAuditCounts(
        C=_one(serialized.C, "C"),
        A=_one(serialized.A, "A"),
        P=_one(serialized.P, "P"),
        TP=_one(serialized.TP, "TP"),
        N=_one(serialized.N, "N"),
        FP=_one(serialized.FP, "FP"),
    )


def decrypt_audit_packet_for_diagnostics_legacy_compsim(
    packet: LegacyEncryptedAuditPacket, fla_context: ts.Context
) -> DecryptedAuditPacket:
    """LEGACY (Phase 5, compSim-based). FLA/EVALUATOR-ONLY diagnostic
    decryption. Requires the FLA's private (``sk_HE``-holding) context;
    never called from LPU-side production code.

    Reports raw decrypted floats and their rounded integer form ONLY --
    no DP/EO fairness metric is computed here (see
    ``fairlend.audit.reconstruction``).
    """
    if not context_can_decrypt(fla_context):
        raise KeyBoundaryError(
            "decrypt_audit_packet_for_diagnostics_legacy_compsim requires the "
            "FLA's private (sk_HE-holding) context; this is diagnostic/"
            "evaluator-only code, never part of the LPU production path."
        )
    return DecryptedAuditPacket(
        male=_decrypt_group_legacy(packet.male, fla_context),
        female=_decrypt_group_legacy(packet.female, fla_context),
        model=packet.model,
        test_population_n=packet.test_population_n,
        resolved_test_n=packet.resolved_test_n,
        unresolved_test_n=packet.unresolved_test_n,
    )


def _decrypt_stat_pair_ckks(data: bytes, label: str, fla_context: ts.Context) -> Tuple[float, float]:
    """PHASE 1 BASELINE (CKKS direct addition): each field is a size-2
    ciphertext (BOTH groups' share of one statistic, packed as [male,
    female])."""
    try:
        vector = ts.ckks_vector_from(fla_context, data)
    except ValueError as exc:
        raise MalformedCiphertextError(f"aggregate {label}: failed to parse ciphertext bytes ({exc}).") from exc
    if vector.size() != 2:
        raise MalformedCiphertextError(f"aggregate {label} has {vector.size()} slot(s); expected 2.")
    decrypted = vector.decrypt()
    return decrypted[0], decrypted[1]


def decrypt_audit_packet_for_diagnostics_ckks_direct(
    packet: CKKSDirectAuditPacket, fla_context: ts.Context
) -> DecryptedAuditPacket:
    """PHASE 1 BASELINE. FLA/EVALUATOR-ONLY diagnostic decryption.
    Requires the FLA's private (``sk_HE``-holding) context; never called
    from LPU-side production code.

    Each of the packet's six fields is a single 2-slot ciphertext
    covering both groups; this function splits each one into its
    male/female slot and reassembles the SAME ``DecryptedAuditPacket``/
    ``DecryptedGroupAuditCounts`` shape every other path (legacy, BFV)
    also produces, so every downstream consumer
    (``fairlend.audit.reconstruction``) works identically regardless of
    which aggregation path produced the packet.

    Reports raw decrypted floats and their rounded integer form ONLY --
    no DP/EO fairness metric is computed here (see
    ``fairlend.audit.reconstruction``).
    """
    if not context_can_decrypt(fla_context):
        raise KeyBoundaryError(
            "decrypt_audit_packet_for_diagnostics_ckks_direct requires the "
            "FLA's private (sk_HE-holding) context; this is diagnostic/"
            "evaluator-only code, never part of the LPU production path."
        )
    male_values: Dict[str, float] = {}
    female_values: Dict[str, float] = {}
    for stat in _STAT_NAMES:
        male_values[stat], female_values[stat] = _decrypt_stat_pair_ckks(getattr(packet, stat), stat, fla_context)

    return DecryptedAuditPacket(
        male=DecryptedGroupAuditCounts(**male_values),
        female=DecryptedGroupAuditCounts(**female_values),
        model=packet.model,
        test_population_n=packet.test_population_n,
        resolved_test_n=packet.resolved_test_n,
        unresolved_test_n=packet.unresolved_test_n,
    )


# ============================================================================
# PHASE 2 (ACTIVE): BFV direct-additive aggregation
# ============================================================================
#
# reviewer2_phase2_bfv_migration_report.md: the active protocol performs
# only exact integer one-hot addition and releases integer aggregate
# counts -- BFV's native domain. This section is architecturally IDENTICAL
# to the CKKS-direct baseline above (same control flow, same population
# rules, same packet shape philosophy) -- ONLY the homomorphic scheme
# differs. Every function/class name below has no CKKS/BFV suffix,
# because these ARE the canonical ``compute_encrypted_audit`` /
# ``EncryptedAuditPacket`` names as of Phase 2 -- the CKKS-direct
# baseline these superseded is preserved above under its explicit
# ``*_ckks_direct``/``CKKSDirect*`` names for the differential comparison.
#
# NO CKKS-SPECIFIC BEHAVIOUR IS PRESENT HERE: no floating-point scale, no
# rescaling, no approximation tolerance, no rounding needed to recover
# integer counts (BFV decryption returns exact integers), no ciphertext
# multiplication, no relinearisation, multiplicative depth 0 -- verified
# in tests/scientific/test_encrypted_aggregation_bfv.py exactly as the
# CKKS-direct path's own structural tests verify the analogous claims for
# CKKS.
#
# OVERFLOW GUARD (task item 14): BFV arithmetic is exact modulo
# ``plain_modulus``, with SIGNED decoding (see
# ``fairlend.core.config.BFVConfig.max_safe_count``'s docstring for the
# empirically-verified signed-decoding behaviour this guard protects
# against). Since no single aggregate statistic can exceed the number of
# records processed in one call, checking ``len(records) <=
# max_safe_count`` up front is sufficient and is enforced structurally
# below -- ``compute_encrypted_audit`` refuses (raises
# ``BFVOverflowError``) rather than silently wrapping.


def assert_population_within_bfv_safe_bound(
    population_size: int, config: BFVConfig | None = None
) -> None:
    """Validates a planned audit population BEFORE any BFV aggregation
    begins. Raises ``BFVOverflowError`` if ``population_size`` could ever
    produce an aggregate count that wraps under this codebase's chosen
    plaintext modulus's SIGNED decoding -- see ``BFVConfig.max_safe_count``.
    Exposed as a standalone function so callers (e.g. a future real-data
    evaluation script) can validate a planned run's size before issuing
    any credentials, not only inside ``compute_encrypted_audit`` itself."""
    config = config or BFVConfig()
    if population_size > config.max_safe_count:
        raise BFVOverflowError(
            f"Planned audit population ({population_size}) exceeds this BFV "
            f"parameterisation's max safe count ({config.max_safe_count} = "
            f"(plain_modulus - 1) // 2 for plain_modulus="
            f"{config.plain_modulus}). Aggregating this many records could "
            "silently wrap a statistic's true value into a different "
            "(possibly negative) decoded integer. Choose a larger "
            "plain_modulus (see BFVConfig) before processing a population "
            "this large."
        )


@dataclass(frozen=True)
class BFVAuditCounts:
    """PHASE 2 (ACTIVE). The six aggregate sufficient statistics, EACH a
    live, still-encrypted 2-slot ``ts.BFVVector`` (slot 0 = male, slot 1 =
    female) -- never decrypted here. Six ciphertexts total, structurally
    identical in shape to ``CKKSDirectAuditCounts``, just a different
    scheme."""

    C: ts.BFVVector
    A: ts.BFVVector
    P: ts.BFVVector
    TP: ts.BFVVector
    N: ts.BFVVector
    FP: ts.BFVVector


@dataclass(frozen=True)
class BFVAuditResult:
    """PHASE 2 (ACTIVE). LPU-side working result: ciphertexts still live
    under the LPU's context. Convert to a transportable
    ``BFVAuditPacket`` via ``build_encrypted_aggregate_packet`` before
    sending to the FLA."""

    counts: BFVAuditCounts
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int


def _load_verified_protected_attribute_vector_bfv(
    credential: ProtectedAttributeCredential, ip_public_key: Ed25519PublicKey, lpu_context: ts.Context
) -> ts.BFVVector:
    """BFV counterpart of
    ``fairlend.audit.similarity.load_verified_protected_attribute_vector``
    -- verify the credential's IP signature, then deserialize its
    ciphertext bytes into a live 2-slot ``ts.BFVVector``. Never
    multiplies, never decrypts. Kept local to this module (rather than
    added to ``fairlend.audit.similarity``, which is specifically about
    the compSim/similarity concept that has no BFV counterpart -- the
    active protocol never computes a similarity score at all)."""
    if bfv_crypto.context_can_decrypt(lpu_context):
        raise KeyBoundaryError(
            "compute_encrypted_audit's lpu_context must not hold the BFV "
            "secret key -- this is the LPU-side production aggregation path."
        )
    if not credential.verify(ip_public_key):
        raise CredentialVerificationError(
            "protected-attribute credential failed IP signature verification; "
            "refusing to touch its ciphertext."
        )
    try:
        vector = ts.bfv_vector_from(lpu_context, credential.ciphertext_bytes)
    except ValueError as exc:
        raise MalformedCiphertextError(
            f"borrower protected-attribute (g_i): failed to parse ciphertext bytes ({exc})."
        ) from exc
    if vector.size() != 2:
        raise MalformedCiphertextError(
            f"borrower protected-attribute (g_i) ciphertext has {vector.size()} slot(s); expected exactly 2."
        )
    return vector


def compute_encrypted_audit(
    records: Sequence[EncryptedTestRecord],
    ip_public_key: Ed25519PublicKey,
    lpu_context: ts.Context,
    model_name: str,
    *,
    bfv_config: BFVConfig | None = None,
) -> BFVAuditResult:
    """PHASE 2 (ACTIVE): direct encrypted-additive aggregation over BFV.

    Architecturally identical to
    ``compute_encrypted_audit_ckks_direct`` -- for every TEST record,
    load and verify its protected-attribute credential's own 2-slot BFV
    ciphertext ``HE.g_i``, then homomorphically ADD it (no multiplication,
    no reference vector) into every aggregate the row's PLAINTEXT
    decision/outcome make it eligible for:

        always:                       HE.C  += HE.g_i
        if y_pred == 1:                HE.A  += HE.g_i
        if resolved and Y == 1:        HE.P  += HE.g_i
        if resolved and Y == 0:        HE.N  += HE.g_i
        if resolved and Y==1, pred==1: HE.TP += HE.g_i
        if resolved and Y==0, pred==1: HE.FP += HE.g_i

    Decryption of any of the six resulting ciphertexts yields the EXACT
    integer pair ``[stat_m, stat_f]`` -- no CKKS-style approximation, no
    rounding. Multiplicative depth 0 throughout (no relinearisation, no
    rescaling -- BFV has no rescaling operation to begin with).

    Validates ``len(records)`` against
    ``BFVConfig.max_safe_count`` BEFORE issuing any homomorphic operation
    (task item 14) -- raises ``BFVOverflowError`` rather than silently
    wrapping a statistic.

    Args:
        records: One ``EncryptedTestRecord`` per TEST row for this model.
        lpu_context: The LPU's public BFV context. Must NOT hold the BFV
            secret key -- checked structurally.
        bfv_config: Only consulted for its ``max_safe_count`` overflow
            guard; defaults to ``BFVConfig()``, which MUST match the
            parameters ``lpu_context`` was actually built with (this
            function has no way to introspect a ``ts.Context``'s own
            plain_modulus -- see reviewer2_phase2_bfv_migration_report.md's
            "Confirm BFV support" section on this API limitation).

    Returns:
        A ``BFVAuditResult`` whose six ciphertexts have never been
        decrypted.
    """
    if bfv_crypto.context_can_decrypt(lpu_context):
        raise KeyBoundaryError(
            "compute_encrypted_audit's lpu_context must not hold the BFV "
            "secret key -- this is the LPU-side production aggregation path."
        )
    assert_population_within_bfv_safe_bound(len(records), bfv_config)

    accumulators: Dict[str, ts.BFVVector] = {
        stat: ts.bfv_vector(lpu_context, [0, 0]) for stat in _STAT_NAMES
    }
    resolved_test_n = 0

    for record in records:
        g_i = _load_verified_protected_attribute_vector_bfv(record.credential, ip_public_key, lpu_context)

        accumulators["C"] = accumulators["C"] + g_i
        if record.y_pred == 1:
            accumulators["A"] = accumulators["A"] + g_i
        if record.y_true is not None:
            if record.y_true == 1:
                accumulators["P"] = accumulators["P"] + g_i
                if record.y_pred == 1:
                    accumulators["TP"] = accumulators["TP"] + g_i
            elif record.y_true == 0:
                accumulators["N"] = accumulators["N"] + g_i
                if record.y_pred == 1:
                    accumulators["FP"] = accumulators["FP"] + g_i
            resolved_test_n += 1

    full_test_n = len(records)
    return BFVAuditResult(
        counts=BFVAuditCounts(**accumulators),
        model=model_name,
        test_population_n=full_test_n,
        resolved_test_n=resolved_test_n,
        unresolved_test_n=full_test_n - resolved_test_n,
    )


@dataclass(frozen=True)
class SerializedBFVAuditCounts:
    """Serialized ciphertext bytes for the six 2-slot BFV aggregate
    statistics (Phase 2, ACTIVE)."""

    C: bytes
    A: bytes
    P: bytes
    TP: bytes
    N: bytes
    FP: bytes


# CANONICAL (Phase 2) names -- plain aliases, not separate types, so
# isinstance()/dataclasses.fields() introspection behave identically
# whether code refers to ``EncryptedAuditCounts`` or ``BFVAuditCounts``.
EncryptedAuditCounts = BFVAuditCounts
EncryptedAuditResult = BFVAuditResult


@dataclass(frozen=True)
class EncryptedAuditPacket:
    """PHASE 2 (ACTIVE). The LPU -> FLA transport object -- BFV-backed.

    Contains ONLY: serialized ciphertext bytes for the six aggregate
    statistics (each a single 2-slot ciphertext covering BOTH groups),
    plus POPULATION-COUNT metadata and a model name/protocol version
    string. Structurally identical field shape to
    ``CKKSDirectAuditPacket`` -- see that class's docstring for the full
    "deliberately absent fields" privacy proof, which applies unchanged
    here (see tests/scientific/test_encrypted_aggregation_bfv.py for this
    packet's own field-enumeration test).
    """

    C: bytes
    A: bytes
    P: bytes
    TP: bytes
    N: bytes
    FP: bytes
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int
    protocol_version: str = PROTOCOL_VERSION_BFV


def build_encrypted_aggregate_packet(result: BFVAuditResult) -> EncryptedAuditPacket:
    """PHASE 2 (ACTIVE). Serialize a ``BFVAuditResult`` into the
    transportable, aggregate-only ``EncryptedAuditPacket``. Does not
    decrypt anything; does not touch ``lpu_context``; does not add any
    new field beyond what ``EncryptedAuditPacket`` declares."""
    counts = result.counts
    return EncryptedAuditPacket(
        C=counts.C.serialize(),
        A=counts.A.serialize(),
        P=counts.P.serialize(),
        TP=counts.TP.serialize(),
        N=counts.N.serialize(),
        FP=counts.FP.serialize(),
        model=result.model,
        test_population_n=result.test_population_n,
        resolved_test_n=result.resolved_test_n,
        unresolved_test_n=result.unresolved_test_n,
    )


def _decrypt_stat_pair_bfv(data: bytes, label: str, fla_context: ts.Context) -> Tuple[int, int]:
    """PHASE 2 (ACTIVE): each field is a size-2 BFV ciphertext (BOTH
    groups' share of one statistic, packed as [male, female]).
    Decryption is EXACT -- both returned values are already integers,
    verified below rather than assumed (a non-integer result here would
    indicate a bug, since BFV has no approximation to produce one)."""
    try:
        vector = ts.bfv_vector_from(fla_context, data)
    except ValueError as exc:
        raise MalformedCiphertextError(f"aggregate {label}: failed to parse ciphertext bytes ({exc}).") from exc
    if vector.size() != 2:
        raise MalformedCiphertextError(f"aggregate {label} has {vector.size()} slot(s); expected 2.")
    decrypted = vector.decrypt()
    male_value, female_value = int(decrypted[0]), int(decrypted[1])
    if male_value != decrypted[0] or female_value != decrypted[1]:
        raise MalformedCiphertextError(
            f"aggregate {label}: BFV decryption returned a non-integer value "
            f"({decrypted!r}) -- this must never happen and indicates a bug, "
            "not an approximation to tolerate."
        )
    return male_value, female_value


def decrypt_audit_packet_for_diagnostics(packet: EncryptedAuditPacket, fla_context: ts.Context) -> DecryptedAuditPacket:
    """PHASE 2 (ACTIVE). FLA/EVALUATOR-ONLY diagnostic decryption.
    Requires the FLA's private (BFV-secret-key-holding) context; never
    called from LPU-side production code (``compute_encrypted_audit``/
    ``build_encrypted_aggregate_packet`` above never call this).

    Each of the packet's six fields is a single 2-slot BFV ciphertext
    covering both groups; this function splits each one into its
    male/female slot and reassembles the SAME ``DecryptedAuditPacket``/
    ``DecryptedGroupAuditCounts`` shape every other path (legacy,
    CKKS-direct) also produces, so every downstream consumer
    (``fairlend.audit.reconstruction``) works identically regardless of
    which aggregation path produced the packet. Unlike the CKKS paths,
    the values placed into ``DecryptedGroupAuditCounts`` (a ``float``-
    typed dataclass, kept for interop) are already EXACT integers --
    ``.rounded()`` is a no-op here, not a correction.
    """
    if not bfv_crypto.context_can_decrypt(fla_context):
        raise KeyBoundaryError(
            "decrypt_audit_packet_for_diagnostics requires the FLA's private "
            "(BFV-secret-key-holding) context; this is diagnostic/evaluator-"
            "only code, never part of the LPU production path."
        )
    male_values: Dict[str, float] = {}
    female_values: Dict[str, float] = {}
    for stat in _STAT_NAMES:
        male_int, female_int = _decrypt_stat_pair_bfv(getattr(packet, stat), stat, fla_context)
        male_values[stat] = float(male_int)
        female_values[stat] = float(female_int)

    return DecryptedAuditPacket(
        male=DecryptedGroupAuditCounts(**male_values),
        female=DecryptedGroupAuditCounts(**female_values),
        model=packet.model,
        test_population_n=packet.test_population_n,
        resolved_test_n=packet.resolved_test_n,
        unresolved_test_n=packet.unresolved_test_n,
    )
