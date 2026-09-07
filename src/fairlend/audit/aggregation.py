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

ENCRYPTED PATH (Phase 5; manuscript Algorithm 5's actual encrypted
aggregation, as opposed to the plaintext analogue above). This is a
SEPARATE set of types/functions appended below -- nothing above this
point is modified by it, and the plaintext API's behaviour/tests are
unaffected.

Same population rules as above (C_k always, A_k iff approved, P/N/TP/FP
only over resolved outcomes), but every group-membership contribution is
an ENCRYPTED similarity score (``fairlend.audit.similarity.comp_sim``'s
output) rather than a plaintext boolean-driven count -- the LPU never
learns which group a row is in; it homomorphically adds the SAME
similarity-weighted ciphertext to a row's contribution for EVERY group,
and only decryption (FLA-only, diagnostic in this phase) reveals the
resulting per-group tallies.

Per-record group-membership ciphertexts are obtained EXCLUSIVELY via
``fairlend.audit.similarity.comp_sim`` on a real, IP-issued, LPU-verified
``ProtectedAttributeCredential`` (see ``EncryptedTestRecord`` below) --
this module never accepts, and never internally constructs, a ciphertext
from a plaintext gender label. Producing that credential in the first
place (i.e. deciding which label to ask the IP to encrypt for a given
TEST row) is the EVALUATION HARNESS's job
(``evaluation/run_encrypted_audit.py``), exactly as
``fairlend.roles.identity_provider.IdentityProvider.issue_credential``'s
own docstring describes -- the harness may know a row's synthetic label
(it generated the controlled experiment), but nothing in this module ever
does.

Conditional accumulation uses plain Python ``if`` statements on PLAINTEXT
``y_pred``/``y_true`` (the LPU's own legitimate operational data -- a
loan decision and a repayment outcome are not secret; only the protected
attribute is) to decide WHETHER to homomorphically add a given row's
similarity ciphertext into a given aggregate -- never an extra
ciphertext-plaintext multiplication by a 0/1 indicator, since a plain
Python conditional skip achieves the identical result with strictly less
homomorphic work and no additional multiplicative depth.

ENCRYPTED-ZERO INITIALISATION (verified empirically, not assumed):
TenSEAL's ``auto_mod_switch=True`` (default on every context this
codebase creates) automatically reconciles the level mismatch between a
FRESH, top-level zero ciphertext (``ts.ckks_vector(context, [0.0])``) and
a post-``comp_sim`` ciphertext (which has gone through one
multiplication + automatic rescale, and is therefore one level lower).
This was verified directly: adding a fresh zero to a compSim output, and
accumulating 38 sequential compSim outputs into a fresh-zero-initialised
accumulator, both produced numerically correct results (absolute error
~2-3e-6, consistent with Phase 4's measured compSim noise) with no
error and no manual level/rescale handling. Aggregates in this module are
therefore initialised as fresh top-level zero ciphertexts -- NOT
by copying the first contributing ciphertext (an alternative this
module's design note originally considered) and NOT by decrypting/
re-encrypting to "fix" a level mismatch, since no such fix is needed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Optional, Sequence, Tuple

import tenseal as ts
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fairlend.audit.similarity import LoadedReferenceVectors, comp_sim
from fairlend.core.exceptions import KeyBoundaryError, MalformedCiphertextError
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential
from fairlend.crypto.ckks import context_can_decrypt

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
class EncryptedGroupAuditCounts:
    """One group's encrypted sufficient statistics. All six fields are
    live ``ts.CKKSVector`` ciphertexts (size 1) -- never decrypted here."""

    C: ts.CKKSVector
    A: ts.CKKSVector
    P: ts.CKKSVector
    TP: ts.CKKSVector
    N: ts.CKKSVector
    FP: ts.CKKSVector


@dataclass(frozen=True)
class EncryptedAuditResult:
    """LPU-side working result: ciphertexts still live under the LPU's
    context. Convert to a transportable ``EncryptedAuditPacket`` via
    ``build_encrypted_aggregate_packet`` before sending to the FLA."""

    male: EncryptedGroupAuditCounts
    female: EncryptedGroupAuditCounts
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int


def compute_encrypted_audit(
    records: Sequence[EncryptedTestRecord],
    ip_public_key: Ed25519PublicKey,
    references: LoadedReferenceVectors,
    lpu_context: ts.Context,
    model_name: str,
) -> EncryptedAuditResult:
    """Manuscript Algorithm 5's encrypted aggregation: for every TEST
    record, compute its encrypted group-membership similarity
    (``comp_sim``, which itself verifies the IP's signature before
    computing anything -- an invalid/tampered/substituted credential
    aborts this whole call), then homomorphically add that similarity into
    every aggregate the row's PLAINTEXT decision/outcome make it eligible
    for:

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

    Args:
        records: One ``EncryptedTestRecord`` per TEST row for this model,
            covering the TEST population exactly (validated by the
            caller -- see ``evaluation/run_encrypted_audit.py`` -- before
            this function ever runs).
        lpu_context: The LPU's public CKKS context. Must NOT hold
            ``sk_HE`` -- checked structurally, same invariant as
            ``fairlend.audit.similarity.comp_sim``.

    Returns:
        An ``EncryptedAuditResult`` whose six-times-two ciphertexts have
        never been decrypted.
    """
    if context_can_decrypt(lpu_context):
        raise KeyBoundaryError(
            "compute_encrypted_audit's lpu_context must not hold sk_HE -- "
            "this is the LPU-side production aggregation path."
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
    return EncryptedAuditResult(
        male=EncryptedGroupAuditCounts(**accumulators[GROUP_MALE]),
        female=EncryptedGroupAuditCounts(**accumulators[GROUP_FEMALE]),
        model=model_name,
        test_population_n=full_test_n,
        resolved_test_n=resolved_test_n,
        unresolved_test_n=full_test_n - resolved_test_n,
    )


@dataclass(frozen=True)
class SerializedGroupAuditCounts:
    """Serialized ciphertext bytes for one group's six aggregates."""

    C: bytes
    A: bytes
    P: bytes
    TP: bytes
    N: bytes
    FP: bytes


PROTOCOL_VERSION = "fairlend/encrypted-audit/v1"


@dataclass(frozen=True)
class EncryptedAuditPacket:
    """The LPU -> FLA transport object.

    Contains ONLY: serialized ciphertext bytes for the six aggregate
    statistics, per group, plus POPULATION-COUNT metadata (how many TEST
    rows total/resolved/unresolved contributed -- an aggregate count, not
    per-record data) and a model name/protocol version string.

    Deliberately absent (see tests/scientific/test_encrypted_aggregation_
    privacy.py for the exhaustive field-enumeration proof): uid, id,
    row_index, plaintext gender, synthetic gender label,
    probability_female, account data, credit score, or any per-borrower
    y_true/y_pred/similarity value. Nothing in this dataclass's fields, at
    any nesting depth, is per-record.
    """

    male: SerializedGroupAuditCounts
    female: SerializedGroupAuditCounts
    model: str
    test_population_n: int
    resolved_test_n: int
    unresolved_test_n: int
    protocol_version: str = PROTOCOL_VERSION


def _serialize_group(counts: EncryptedGroupAuditCounts) -> SerializedGroupAuditCounts:
    return SerializedGroupAuditCounts(
        C=counts.C.serialize(),
        A=counts.A.serialize(),
        P=counts.P.serialize(),
        TP=counts.TP.serialize(),
        N=counts.N.serialize(),
        FP=counts.FP.serialize(),
    )


def build_encrypted_aggregate_packet(result: EncryptedAuditResult) -> EncryptedAuditPacket:
    """Serialize an ``EncryptedAuditResult`` into the transportable,
    aggregate-only ``EncryptedAuditPacket``. Does not decrypt anything;
    does not touch ``lpu_context``; does not add any new field beyond
    what ``EncryptedAuditPacket`` declares."""
    return EncryptedAuditPacket(
        male=_serialize_group(result.male),
        female=_serialize_group(result.female),
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


def _decrypt_group(serialized: SerializedGroupAuditCounts, fla_context: ts.Context) -> DecryptedGroupAuditCounts:
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


def decrypt_audit_packet_for_diagnostics(packet: EncryptedAuditPacket, fla_context: ts.Context) -> DecryptedAuditPacket:
    """FLA/EVALUATOR-ONLY diagnostic decryption. Requires the FLA's
    private (``sk_HE``-holding) context; never called from LPU-side
    production code (``compute_encrypted_audit``/
    ``build_encrypted_aggregate_packet`` above never call this).

    Phase 5 scope: reports raw decrypted floats and their rounded integer
    form ONLY -- no DP/EO fairness metric is computed here (that is a
    later, separate phase; see docs/MANUSCRIPT_EVIDENCE_STATUS.md).
    """
    if not context_can_decrypt(fla_context):
        raise KeyBoundaryError(
            "decrypt_audit_packet_for_diagnostics requires the FLA's private "
            "(sk_HE-holding) context; this is diagnostic/evaluator-only code, "
            "never part of the LPU production path."
        )
    return DecryptedAuditPacket(
        male=_decrypt_group(packet.male, fla_context),
        female=_decrypt_group(packet.female, fla_context),
        model=packet.model,
        test_population_n=packet.test_population_n,
        resolved_test_n=packet.resolved_test_n,
        unresolved_test_n=packet.unresolved_test_n,
    )
