"""Diagnostic protected-attribute matching fidelity (Phase 7): the
manuscript's argmax/delta* group-prediction diagnostic built on top of
compSim.

DIAGNOSTIC ONLY. Every function here runs AFTER FLA/evaluator diagnostic
decryption (``fairlend.audit.similarity.decrypt_similarity_pair_for_
diagnostics``) and is never called from, or reachable by, the LPU
production path (``fairlend.audit.similarity.comp_sim``,
``fairlend.audit.aggregation.compute_encrypted_audit``/
``build_encrypted_aggregate_packet``). Production
``EncryptedSimilarityPair``/``EncryptedAuditPacket`` objects remain fully
encrypted regardless of anything in this module; nothing here changes
compSim's semantics, CKKS parameters, or encrypted aggregation.

The "expected group" used throughout this module and its result
artifacts is the SYNTHETIC protected-attribute label used only for
controlled audit evaluation (manuscript Sec. 6.1.1) -- it must never be
described as observed gender.

DELTA* SELECTION -- an implementation choice, not a manuscript-prescribed
algorithm (see docs/MANUSCRIPT_EVIDENCE_STATUS.md): ``select_delta_star``
picks the LARGEST candidate in ``DELTA_STAR_GRID`` that achieves the
MAXIMUM matching accuracy on the VALIDATION pairs it is given. Preferring
the largest such threshold is deliberately conservative -- it maximises
the "unmatched" rejection zone for borderline/low-confidence score pairs
without sacrificing any validation accuracy. TEST pairs are never passed
to, or inspectable by, this function -- see
``tests/scientific/test_matching_fidelity.py`` for the structural
validation/TEST-boundary proof.

MATCHING RULE (manuscript's paired interpretation, Sec. 4.6):

    predicted_group = argmax(male_score, female_score)
    unmatched        = max(male_score, female_score) < delta*

A record is judged unmatched ONLY when BOTH scores are below delta* --
never merely because the non-matching score is close to zero; the two
scores are interpreted jointly, not thresholded independently.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import tenseal as ts
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sklearn.metrics import accuracy_score, f1_score

from fairlend.audit.aggregation import GROUP_FEMALE, GROUP_MALE
from fairlend.audit.similarity import (
    LoadedReferenceVectors,
    comp_sim,
    decrypt_similarity_pair_for_diagnostics,
)
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential

UNMATCHED_LABEL = "unmatched"

# Candidate delta* thresholds -- same granularity as
# fairlend.models.credit_models.THRESHOLD_GRID (19 values, 0.05..0.95),
# for consistency with this codebase's existing threshold-selection style.
# Not 0.0 or 1.0: CKKS noise means an "expected-1" score is virtually never
# EXACTLY 1.0 (see Phase 4's measured error), so delta*=1.0 would spuriously
# mark every well-matched record unmatched.
DELTA_STAR_GRID: Tuple[float, ...] = tuple(round(0.05 + 0.05 * i, 2) for i in range(19))


@dataclass(frozen=True)
class MatchingInputRecord:
    """One record to diagnostically match: an ALREADY-ISSUED credential
    plus its SYNTHETIC protected-attribute expected label -- the
    evaluation harness knows this label because it generated the
    controlled experiment (see ``fairlend.roles.identity_provider.
    IdentityProvider.issue_credential``'s docstring for the identical
    boundary). ``identifier`` is diagnostic-only (e.g. a row index),
    never a production field."""

    identifier: str
    credential: ProtectedAttributeCredential
    expected_group: str


@dataclass(frozen=True)
class PairedSimilarityScore:
    """One record's DECRYPTED paired similarity scores plus its expected
    label. Produced ONLY by ``compute_paired_scores`` (FLA/evaluator
    diagnostic decryption), never inside the LPU production path."""

    identifier: str
    male_score: float
    female_score: float
    expected_group: str


@dataclass(frozen=True)
class MatchingPrediction:
    """The diagnostic argmax/delta* classification of one paired score."""

    identifier: str
    male_score: float
    female_score: float
    expected_group: str
    predicted_group: Optional[str]  # None iff unmatched
    unmatched: bool

    @property
    def correct(self) -> bool:
        return (not self.unmatched) and self.predicted_group == self.expected_group

    @property
    def predicted_label(self) -> str:
        """``predicted_group``, or the sentinel ``UNMATCHED_LABEL`` --
        for feeding directly into sklearn metric functions alongside
        ``expected_group`` without a separate None-handling branch at
        every call site."""
        return self.predicted_group if self.predicted_group is not None else UNMATCHED_LABEL


@dataclass(frozen=True)
class MatchingMetrics:
    n: int
    correct: int
    accuracy: float
    macro_f1: float
    unmatched_count: int
    unmatched_rate: float


@dataclass(frozen=True)
class ScoreDistributionStats:
    """Numerical-error statistics for one expected-value group (task
    Sec. 7). ``mean``/``std``/``min``/``max`` describe the RAW decrypted
    scores themselves (never rounded); ``mae``/``max_abs_error`` describe
    ``abs(score - expected_value)``."""

    n: int
    expected_value: float
    mean: float
    std: float
    min: float
    max: float
    mae: float
    max_abs_error: float


@dataclass(frozen=True)
class MatchingFidelityResult:
    """One complete diagnostic run: delta* selected from VALIDATION,
    then applied, frozen, to TEST."""

    delta_star: float
    validation_n: int
    validation_accuracy_at_delta_star: float
    test_n: int
    test_metrics: MatchingMetrics
    expected_one_stats: ScoreDistributionStats
    expected_zero_stats: ScoreDistributionStats
    combined_mae: float
    combined_max_abs_error: float


def compute_paired_scores(
    records: Sequence[MatchingInputRecord],
    ip_public_key: Ed25519PublicKey,
    references: LoadedReferenceVectors,
    lpu_context: ts.Context,
    fla_context: ts.Context,
) -> List[PairedSimilarityScore]:
    """The REAL path (task Sec. 8): IP-issued credential -> LPU-verified
    compSim -> FLA/evaluator diagnostic decryption. Reuses
    ``fairlend.audit.similarity.comp_sim`` and
    ``decrypt_similarity_pair_for_diagnostics`` UNCHANGED -- this function
    performs no cryptography, shape checking, or credential verification
    of its own; a malformed/tampered/wrong-key credential fails inside
    ``comp_sim`` exactly as it does in production (see Phase 4's tests),
    propagating out of this function unchanged.
    """
    paired: List[PairedSimilarityScore] = []
    for record in records:
        pair = comp_sim(record.credential, ip_public_key, references, lpu_context)
        decrypted = decrypt_similarity_pair_for_diagnostics(pair.serialize(), fla_context)
        paired.append(
            PairedSimilarityScore(
                identifier=record.identifier,
                male_score=decrypted.male_score,
                female_score=decrypted.female_score,
                expected_group=record.expected_group,
            )
        )
    return paired


def classify_paired_score(pair: PairedSimilarityScore, delta_star: float) -> MatchingPrediction:
    """argmax + delta* classification (manuscript's paired rule -- see
    module docstring). Never inspects ``pair.expected_group`` to decide
    ``predicted_group``/``unmatched`` -- only the two scores."""
    max_score = max(pair.male_score, pair.female_score)
    if max_score < delta_star:
        predicted_group: Optional[str] = None
        unmatched = True
    else:
        # Ties (male_score == female_score) are vanishingly unlikely with
        # CKKS noise; broken deterministically toward male, matching this
        # module's GROUP_MALE-first field ordering throughout.
        predicted_group = GROUP_MALE if pair.male_score >= pair.female_score else GROUP_FEMALE
        unmatched = False
    return MatchingPrediction(
        identifier=pair.identifier,
        male_score=pair.male_score,
        female_score=pair.female_score,
        expected_group=pair.expected_group,
        predicted_group=predicted_group,
        unmatched=unmatched,
    )


def compute_matching_metrics(predictions: Sequence[MatchingPrediction]) -> MatchingMetrics:
    """Accuracy/macro-F1 treat an unmatched prediction as simply "not the
    correct class" (it can never satisfy ``correct``) -- sklearn's
    ``UNMATCHED_LABEL`` sentinel is never one of the two real classes, so
    it contributes a false negative to the record's true class and never
    a true/false positive to either class, matching this rejection-option
    semantics exactly."""
    if not predictions:
        raise ValueError("compute_matching_metrics called with zero predictions.")
    y_true = [p.expected_group for p in predictions]
    y_pred = [p.predicted_label for p in predictions]
    unmatched_count = sum(1 for p in predictions if p.unmatched)
    n = len(predictions)
    return MatchingMetrics(
        n=n,
        correct=sum(1 for p in predictions if p.correct),
        accuracy=float(accuracy_score(y_true, y_pred)),
        macro_f1=float(f1_score(y_true, y_pred, labels=[GROUP_MALE, GROUP_FEMALE], average="macro", zero_division=0)),
        unmatched_count=unmatched_count,
        unmatched_rate=unmatched_count / n,
    )


def select_delta_star(
    validation_pairs: Sequence[PairedSimilarityScore], grid: Sequence[float] = DELTA_STAR_GRID
) -> Tuple[float, MatchingMetrics]:
    """VALIDATION ONLY (task Sec. 3/4): picks the LARGEST ``grid`` value
    achieving the maximum matching accuracy on ``validation_pairs``. Never
    accepts, or has any parameter shaped like, TEST data -- see this
    module's docstring and
    ``tests/scientific/test_matching_fidelity.py::
    test_selection_functions_have_no_test_data_parameter``.
    """
    if not validation_pairs:
        raise ValueError("select_delta_star called with zero validation pairs.")
    best_delta = grid[0]
    best_metrics: Optional[MatchingMetrics] = None
    best_accuracy = -1.0
    for delta in grid:
        predictions = [classify_paired_score(pair, delta) for pair in validation_pairs]
        metrics = compute_matching_metrics(predictions)
        if metrics.accuracy >= best_accuracy:
            best_accuracy = metrics.accuracy
            best_delta = delta
            best_metrics = metrics
    assert best_metrics is not None
    return best_delta, best_metrics


def compute_score_distribution_stats(scores: Sequence[float], expected_value: float) -> ScoreDistributionStats:
    """Task Sec. 7: raw (never rounded) score distribution plus
    ``error_i = score_i - expected_value`` statistics, for
    ``expected_value`` in {0.0, 1.0}."""
    if not scores:
        raise ValueError("compute_score_distribution_stats called with zero scores.")
    errors = [s - expected_value for s in scores]
    abs_errors = [abs(e) for e in errors]
    return ScoreDistributionStats(
        n=len(scores),
        expected_value=expected_value,
        mean=statistics.fmean(scores),
        std=statistics.pstdev(scores),
        min=min(scores),
        max=max(scores),
        mae=statistics.fmean(abs_errors),
        max_abs_error=max(abs_errors),
    )


def _own_and_other_scores(pairs: Sequence[PairedSimilarityScore]) -> Tuple[List[float], List[float]]:
    """Splits each pair into its "expected-1" score (the slot matching
    the record's own expected group) and "expected-0" score (the other
    slot) -- e.g. for an expected-male record, male_score is expected-1
    and female_score is expected-0."""
    expected_one: List[float] = []
    expected_zero: List[float] = []
    for pair in pairs:
        if pair.expected_group == GROUP_MALE:
            expected_one.append(pair.male_score)
            expected_zero.append(pair.female_score)
        else:
            expected_one.append(pair.female_score)
            expected_zero.append(pair.male_score)
    return expected_one, expected_zero


def run_matching_fidelity_diagnostic(
    validation_records: Sequence[MatchingInputRecord],
    test_records: Sequence[MatchingInputRecord],
    ip_public_key: Ed25519PublicKey,
    references: LoadedReferenceVectors,
    lpu_context: ts.Context,
    fla_context: ts.Context,
) -> MatchingFidelityResult:
    """The full Phase 7 diagnostic for one cryptographic realisation:
    VALIDATION -> delta* (frozen) -> TEST -> matching fidelity metrics +
    numerical-error statistics. TEST pairs are computed AFTER, and never
    influence, delta* selection -- the two computations do not share any
    mutable state, so this is a structural guarantee, not merely an
    ordering convention.
    """
    validation_pairs = compute_paired_scores(validation_records, ip_public_key, references, lpu_context, fla_context)
    delta_star, validation_metrics = select_delta_star(validation_pairs)

    test_pairs = compute_paired_scores(test_records, ip_public_key, references, lpu_context, fla_context)
    test_predictions = [classify_paired_score(pair, delta_star) for pair in test_pairs]
    test_metrics = compute_matching_metrics(test_predictions)

    expected_one_scores, expected_zero_scores = _own_and_other_scores(test_pairs)
    expected_one_stats = compute_score_distribution_stats(expected_one_scores, 1.0)
    expected_zero_stats = compute_score_distribution_stats(expected_zero_scores, 0.0)

    combined_abs_errors = [abs(s - 1.0) for s in expected_one_scores] + [abs(s - 0.0) for s in expected_zero_scores]

    return MatchingFidelityResult(
        delta_star=delta_star,
        validation_n=len(validation_records),
        validation_accuracy_at_delta_star=validation_metrics.accuracy,
        test_n=len(test_records),
        test_metrics=test_metrics,
        expected_one_stats=expected_one_stats,
        expected_zero_stats=expected_zero_stats,
        combined_mae=statistics.fmean(combined_abs_errors),
        combined_max_abs_error=max(combined_abs_errors),
    )
