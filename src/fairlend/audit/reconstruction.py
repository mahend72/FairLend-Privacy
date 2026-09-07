"""Plaintext-vs-encrypted fairness reconstruction (Phase 6).

Compares the Phase 2 plaintext audit (the oracle -- already computed via
``fairlend.audit.fairness`` on borrower-level plaintext data,
``results/fixture_validation/evaluation/plaintext_audit.csv``) against the
Phase 5 encrypted aggregate audit (an ``EncryptedAuditPacket``, decrypted
and rounded by the FLA) -- using the SAME ``fairlend.audit.fairness``
formulas for both sides, never a second/duplicated formula. This module
does not implement DP/EO itself; it only builds aggregate-only inputs for
``fairlend.audit.fairness.compute_demographic_parity``/
``compute_equalised_odds`` and diffs the two results.

AGGREGATE-ONLY: every function here operates on already-aggregated
``GroupAuditCounts``/``PlaintextAuditResult``-shaped objects (built either
from a ``plaintext_audit.csv`` row's aggregate columns, or from a Phase 5
``DecryptedAuditPacket``) -- never a borrower-level DataFrame, a uid, a
row_index, a synthetic_gender_label, an account/score value, or a
per-record y_pred/y_true/similarity score. See
``tests/unit/test_reconstruction.py::
test_reconstruction_functions_take_no_borrower_level_parameter`` for the
structural proof (function-signature inspection: no parameter here is
ever a DataFrame or a per-record sequence).

ROUNDING RULE (manuscript audit construction; matches Phase 5's own
design): the production reconstruction path
(``encrypted_result_from_rounded_packet``) uses the FLA's ROUNDED
aggregate counts -- DP_encrypted/EO_encrypted are never computed directly
from unrounded floating-point CKKS values. A SEPARATE, clearly-labelled
raw-CKKS diagnostic (``encrypted_result_from_raw_packet``,
``FairnessReconstructionResult.dp_raw_ckks``/``eo_raw_ckks``) is also
provided to quantify CKKS approximation error, and is never used as, or
confused with, the production result.

RAW-CKKS CLIPPING (read before touching this file): raw, unrounded CKKS
aggregate values can violate ``GroupAuditCounts``'s exact-count structural
invariants (``A<=C``, ``TP<=P``, ``FP<=N``) by a tiny epsilon, even when
the true underlying counts satisfy them exactly -- observed directly on
this fixture (e.g. random forest's raw decrypted ``A_m`` was measured to
exceed raw decrypted ``C_m`` by ~4e-9, from independent per-ciphertext
CKKS noise accumulated along different summation paths). The raw-CKKS
diagnostic therefore clips each value to its exact-invariant partner
(``min(A, C)``, ``min(TP, P)``, ``min(FP, N)``) ONLY as input to
``GroupAuditCounts`` so the reused fairness formula never divides using a
value that violates its own precondition -- the UNCLIPPED raw values are
still reported in full precision elsewhere
(``AggregateReconstructionResult.raw_decrypted``) for numerical-error
transparency; clipping never touches the production rounded-count path.

Preserves Phase 2's ``minimum_cell_size`` semantics exactly (via
``fairlend.audit.fairness.dp_release_status``/``eo_release_status``,
unchanged, reused as-is): ``None`` is reported as
``"minimum_cell_size_not_configured"``, never silently treated as zero or
as "released".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping, Optional

from fairlend.audit.aggregation import (
    GROUP_FEMALE,
    GROUP_MALE,
    DecryptedAuditPacket,
    DecryptedGroupAuditCounts,
    GroupAuditCounts,
    PlaintextAuditResult,
)
from fairlend.audit.fairness import (
    RateResult,
    compute_demographic_parity,
    compute_equalised_odds,
    dp_release_status,
    eo_release_status,
)

STAT_NAMES = ("C", "A", "P", "TP", "N", "FP")
GROUP_SUFFIX: Dict[str, str] = {GROUP_MALE: "m", GROUP_FEMALE: "f"}


@dataclass(frozen=True)
class AggregateReconstructionResult:
    """Per-statistic plaintext-vs-encrypted comparison for one model,
    covering all 12 aggregates (6 statistics x 2 groups). Keys are
    ``"{stat}_{m|f}"``, e.g. ``"C_m"``, ``"TP_f"``."""

    model: str
    plaintext: Dict[str, int]
    raw_decrypted: Dict[str, float]
    rounded: Dict[str, int]
    absolute_error: Dict[str, float]

    @property
    def max_absolute_error(self) -> float:
        return max(self.absolute_error.values())

    @property
    def mean_absolute_error(self) -> float:
        return sum(self.absolute_error.values()) / len(self.absolute_error)

    @property
    def all_rounded_match_plaintext(self) -> bool:
        return all(self.rounded[key] == self.plaintext[key] for key in self.plaintext)


@dataclass(frozen=True)
class FairnessReconstructionResult:
    """Plaintext-vs-encrypted(rounded) DP/EO comparison for one model,
    plus an optional raw-CKKS diagnostic. All rate/gap fields are
    ``fairlend.audit.fairness.RateResult`` -- never a bare float that
    could silently stand in for "unavailable"."""

    model: str
    minimum_cell_size: Optional[int]

    dp_plain: RateResult
    dp_encrypted: RateResult
    dp_reconstruction_error: Optional[float]

    eo_plain: RateResult
    eo_encrypted: RateResult
    eo_reconstruction_error: Optional[float]

    approval_rate_m_plain: RateResult
    approval_rate_f_plain: RateResult
    approval_rate_m_encrypted: RateResult
    approval_rate_f_encrypted: RateResult

    tpr_m_plain: RateResult
    tpr_f_plain: RateResult
    tpr_m_encrypted: RateResult
    tpr_f_encrypted: RateResult

    fpr_m_plain: RateResult
    fpr_f_plain: RateResult
    fpr_m_encrypted: RateResult
    fpr_f_encrypted: RateResult

    dp_release_status_plain: str
    dp_release_status_encrypted: str
    eo_release_status_plain: str
    eo_release_status_encrypted: str

    # Diagnostic ONLY -- never the production DP_encrypted/EO_encrypted.
    dp_raw_ckks: Optional[RateResult] = None
    eo_raw_ckks: Optional[RateResult] = None
    dp_raw_ckks_error: Optional[float] = None
    eo_raw_ckks_error: Optional[float] = None


def _group_counts_from_int_mapping(values: Mapping[str, object], group: str) -> GroupAuditCounts:
    suffix = GROUP_SUFFIX[group]
    return GroupAuditCounts(
        group=group, **{stat: int(values[f"{stat}_{suffix}"]) for stat in STAT_NAMES}
    )


def plaintext_result_from_oracle_row(row: Mapping[str, object], model_name: str) -> PlaintextAuditResult:
    """Rebuild a ``PlaintextAuditResult`` purely from a
    ``plaintext_audit.csv`` row's aggregate columns (``C_m``, ``A_m``,
    ..., ``test_population_n``, ``resolved_test_n``,
    ``unresolved_test_n``) -- no borrower-level data is read or required.
    """
    male = _group_counts_from_int_mapping(row, GROUP_MALE)
    female = _group_counts_from_int_mapping(row, GROUP_FEMALE)
    result = PlaintextAuditResult(
        model_name=model_name,
        groups={GROUP_MALE: male, GROUP_FEMALE: female},
        full_test_n=int(row["test_population_n"]),
        resolved_test_n=int(row["resolved_test_n"]),
        unresolved_test_n=int(row["unresolved_test_n"]),
    )
    result.assert_consistent()
    return result


def encrypted_result_from_rounded_packet(decrypted: DecryptedAuditPacket) -> PlaintextAuditResult:
    """PRODUCTION reconstruction: builds a ``PlaintextAuditResult`` from a
    Phase 5 ``DecryptedAuditPacket``'s ROUNDED aggregate counts (see
    ``DecryptedGroupAuditCounts.rounded()``) -- reuses
    ``fairlend.audit.fairness``'s formulas unchanged."""

    def _group(counts: DecryptedGroupAuditCounts, group: str) -> GroupAuditCounts:
        return GroupAuditCounts(group=group, **counts.rounded())

    male = _group(decrypted.male, GROUP_MALE)
    female = _group(decrypted.female, GROUP_FEMALE)
    result = PlaintextAuditResult(
        model_name=decrypted.model,
        groups={GROUP_MALE: male, GROUP_FEMALE: female},
        full_test_n=decrypted.test_population_n,
        resolved_test_n=decrypted.resolved_test_n,
        unresolved_test_n=decrypted.unresolved_test_n,
    )
    result.assert_consistent()
    return result


def _clip_group_counts_from_raw(counts: DecryptedGroupAuditCounts, group: str) -> GroupAuditCounts:
    """DIAGNOSTIC ONLY -- see module docstring's "RAW-CKKS CLIPPING" note."""
    C, P, N = counts.C, counts.P, counts.N
    A = min(counts.A, C)
    TP = min(counts.TP, P)
    FP = min(counts.FP, N)
    return GroupAuditCounts(group=group, C=C, A=A, P=P, TP=TP, N=N, FP=FP)


def encrypted_result_from_raw_packet(decrypted: DecryptedAuditPacket) -> PlaintextAuditResult:
    """DIAGNOSTIC ONLY -- see module docstring's rounding-rule note.
    Builds a ``PlaintextAuditResult`` from RAW, unrounded decrypted CKKS
    values (clipped only enough to satisfy ``GroupAuditCounts``'s
    structural invariants; see ``_clip_group_counts_from_raw``). Deliberately
    does NOT call ``assert_consistent()`` -- summing raw floats (e.g.
    ``C_m + C_f``) will not exactly equal the integer ``full_test_n`` due
    to CKKS noise, which is the numerical error this diagnostic exists to
    quantify, not an error to suppress.
    """
    male = _clip_group_counts_from_raw(decrypted.male, GROUP_MALE)
    female = _clip_group_counts_from_raw(decrypted.female, GROUP_FEMALE)
    return PlaintextAuditResult(
        model_name=decrypted.model,
        groups={GROUP_MALE: male, GROUP_FEMALE: female},
        full_test_n=decrypted.test_population_n,
        resolved_test_n=decrypted.resolved_test_n,
        unresolved_test_n=decrypted.unresolved_test_n,
    )


def compute_aggregate_reconstruction(
    plaintext_row: Mapping[str, object], decrypted: DecryptedAuditPacket, model_name: str
) -> AggregateReconstructionResult:
    """Task Sec. 8/13: plaintext count, raw decrypted value, rounded
    value, and absolute error for all 12 aggregates."""
    plaintext: Dict[str, int] = {}
    raw_decrypted: Dict[str, float] = {}
    rounded: Dict[str, int] = {}
    absolute_error: Dict[str, float] = {}

    for group, decrypted_group in ((GROUP_MALE, decrypted.male), (GROUP_FEMALE, decrypted.female)):
        suffix = GROUP_SUFFIX[group]
        for stat in STAT_NAMES:
            key = f"{stat}_{suffix}"
            expected = int(plaintext_row[key])
            raw_value = float(getattr(decrypted_group, stat))
            rounded_value = round(raw_value)
            plaintext[key] = expected
            raw_decrypted[key] = raw_value
            rounded[key] = rounded_value
            absolute_error[key] = abs(raw_value - expected)

    return AggregateReconstructionResult(
        model=model_name,
        plaintext=plaintext,
        raw_decrypted=raw_decrypted,
        rounded=rounded,
        absolute_error=absolute_error,
    )


def compute_fairness_reconstruction(
    plaintext_row: Mapping[str, object],
    decrypted: DecryptedAuditPacket,
    model_name: str,
    minimum_cell_size: Optional[int],
    include_raw_ckks_diagnostic: bool = True,
) -> FairnessReconstructionResult:
    """Task Sec. 6/7/8: DP/EO from plaintext vs. rounded-encrypted
    aggregates (same ``fairlend.audit.fairness`` formula for both), the
    reconstruction errors ``e_DP``/``e_EO``, matching release-suppression
    status, and (optionally) the raw-CKKS diagnostic."""
    plaintext_result = plaintext_result_from_oracle_row(plaintext_row, model_name)
    encrypted_result = encrypted_result_from_rounded_packet(decrypted)

    dp_plain = compute_demographic_parity(plaintext_result)
    dp_encrypted = compute_demographic_parity(encrypted_result)
    eo_plain = compute_equalised_odds(plaintext_result)
    eo_encrypted = compute_equalised_odds(encrypted_result)

    dp_error = (
        abs(dp_encrypted.dp_gap.value - dp_plain.dp_gap.value)
        if dp_plain.dp_gap.available and dp_encrypted.dp_gap.available
        else None
    )
    eo_error = (
        abs(eo_encrypted.eo_gap.value - eo_plain.eo_gap.value)
        if eo_plain.eo_gap.available and eo_encrypted.eo_gap.available
        else None
    )

    dp_raw_ckks = eo_raw_ckks = None
    dp_raw_ckks_error = eo_raw_ckks_error = None
    if include_raw_ckks_diagnostic:
        raw_result = encrypted_result_from_raw_packet(decrypted)
        dp_raw_ckks = compute_demographic_parity(raw_result).dp_gap
        eo_raw_ckks = compute_equalised_odds(raw_result).eo_gap
        if dp_plain.dp_gap.available and dp_raw_ckks.available:
            dp_raw_ckks_error = abs(dp_raw_ckks.value - dp_plain.dp_gap.value)
        if eo_plain.eo_gap.available and eo_raw_ckks.available:
            eo_raw_ckks_error = abs(eo_raw_ckks.value - eo_plain.eo_gap.value)

    return FairnessReconstructionResult(
        model=model_name,
        minimum_cell_size=minimum_cell_size,
        dp_plain=dp_plain.dp_gap,
        dp_encrypted=dp_encrypted.dp_gap,
        dp_reconstruction_error=dp_error,
        eo_plain=eo_plain.eo_gap,
        eo_encrypted=eo_encrypted.eo_gap,
        eo_reconstruction_error=eo_error,
        approval_rate_m_plain=dp_plain.approval_rate_m,
        approval_rate_f_plain=dp_plain.approval_rate_f,
        approval_rate_m_encrypted=dp_encrypted.approval_rate_m,
        approval_rate_f_encrypted=dp_encrypted.approval_rate_f,
        tpr_m_plain=eo_plain.tpr_m,
        tpr_f_plain=eo_plain.tpr_f,
        tpr_m_encrypted=eo_encrypted.tpr_m,
        tpr_f_encrypted=eo_encrypted.tpr_f,
        fpr_m_plain=eo_plain.fpr_m,
        fpr_f_plain=eo_plain.fpr_f,
        fpr_m_encrypted=eo_encrypted.fpr_m,
        fpr_f_encrypted=eo_encrypted.fpr_f,
        dp_release_status_plain=dp_release_status(plaintext_result, minimum_cell_size),
        dp_release_status_encrypted=dp_release_status(encrypted_result, minimum_cell_size),
        eo_release_status_plain=eo_release_status(plaintext_result, minimum_cell_size),
        eo_release_status_encrypted=eo_release_status(encrypted_result, minimum_cell_size),
        dp_raw_ckks=dp_raw_ckks,
        eo_raw_ckks=eo_raw_ckks,
        dp_raw_ckks_error=dp_raw_ckks_error,
        eo_raw_ckks_error=eo_raw_ckks_error,
    )
