"""FLA fairness metrics: demographic parity and equalised odds (manuscript
Sec. 4.8, Algorithm 6's plaintext analogue).

    DP = |A_f/C_f - A_m/C_m|
    TPR_k = TP_k / P_k,  FPR_k = FP_k / N_k
    EO = max(|TPR_f - TPR_m|, |FPR_f - FPR_m|)

A metric is never silently reported as 0.0 when its denominator is zero --
``RateResult.available`` is False and ``value`` is None in that case, with
``reason`` recorded, so "the gap is zero" and "the gap could not be
computed" are never confused with each other.

Minimum-cell-size release suppression (k_min, Table 1): the manuscript
defines k_min but states no numeric value (docs/IMPLEMENTATION_GAPS.md).
``configs/evaluation.yaml``'s ``fairness.minimum_cell_size`` is therefore
``None`` by default, and ``dp_release_status``/``eo_release_status``
report ``"minimum_cell_size_not_configured"`` in that case -- NOT
``"released"`` and NOT a fabricated ``"suppressed"``. The raw metrics
above are always computed regardless of release status (they are needed
for scientific verification of this implementation); release status is a
separate, explicit annotation on top, never a gate on computing the
number in the first place.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fairlend.audit.aggregation import PlaintextAuditResult

NOT_CONFIGURED = "minimum_cell_size_not_configured"
RELEASED = "released"
SUPPRESSED = "suppressed_below_minimum_cell_size"


@dataclass(frozen=True)
class RateResult:
    """A single rate (or gap), or an explicit reason it is unavailable.

    ``value`` is None whenever ``available`` is False -- never 0.0 as a
    stand-in for "undefined".
    """

    value: Optional[float]
    available: bool
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.available and self.value is None:
            raise ValueError("RateResult marked available=True but value is None.")
        if not self.available and self.value is not None:
            raise ValueError("RateResult marked available=False but value is not None.")
        if not self.available and not self.reason:
            raise ValueError("RateResult marked unavailable must record a reason.")


def _safe_rate(numerator: int, denominator: int, name: str) -> RateResult:
    if denominator == 0:
        return RateResult(value=None, available=False, reason=f"{name} undefined: denominator is 0")
    return RateResult(value=numerator / denominator, available=True)


@dataclass(frozen=True)
class DemographicParityResult:
    approval_rate_m: RateResult
    approval_rate_f: RateResult
    dp_gap: RateResult


@dataclass(frozen=True)
class EqualisedOddsResult:
    tpr_m: RateResult
    tpr_f: RateResult
    fpr_m: RateResult
    fpr_f: RateResult
    eo_gap: RateResult


def compute_demographic_parity(result: PlaintextAuditResult) -> DemographicParityResult:
    m, f = result.male(), result.female()
    approval_rate_m = _safe_rate(m.A, m.C, "approval_rate_m")
    approval_rate_f = _safe_rate(f.A, f.C, "approval_rate_f")
    if approval_rate_m.available and approval_rate_f.available:
        dp_gap = RateResult(value=abs(approval_rate_f.value - approval_rate_m.value), available=True)
    else:
        reasons = [r.reason for r in (approval_rate_m, approval_rate_f) if not r.available]
        dp_gap = RateResult(value=None, available=False, reason="; ".join(reasons))
    return DemographicParityResult(
        approval_rate_m=approval_rate_m, approval_rate_f=approval_rate_f, dp_gap=dp_gap
    )


def compute_equalised_odds(result: PlaintextAuditResult) -> EqualisedOddsResult:
    m, f = result.male(), result.female()
    tpr_m = _safe_rate(m.TP, m.P, "TPR_m")
    tpr_f = _safe_rate(f.TP, f.P, "TPR_f")
    fpr_m = _safe_rate(m.FP, m.N, "FPR_m")
    fpr_f = _safe_rate(f.FP, f.N, "FPR_f")
    rates = (tpr_m, tpr_f, fpr_m, fpr_f)
    if all(r.available for r in rates):
        eo_gap = RateResult(
            value=max(abs(tpr_f.value - tpr_m.value), abs(fpr_f.value - fpr_m.value)),
            available=True,
        )
    else:
        reasons = [r.reason for r in rates if not r.available]
        eo_gap = RateResult(value=None, available=False, reason="; ".join(reasons))
    return EqualisedOddsResult(tpr_m=tpr_m, tpr_f=tpr_f, fpr_m=fpr_m, fpr_f=fpr_f, eo_gap=eo_gap)


def dp_release_status(result: PlaintextAuditResult, minimum_cell_size: Optional[int]) -> str:
    """"released" requires C_m >= k_min AND C_f >= k_min. ``None`` reports
    ``NOT_CONFIGURED`` -- it is never treated as k_min = 0."""
    if minimum_cell_size is None:
        return NOT_CONFIGURED
    m, f = result.male(), result.female()
    if m.C >= minimum_cell_size and f.C >= minimum_cell_size:
        return RELEASED
    return SUPPRESSED


def eo_release_status(result: PlaintextAuditResult, minimum_cell_size: Optional[int]) -> str:
    """"released" requires P_m, P_f, N_m, N_f all >= k_min. ``None``
    reports ``NOT_CONFIGURED`` -- it is never treated as k_min = 0."""
    if minimum_cell_size is None:
        return NOT_CONFIGURED
    m, f = result.male(), result.female()
    if all(x >= minimum_cell_size for x in (m.P, f.P, m.N, f.N)):
        return RELEASED
    return SUPPRESSED
