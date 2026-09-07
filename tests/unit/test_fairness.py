"""Unit tests for fairlend.audit.fairness: DP/EO formulas on hand-
calculated counts, zero-denominator handling, and k_min release status."""
from __future__ import annotations

import pytest

from fairlend.audit.aggregation import GROUP_FEMALE, GROUP_MALE, GroupAuditCounts, PlaintextAuditResult
from fairlend.audit.fairness import (
    NOT_CONFIGURED,
    RELEASED,
    SUPPRESSED,
    RateResult,
    compute_demographic_parity,
    compute_equalised_odds,
    dp_release_status,
    eo_release_status,
)


def _result(m: GroupAuditCounts, f: GroupAuditCounts) -> PlaintextAuditResult:
    full_test_n = m.C + f.C
    resolved_test_n = m.P + m.N + f.P + f.N
    return PlaintextAuditResult(
        model_name="toy",
        groups={GROUP_MALE: m, GROUP_FEMALE: f},
        full_test_n=full_test_n,
        resolved_test_n=resolved_test_n,
        unresolved_test_n=full_test_n - resolved_test_n,
    )


# --- RateResult invariants --------------------------------------------------


def test_rate_result_available_requires_value():
    with pytest.raises(ValueError):
        RateResult(value=None, available=True)


def test_rate_result_unavailable_requires_reason():
    with pytest.raises(ValueError):
        RateResult(value=None, available=False, reason=None)


def test_rate_result_unavailable_forbids_value():
    with pytest.raises(ValueError):
        RateResult(value=0.5, available=False, reason="x")


# --- Demographic parity: hand-calculated ------------------------------------


def test_demographic_parity_hand_calculated():
    # C_m=20, A_m=10 -> approval_rate_m=0.5
    # C_f=10, A_f=6  -> approval_rate_f=0.6
    # DP = |0.6 - 0.5| = 0.1
    m = GroupAuditCounts(group=GROUP_MALE, C=20, A=10, P=0, TP=0, N=0, FP=0)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=10, A=6, P=0, TP=0, N=0, FP=0)
    dp = compute_demographic_parity(_result(m, f))
    assert dp.approval_rate_m.value == pytest.approx(0.5)
    assert dp.approval_rate_f.value == pytest.approx(0.6)
    assert dp.dp_gap.value == pytest.approx(0.1)
    assert dp.dp_gap.available


def test_demographic_parity_zero_denominator_reports_unavailable_not_zero():
    m = GroupAuditCounts(group=GROUP_MALE, C=0, A=0, P=0, TP=0, N=0, FP=0)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=10, A=6, P=0, TP=0, N=0, FP=0)
    dp = compute_demographic_parity(_result(m, f))
    assert dp.approval_rate_m.available is False
    assert dp.approval_rate_m.value is None
    assert "denominator is 0" in dp.approval_rate_m.reason
    assert dp.dp_gap.available is False
    assert dp.dp_gap.value is None


# --- Equalised odds: hand-calculated ----------------------------------------


def test_equalised_odds_hand_calculated():
    # Male:   P=10, TP=8 -> TPR_m=0.8 ; N=10, FP=2 -> FPR_m=0.2
    # Female: P=5,  TP=3 -> TPR_f=0.6 ; N=5,  FP=2 -> FPR_f=0.4
    # EO = max(|0.6-0.8|, |0.4-0.2|) = max(0.2, 0.2) = 0.2
    m = GroupAuditCounts(group=GROUP_MALE, C=20, A=10, P=10, TP=8, N=10, FP=2)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=10, A=5, P=5, TP=3, N=5, FP=2)
    eo = compute_equalised_odds(_result(m, f))
    assert eo.tpr_m.value == pytest.approx(0.8)
    assert eo.tpr_f.value == pytest.approx(0.6)
    assert eo.fpr_m.value == pytest.approx(0.2)
    assert eo.fpr_f.value == pytest.approx(0.4)
    assert eo.eo_gap.value == pytest.approx(0.2)


def test_equalised_odds_uses_tpr_gap_when_it_dominates():
    m = GroupAuditCounts(group=GROUP_MALE, C=20, A=10, P=10, TP=9, N=10, FP=1)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=10, A=5, P=5, TP=1, N=5, FP=1)
    eo = compute_equalised_odds(_result(m, f))
    # TPR_m=0.9, TPR_f=0.2 -> |gap|=0.7 ; FPR_m=0.1, FPR_f=0.2 -> |gap|=0.1
    assert eo.eo_gap.value == pytest.approx(0.7)


def test_equalised_odds_zero_denominator_reports_unavailable_not_zero():
    m = GroupAuditCounts(group=GROUP_MALE, C=20, A=10, P=0, TP=0, N=10, FP=2)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=10, A=5, P=5, TP=3, N=5, FP=2)
    eo = compute_equalised_odds(_result(m, f))
    assert eo.tpr_m.available is False
    assert eo.eo_gap.available is False
    assert eo.eo_gap.value is None
    assert "TPR_m" in eo.eo_gap.reason


# --- k_min release status ----------------------------------------------------


def test_dp_release_status_not_configured_when_k_min_is_none():
    m = GroupAuditCounts(group=GROUP_MALE, C=1, A=0, P=0, TP=0, N=0, FP=0)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=1, A=0, P=0, TP=0, N=0, FP=0)
    assert dp_release_status(_result(m, f), minimum_cell_size=None) == NOT_CONFIGURED


def test_eo_release_status_not_configured_when_k_min_is_none():
    m = GroupAuditCounts(group=GROUP_MALE, C=1, A=0, P=1, TP=0, N=1, FP=0)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=1, A=0, P=1, TP=0, N=1, FP=0)
    assert eo_release_status(_result(m, f), minimum_cell_size=None) == NOT_CONFIGURED


def test_dp_release_status_released_when_both_groups_meet_k_min():
    m = GroupAuditCounts(group=GROUP_MALE, C=20, A=0, P=0, TP=0, N=0, FP=0)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=15, A=0, P=0, TP=0, N=0, FP=0)
    assert dp_release_status(_result(m, f), minimum_cell_size=10) == RELEASED


def test_dp_release_status_suppressed_when_one_group_below_k_min():
    m = GroupAuditCounts(group=GROUP_MALE, C=20, A=0, P=0, TP=0, N=0, FP=0)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=5, A=0, P=0, TP=0, N=0, FP=0)
    assert dp_release_status(_result(m, f), minimum_cell_size=10) == SUPPRESSED


def test_eo_release_status_released_when_all_four_cells_meet_k_min():
    m = GroupAuditCounts(group=GROUP_MALE, C=30, A=0, P=15, TP=0, N=15, FP=0)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=30, A=0, P=15, TP=0, N=15, FP=0)
    assert eo_release_status(_result(m, f), minimum_cell_size=10) == RELEASED


def test_eo_release_status_suppressed_when_one_cell_below_k_min():
    m = GroupAuditCounts(group=GROUP_MALE, C=30, A=0, P=15, TP=0, N=15, FP=0)
    f = GroupAuditCounts(group=GROUP_FEMALE, C=30, A=0, P=3, TP=0, N=15, FP=0)
    assert eo_release_status(_result(m, f), minimum_cell_size=10) == SUPPRESSED
