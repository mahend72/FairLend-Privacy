"""Unit tests for fairlend.models.threshold_policies: hand-built
validation arrays, no model fitting, no CKKS -- pure selection-formula
correctness, VALIDATION/TEST boundary, and reproducibility of the
existing validation_f1_max policy."""
from __future__ import annotations

import inspect

import numpy as np
import pytest

from fairlend.models.credit_models import THRESHOLD_GRID, select_decision_threshold
from fairlend.models.threshold_policies import (
    ALL_POLICIES,
    POLICY_BALANCED_ACCURACY_MAX,
    POLICY_FIXED_050,
    POLICY_VALIDATION_F1_MAX,
    POLICY_YOUDEN_J,
    ThresholdPolicyResult,
    evaluate_at_threshold,
    select_threshold,
    select_threshold_balanced_accuracy_max,
    select_threshold_fixed_050,
    select_threshold_youden_j,
)


# --- Structural: VALIDATION only, no TEST parameter -------------------------


def test_all_policy_functions_have_no_test_data_parameter():
    for fn in (
        select_decision_threshold,
        select_threshold_fixed_050,
        select_threshold_balanced_accuracy_max,
        select_threshold_youden_j,
    ):
        params = list(inspect.signature(fn).parameters)
        assert not any("test" in p.lower() for p in params), (fn.__name__, params)


def test_select_threshold_dispatch_has_no_test_data_parameter():
    params = list(inspect.signature(select_threshold).parameters)
    assert params == ["policy", "y_true_validation", "proba_validation"]


def test_select_threshold_unknown_policy_raises():
    with pytest.raises(ValueError):
        select_threshold("not_a_real_policy", np.array([0, 1]), np.array([0.1, 0.9]))


# --- Policy B: fixed 0.50 really remains 0.50 -------------------------------


def test_fixed_050_ignores_validation_data_entirely():
    tau_a, _ = select_threshold_fixed_050(np.array([1, 1, 1]), np.array([0.01, 0.02, 0.03]))
    tau_b, _ = select_threshold_fixed_050(np.array([0, 0, 0]), np.array([0.99, 0.98, 0.97]))
    assert tau_a == 0.5
    assert tau_b == 0.5


def test_select_threshold_dispatch_fixed_050():
    result = select_threshold(POLICY_FIXED_050, np.array([1, 0]), np.array([0.9, 0.1]))
    assert result.tau == 0.5
    assert result.policy == POLICY_FIXED_050


# --- Policy A: validation_f1_max reproducibility (reuses existing fn) ------


def test_validation_f1_max_matches_direct_call_to_existing_function():
    y_true = np.array([1, 1, 0, 0, 1, 0])
    proba = np.array([0.9, 0.8, 0.3, 0.2, 0.6, 0.55])
    expected_tau, expected_f1 = select_decision_threshold(y_true, proba)
    result = select_threshold(POLICY_VALIDATION_F1_MAX, y_true, proba)
    assert result.tau == expected_tau
    assert result.selection_score == expected_f1


# --- Policy C: balanced-accuracy-max hand-calculated ------------------------


def test_balanced_accuracy_max_hand_calculated():
    # 4 positives (proba >= 0.6), 4 negatives (proba <= 0.4) -- a clean
    # gap between the classes.
    # At threshold 0.5: TPR=4/4=1.0 (all positives >= 0.5), FPR=0/4=0.0
    # (all negatives < 0.5) -> balanced acc = 1.0 (perfect).
    # At threshold 0.65: TPR=3/4=0.75 (0.6 now falls below), FPR=0.0
    # -> balanced acc = 0.875 -- strictly worse.
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0])
    proba = np.array([0.9, 0.8, 0.7, 0.6, 0.4, 0.3, 0.2, 0.1])
    tau, score = select_threshold_balanced_accuracy_max(y_true, proba, grid=(0.5, 0.65))
    assert tau == 0.5
    assert score == pytest.approx(1.0)


def test_balanced_accuracy_max_prefers_smaller_tau_on_tie():
    y_true = np.array([1, 1, 0, 0])
    proba = np.array([0.9, 0.8, 0.2, 0.1])
    # Every threshold in (0.2, 0.8) perfectly separates -> balanced acc=1.0 for all of them.
    tau, score = select_threshold_balanced_accuracy_max(y_true, proba, grid=(0.3, 0.5, 0.7))
    assert tau == 0.3  # smallest, per the documented tie-break (matches select_decision_threshold's convention)
    assert score == pytest.approx(1.0)


# --- Policy D: Youden's J hand-calculated + provable equivalence to C ------


def test_youden_j_hand_calculated():
    # Same clean-gap data as test_balanced_accuracy_max_hand_calculated:
    # at tau=0.5, TPR=1.0, FPR=0.0 -> J=1.0 (maximal); at tau=0.65,
    # TPR=0.75, FPR=0.0 -> J=0.75, strictly worse.
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0])
    proba = np.array([0.9, 0.8, 0.7, 0.6, 0.4, 0.3, 0.2, 0.1])
    tau, score = select_threshold_youden_j(y_true, proba, grid=(0.5, 0.65))
    assert tau == 0.5
    assert score == pytest.approx(1.0)


@pytest.mark.parametrize("seed", range(5))
def test_balanced_accuracy_and_youden_j_always_select_the_same_tau(seed):
    """Provable mathematical fact (module docstring): J = 2*BA - 1 is a
    strictly increasing function of balanced accuracy, so argmax is
    identical for any (y_true, proba) input -- checked here on several
    random instances, not just one hand-built example."""
    rng = np.random.default_rng(seed)
    y_true = rng.integers(0, 2, size=50)
    proba = rng.random(50)
    tau_ba, _ = select_threshold_balanced_accuracy_max(y_true, proba)
    tau_j, _ = select_threshold_youden_j(y_true, proba)
    assert tau_ba == tau_j


# --- evaluate_at_threshold: frozen application, approval rate correctness --


def test_evaluate_at_threshold_approval_rate_computed_correctly():
    y_true = np.array([1, 0, 1, 0, 1])
    proba = np.array([0.9, 0.8, 0.3, 0.2, 0.6])
    metrics = evaluate_at_threshold(y_true, proba, tau=0.5)
    # Approved: 0.9, 0.8, 0.6 -> 3 of 5.
    assert metrics["predicted_positive_rate"] == pytest.approx(0.6)


def test_evaluate_at_threshold_uses_the_given_tau_unchanged():
    y_true = np.array([1, 0, 1, 0])
    proba = np.array([0.9, 0.1, 0.55, 0.45])
    low = evaluate_at_threshold(y_true, proba, tau=0.05)  # below every score -> all approved
    high = evaluate_at_threshold(y_true, proba, tau=0.95)  # above every score -> none approved
    assert low["predicted_positive_rate"] == pytest.approx(1.0)
    assert high["predicted_positive_rate"] == pytest.approx(0.0)


def test_evaluate_at_threshold_reports_tpr_fpr_and_balanced_accuracy():
    y_true = np.array([1, 1, 0, 0])
    proba = np.array([0.9, 0.1, 0.9, 0.1])
    metrics = evaluate_at_threshold(y_true, proba, tau=0.5)
    assert "tpr" in metrics and "fpr" in metrics and "balanced_accuracy" in metrics
    assert metrics["tpr"] == pytest.approx(0.5)
    assert metrics["fpr"] == pytest.approx(0.5)


# --- ThresholdPolicyResult / registry completeness --------------------------


def test_all_policies_are_selectable_and_return_typed_result():
    y_true = np.array([1, 1, 0, 0, 1, 0, 1, 0])
    proba = np.array([0.9, 0.8, 0.3, 0.2, 0.6, 0.55, 0.7, 0.4])
    for policy in ALL_POLICIES:
        result = select_threshold(policy, y_true, proba)
        assert isinstance(result, ThresholdPolicyResult)
        assert 0.0 <= result.tau <= 1.0
        assert result.policy == policy
