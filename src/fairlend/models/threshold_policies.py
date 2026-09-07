"""Validation-only credit-decision threshold-selection policies
(threshold-policy sensitivity audit).

The manuscript defines the decision RULE's shape (Table 1:
``Y-hat_i = I[s_i >= tau]``) but never prescribes HOW tau should be
selected -- see docs/MANUSCRIPT_EVIDENCE_STATUS.md's threshold-policy
section for the exact manuscript passages checked. Every policy in this
module -- including ``VALIDATION_F1_MAX``, which reuses
``fairlend.models.credit_models.select_decision_threshold`` UNCHANGED --
is therefore an IMPLEMENTATION CHOICE, not a manuscript-specified
algorithm. This module does not modify, replace, or override that
existing function or its default status for
``evaluation/train_credit_models.py``'s frozen predictions; it only adds
alternative policies alongside it for comparison.

Every policy function here has the SAME signature --
``(y_true_validation, proba_validation) -> (tau, selection_score)`` --
and NONE has a parameter through which TEST data could reach it. This is
a structural guarantee (see
``tests/unit/test_threshold_policies.py::
test_all_policy_functions_have_no_test_data_parameter``), not merely a
documented convention.

Policy E (a target-approval-rate policy) is deliberately NOT implemented:
no scientifically justified target approval rate exists for this
evaluation (no manuscript figure, no external regulatory quota), and
inventing one solely to produce a non-degenerate or "more interesting"
fairness gap is exactly the kind of outcome-shopping this audit exists to
avoid. See docs/MANUSCRIPT_EVIDENCE_STATUS.md for the same statement.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

import numpy as np

from fairlend.models.credit_models import THRESHOLD_GRID, select_decision_threshold
from fairlend.models.metrics import rate_metrics

POLICY_VALIDATION_F1_MAX = "validation_f1_max"
POLICY_FIXED_050 = "fixed_probability_0.50"
POLICY_BALANCED_ACCURACY_MAX = "validation_balanced_accuracy_max"
POLICY_YOUDEN_J = "validation_youden_j"

ALL_POLICIES: Tuple[str, ...] = (
    POLICY_VALIDATION_F1_MAX,
    POLICY_FIXED_050,
    POLICY_BALANCED_ACCURACY_MAX,
    POLICY_YOUDEN_J,
)


@dataclass(frozen=True)
class ThresholdPolicyResult:
    """The frozen tau a policy selected from VALIDATION, plus the
    selection score that tau achieved (for auditability -- e.g. "this
    tau achieved F1=0.90 on VALIDATION")."""

    policy: str
    tau: float
    selection_score_name: str
    selection_score: float


def select_threshold_fixed_050(y_true_validation: np.ndarray, proba_validation: np.ndarray) -> Tuple[float, float]:
    """Policy B: tau = 0.50 unconditionally. Does not inspect
    ``y_true_validation``/``proba_validation`` at all -- both parameters
    exist only so every policy shares one call signature."""
    return 0.5, float("nan")


def select_threshold_balanced_accuracy_max(
    y_true_validation: np.ndarray, proba_validation: np.ndarray, grid: Tuple[float, ...] = tuple(THRESHOLD_GRID)
) -> Tuple[float, float]:
    """Policy C: the smallest grid tau maximising balanced accuracy
    ((TPR + TNR) / 2) on VALIDATION. Ties keep the FIRST (smallest) tau
    encountered -- the same tie-break convention as
    ``fairlend.models.credit_models.select_decision_threshold``, for a
    fair comparison between policies."""
    best_threshold = float(grid[0])
    best_score = -1.0
    for threshold in grid:
        y_pred = (proba_validation >= threshold).astype(int)
        rates = rate_metrics(y_true_validation, y_pred)
        if rates["balanced_accuracy"] > best_score:
            best_score = rates["balanced_accuracy"]
            best_threshold = float(threshold)
    return best_threshold, best_score


def select_threshold_youden_j(
    y_true_validation: np.ndarray, proba_validation: np.ndarray, grid: Tuple[float, ...] = tuple(THRESHOLD_GRID)
) -> Tuple[float, float]:
    """Policy D: the smallest grid tau maximising Youden's J = TPR - FPR
    on VALIDATION.

    NOTE (verified, not assumed): J = TPR - FPR = 2*balanced_accuracy - 1
    is a strictly increasing affine function of balanced accuracy, so
    this policy and ``select_threshold_balanced_accuracy_max`` always
    select the IDENTICAL tau for the same (y_true, proba) input -- they
    are mathematically equivalent selectors, reported separately here
    only because the task requested both by name.
    """
    best_threshold = float(grid[0])
    best_score = -2.0  # J ranges over [-1, 1]
    for threshold in grid:
        y_pred = (proba_validation >= threshold).astype(int)
        rates = rate_metrics(y_true_validation, y_pred)
        j = rates["tpr"] - rates["fpr"]
        if j > best_score:
            best_score = j
            best_threshold = float(threshold)
    return best_threshold, best_score


_POLICY_FUNCTIONS = {
    POLICY_VALIDATION_F1_MAX: ("f1", select_decision_threshold),
    POLICY_FIXED_050: ("n/a_fixed", select_threshold_fixed_050),
    POLICY_BALANCED_ACCURACY_MAX: ("balanced_accuracy", select_threshold_balanced_accuracy_max),
    POLICY_YOUDEN_J: ("youden_j", select_threshold_youden_j),
}


def select_threshold(policy: str, y_true_validation: np.ndarray, proba_validation: np.ndarray) -> ThresholdPolicyResult:
    """Dispatches to the named policy's selection function -- VALIDATION
    only, exactly as each function above already guarantees structurally.
    """
    if policy not in _POLICY_FUNCTIONS:
        raise ValueError(f"Unknown threshold policy {policy!r}; expected one of {ALL_POLICIES!r}.")
    score_name, fn = _POLICY_FUNCTIONS[policy]
    tau, score = fn(y_true_validation, proba_validation)
    return ThresholdPolicyResult(policy=policy, tau=tau, selection_score_name=score_name, selection_score=score)


def evaluate_at_threshold(y_true: np.ndarray, proba: np.ndarray, tau: float) -> Dict[str, float]:
    """Applies a FROZEN tau (from ``select_threshold``, on a DIFFERENT
    population than ``y_true``/``proba`` here -- e.g. tau selected on
    VALIDATION, applied here to TEST) and reports the resulting
    decision's standard metrics plus TPR/FPR/balanced accuracy. Does not
    alter tau; a pure evaluation function."""
    from fairlend.models.metrics import classification_metrics

    y_pred = (np.asarray(proba) >= tau).astype(int)
    metrics = classification_metrics(y_true, y_pred, proba)
    metrics.update(rate_metrics(y_true, y_pred))
    return metrics
