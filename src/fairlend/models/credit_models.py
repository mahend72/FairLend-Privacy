"""Manuscript-aligned plaintext credit-decision models (Phase G, Sec.
6.9-6.10): a logistic regression and a random forest.

Both model families are fit ONLY on ``train_model_fit_index`` (resolved-
outcome TRAIN rows; see ``fairlend.data.audit_scope``). Hyperparameters
AND the approval-decision threshold tau (Y-hat_i = I[s_i >= tau]) are
BOTH selected on VALIDATION only (``validation_model_select_index``) --
never on TEST. The manuscript defines tau but never states its numeric
value (docs/IMPLEMENTATION_GAPS.md item A.4); ``select_decision_threshold``
picks it by maximising VALIDATION F1 over ``THRESHOLD_GRID``, an explicit,
documented experimental choice, not a manuscript figure.

TEST predictions must be computed exactly once (see
``evaluation/train_credit_models.py``) and saved to
``model_predictions.parquet``. Every downstream audit -- plaintext
(Phase 2) and encrypted (Phases 5-8) -- must read that fixed file rather
than recomputing or re-thresholding its own predictions, so both audit
paths are provably auditing the identical set of decisions.

``fairlend.data.credit_features.assert_no_protected_columns`` is called
before every single fit/predict call in this module (not just once at the
top of the training script), so a caller cannot bypass the guard by
calling a lower-level function directly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from fairlend.data.credit_features import CREDIT_MODEL_FEATURES, assert_no_protected_columns
from fairlend.data.proxy_features import raw_credit_features

LOGISTIC_REGRESSION = "logistic_regression"
RANDOM_FOREST = "random_forest"
MODEL_NAMES: Tuple[str, ...] = (LOGISTIC_REGRESSION, RANDOM_FOREST)

# Small, fixed hyperparameter grids, selected on VALIDATION only (see
# select_best_logistic_regression / select_best_random_forest). These are
# a reasonable, documented default grid -- not tuned against any fixture
# or the real dataset, and not a manuscript-specified value.
LOGISTIC_REGRESSION_C_GRID: Tuple[float, ...] = (0.01, 0.1, 1.0, 10.0)
RANDOM_FOREST_GRID: Tuple[Dict[str, Any], ...] = (
    {"n_estimators": 100, "max_depth": 4},
    {"n_estimators": 100, "max_depth": 8},
    {"n_estimators": 300, "max_depth": None},
)

# Candidate decision thresholds for tau selection (VALIDATION only).
THRESHOLD_GRID: np.ndarray = np.round(np.linspace(0.05, 0.95, 19), 2)


def build_feature_frame(df: pd.DataFrame, emp_length_train_median: float) -> pd.DataFrame:
    """The exact ``CREDIT_MODEL_FEATURES`` columns for every row of ``df``,
    validated against the allowlist before being returned so an
    accidental extra/missing/protected column fails here, not inside
    sklearn."""
    X = raw_credit_features(df, emp_length_train_median)
    X = X[sorted(CREDIT_MODEL_FEATURES)]
    assert_no_protected_columns(X.columns)
    return X


@dataclass(frozen=True)
class FittedCreditModel:
    """A fitted credit-decision model plus its selected hyperparameters
    and decision threshold -- everything needed to reproduce a prediction
    without re-selecting anything on TEST."""

    model_name: str
    estimator: Any
    hyperparameters: Dict[str, Any]
    threshold: float
    selection_metric: str
    selection_score: float

    def predict_probability(self, X: pd.DataFrame) -> np.ndarray:
        assert_no_protected_columns(X.columns)
        return self.estimator.predict_proba(X)[:, 1]

    def predict_decision(self, X: pd.DataFrame) -> np.ndarray:
        proba = self.predict_probability(X)
        return (proba >= self.threshold).astype(int)


def _fit_logistic_regression(
    X_train: pd.DataFrame, y_train: np.ndarray, C: float, random_state: int
) -> Pipeline:
    assert_no_protected_columns(X_train.columns)
    # StandardScaler is fit inside the same Pipeline.fit(X_train, ...) call
    # as the classifier, so it is fit on TRAIN only by construction -- it
    # can never see validation/test rows.
    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(C=C, max_iter=1000, random_state=random_state)),
        ]
    )
    pipeline.fit(X_train, y_train)
    return pipeline


def _fit_random_forest(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    n_estimators: int,
    max_depth: Any,
    random_state: int,
) -> RandomForestClassifier:
    assert_no_protected_columns(X_train.columns)
    clf = RandomForestClassifier(
        n_estimators=n_estimators, max_depth=max_depth, random_state=random_state
    )
    clf.fit(X_train, y_train)
    return clf


def _selection_score(y_true: np.ndarray, proba: np.ndarray) -> Tuple[str, float]:
    """ROC-AUC if VALIDATION has both classes present, else an explicit
    threshold-free fallback (accuracy at 0.5) so model selection never
    silently crashes -- or silently reports a fabricated AUC -- on a
    degenerate single-class validation split."""
    if len(np.unique(y_true)) < 2:
        fallback = float(((proba >= 0.5).astype(int) == y_true).mean())
        return "validation_accuracy_at_0.5_fallback_single_class", fallback
    return "validation_roc_auc", float(roc_auc_score(y_true, proba))


def select_decision_threshold(y_true: np.ndarray, proba: np.ndarray) -> Tuple[float, float]:
    """Choose tau in THRESHOLD_GRID maximising F1 on (y_true, proba).

    VALIDATION ONLY -- callers must never pass TEST data here (this
    function has no way to enforce that structurally; the boundary is
    enforced by evaluation/train_credit_models.py never calling it with
    test data -- see tests/scientific/test_model_boundaries.py).
    """
    best_threshold = float(THRESHOLD_GRID[0])
    best_f1 = -1.0
    for threshold in THRESHOLD_GRID:
        y_pred = (proba >= threshold).astype(int)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        if f1 > best_f1:
            best_f1 = float(f1)
            best_threshold = float(threshold)
    return best_threshold, best_f1


def select_best_logistic_regression(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    X_validation: pd.DataFrame,
    y_validation: np.ndarray,
    random_state: int,
    C_grid: Sequence[float] = LOGISTIC_REGRESSION_C_GRID,
) -> FittedCreditModel:
    """Fit one logistic regression per C in ``C_grid`` on TRAIN, score each
    on VALIDATION, keep the best, then select tau on VALIDATION."""
    assert_no_protected_columns(X_train.columns)
    assert_no_protected_columns(X_validation.columns)

    best_pipeline = None
    best_C = None
    best_metric_name = ""
    best_score = -np.inf
    for C in C_grid:
        pipeline = _fit_logistic_regression(X_train, y_train, C, random_state)
        proba_val = pipeline.predict_proba(X_validation)[:, 1]
        metric_name, score = _selection_score(y_validation, proba_val)
        if score > best_score:
            best_score, best_pipeline, best_C, best_metric_name = score, pipeline, C, metric_name

    proba_val_best = best_pipeline.predict_proba(X_validation)[:, 1]
    threshold, _ = select_decision_threshold(y_validation, proba_val_best)
    return FittedCreditModel(
        model_name=LOGISTIC_REGRESSION,
        estimator=best_pipeline,
        hyperparameters={"C": best_C},
        threshold=threshold,
        selection_metric=best_metric_name,
        selection_score=best_score,
    )


def select_best_random_forest(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    X_validation: pd.DataFrame,
    y_validation: np.ndarray,
    random_state: int,
    grid: Sequence[Mapping[str, Any]] = RANDOM_FOREST_GRID,
) -> FittedCreditModel:
    """Fit one random forest per hyperparameter set in ``grid`` on TRAIN,
    score each on VALIDATION, keep the best, then select tau on
    VALIDATION."""
    assert_no_protected_columns(X_train.columns)
    assert_no_protected_columns(X_validation.columns)

    best_clf = None
    best_params: Dict[str, Any] = {}
    best_metric_name = ""
    best_score = -np.inf
    for params in grid:
        clf = _fit_random_forest(
            X_train, y_train, params["n_estimators"], params["max_depth"], random_state
        )
        proba_val = clf.predict_proba(X_validation)[:, 1]
        metric_name, score = _selection_score(y_validation, proba_val)
        if score > best_score:
            best_score, best_clf, best_params, best_metric_name = (
                score,
                clf,
                dict(params),
                metric_name,
            )

    proba_val_best = best_clf.predict_proba(X_validation)[:, 1]
    threshold, _ = select_decision_threshold(y_validation, proba_val_best)
    return FittedCreditModel(
        model_name=RANDOM_FOREST,
        estimator=best_clf,
        hyperparameters=best_params,
        threshold=threshold,
        selection_metric=best_metric_name,
        selection_score=best_score,
    )
