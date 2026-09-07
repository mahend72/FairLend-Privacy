"""Held-out classification metrics for the plaintext credit-decision
models.

These describe predictive performance of the plaintext baseline models on
TEST; they are not a claim about FairLend's own contribution. FairLend's
contribution is the privacy-preserving fairness AUDIT (``fairlend.audit``),
not the credit-decision model itself -- see
docs/IMPLEMENTATION_GAPS.md item A.5 and the manuscript's own disclaimer
that it does not report specific encrypted-matching accuracy figures.
"""
from __future__ import annotations

from typing import Dict, Optional

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score


def classification_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, y_proba: Optional[np.ndarray] = None
) -> Dict[str, Optional[float]]:
    """Standard held-out metrics.

    ``y_true``/``y_pred`` must contain only resolved (0/1) records --
    callers are responsible for excluding unresolved-outcome rows first
    (see ``fairlend.data.populations``); this function does not know how
    to detect an unresolved row.

    ``roc_auc`` is ``None`` (never silently 0.0 or NaN) when ``y_true``
    has fewer than two classes, since ROC-AUC is undefined there, not
    zero.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    n = int(len(y_true))
    if n == 0:
        raise ValueError("classification_metrics called with zero records.")
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"y_true and y_pred length mismatch: {len(y_true)} vs {len(y_pred)}."
        )

    metrics: Dict[str, Optional[float]] = {
        "n_predictions": n,
        "positive_rate": float(np.mean(y_true)),
        "predicted_positive_rate": float(np.mean(y_pred)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if y_proba is not None and len(np.unique(y_true)) >= 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, np.asarray(y_proba)))
    else:
        metrics["roc_auc"] = None
    return metrics


def rate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    """TPR/FPR/balanced accuracy at a fixed decision -- a small, purely
    additive helper (added for the threshold-policy sensitivity audit,
    ``fairlend.models.threshold_policies``) alongside, not instead of,
    ``classification_metrics`` above; nothing existing is changed.

    ``TPR`` is identical to ``classification_metrics``'s ``recall`` (same
    formula, reported here as ``TPR`` for readability alongside ``FPR``,
    which ``classification_metrics`` does not report). Balanced accuracy
    is ``(TPR + TNR) / 2``; both are 0.0 -- not NaN -- when their
    denominator (P or N) is zero and that class is genuinely absent, to
    keep this function total over any 0/1 ``y_true``.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    positives = y_true == 1
    negatives = y_true == 0
    tpr = float((y_pred[positives] == 1).mean()) if positives.any() else 0.0
    fpr = float((y_pred[negatives] == 1).mean()) if negatives.any() else 0.0
    balanced_accuracy = (tpr + (1.0 - fpr)) / 2.0
    return {"tpr": tpr, "fpr": fpr, "balanced_accuracy": balanced_accuracy}
