"""Unit tests for fairlend.models.metrics.classification_metrics."""
from __future__ import annotations

import numpy as np
import pytest

from fairlend.models.metrics import classification_metrics


def test_perfect_predictions():
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 0, 1, 1])
    metrics = classification_metrics(y_true, y_pred)
    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["n_predictions"] == 4


def test_roc_auc_is_none_for_single_class_y_true():
    y_true = np.array([1, 1, 1])
    y_pred = np.array([1, 0, 1])
    metrics = classification_metrics(y_true, y_pred, y_proba=np.array([0.9, 0.4, 0.8]))
    assert metrics["roc_auc"] is None


def test_roc_auc_present_when_both_classes_and_proba_given():
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 1, 1, 1])
    proba = np.array([0.1, 0.6, 0.7, 0.9])
    metrics = classification_metrics(y_true, y_pred, y_proba=proba)
    assert metrics["roc_auc"] is not None
    assert 0.0 <= metrics["roc_auc"] <= 1.0


def test_zero_division_does_not_raise_and_reports_zero_precision():
    y_true = np.array([0, 0, 0])
    y_pred = np.array([1, 1, 1])
    metrics = classification_metrics(y_true, y_pred)
    assert metrics["precision"] == 0.0


def test_empty_input_raises():
    with pytest.raises(ValueError):
        classification_metrics(np.array([]), np.array([]))


def test_length_mismatch_raises():
    with pytest.raises(ValueError):
        classification_metrics(np.array([0, 1]), np.array([0]))
