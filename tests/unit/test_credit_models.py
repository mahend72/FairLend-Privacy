"""Unit tests for fairlend.models.credit_models: protected-attribute
exclusion at every fit/predict entry point, and threshold selection."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from fairlend.data.credit_features import CREDIT_MODEL_FEATURES
from fairlend.models.credit_models import (
    RANDOM_FOREST_GRID,
    build_feature_frame,
    select_best_logistic_regression,
    select_best_random_forest,
    select_decision_threshold,
)

RNG = np.random.default_rng(0)


def _synthetic_frame(n: int, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    return pd.DataFrame(
        {
            "annual_inc": rng.uniform(20000, 120000, n),
            "emp_length": rng.choice(["1 year", "5 years", "10+ years", np.nan], n),
            "dti": rng.uniform(0, 40, n),
            "home_ownership": rng.choice(["RENT", "OWN", "MORTGAGE"], n),
            "addr_state": rng.choice(["CA", "TX", "NY"], n),
        }
    )


def _labels(n: int, seed: int) -> np.ndarray:
    return np.random.default_rng(seed).integers(0, 2, n)


def test_build_feature_frame_returns_only_allowlisted_columns():
    df = _synthetic_frame(20)
    X = build_feature_frame(df, emp_length_train_median=5.0)
    assert set(X.columns) == CREDIT_MODEL_FEATURES


def test_select_best_logistic_regression_rejects_protected_column_in_train():
    X_train = build_feature_frame(_synthetic_frame(30, seed=1), 5.0)
    X_train["synthetic_gender_label"] = 0
    X_val = build_feature_frame(_synthetic_frame(10, seed=2), 5.0)
    with pytest.raises(ValueError, match="protected-attribute"):
        select_best_logistic_regression(
            X_train, _labels(30, 1), X_val, _labels(10, 2), random_state=0
        )


def test_select_best_logistic_regression_rejects_protected_column_in_validation():
    X_train = build_feature_frame(_synthetic_frame(30, seed=1), 5.0)
    X_val = build_feature_frame(_synthetic_frame(10, seed=2), 5.0)
    X_val["probability_female"] = 0.5
    with pytest.raises(ValueError, match="protected-attribute"):
        select_best_logistic_regression(
            X_train, _labels(30, 1), X_val, _labels(10, 2), random_state=0
        )


def test_select_best_random_forest_rejects_protected_column():
    X_train = build_feature_frame(_synthetic_frame(30, seed=1), 5.0)
    X_train["male"] = 1
    X_val = build_feature_frame(_synthetic_frame(10, seed=2), 5.0)
    with pytest.raises(ValueError, match="protected-attribute"):
        select_best_random_forest(
            X_train, _labels(30, 1), X_val, _labels(10, 2), random_state=0
        )


def test_fitted_model_predict_rejects_protected_column_at_predict_time():
    X_train = build_feature_frame(_synthetic_frame(30, seed=1), 5.0)
    X_val = build_feature_frame(_synthetic_frame(10, seed=2), 5.0)
    model = select_best_logistic_regression(
        X_train, _labels(30, 1), X_val, _labels(10, 2), random_state=0
    )
    X_test = build_feature_frame(_synthetic_frame(10, seed=3), 5.0)
    X_test["gender"] = 0
    with pytest.raises(ValueError, match="protected-attribute"):
        model.predict_probability(X_test)
    with pytest.raises(ValueError, match="protected-attribute"):
        model.predict_decision(X_test)


def test_fitted_model_predicts_on_clean_features_without_raising():
    X_train = build_feature_frame(_synthetic_frame(30, seed=1), 5.0)
    X_val = build_feature_frame(_synthetic_frame(10, seed=2), 5.0)
    model = select_best_logistic_regression(
        X_train, _labels(30, 1), X_val, _labels(10, 2), random_state=0
    )
    X_test = build_feature_frame(_synthetic_frame(10, seed=3), 5.0)
    proba = model.predict_probability(X_test)
    decision = model.predict_decision(X_test)
    assert proba.shape == (10,)
    assert set(np.unique(decision)).issubset({0, 1})


def test_select_decision_threshold_picks_perfectly_separating_threshold():
    y_true = np.array([0, 0, 0, 1, 1, 1])
    proba = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])
    threshold, f1 = select_decision_threshold(y_true, proba)
    assert 0.3 < threshold <= 0.7
    assert f1 == 1.0


def test_random_forest_selection_tries_every_grid_entry():
    X_train = build_feature_frame(_synthetic_frame(40, seed=5), 5.0)
    X_val = build_feature_frame(_synthetic_frame(15, seed=6), 5.0)
    model = select_best_random_forest(
        X_train, _labels(40, 5), X_val, _labels(15, 6), random_state=0
    )
    assert model.hyperparameters in RANDOM_FOREST_GRID
    assert model.model_name == "random_forest"
