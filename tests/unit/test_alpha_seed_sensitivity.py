"""Unit tests for fairlend.audit.alpha_seed_sensitivity (Phase 10's
plaintext alpha1 x seed sensitivity layer) and the configuration grid it
reads from configs/evaluation.yaml. Hand-built, small inputs only -- no
real dataset, no CKKS, no model fitting beyond the tiny diagnostic
classifiers these tests construct themselves."""
from __future__ import annotations

import inspect

import numpy as np
import pandas as pd
import pytest

from fairlend.audit.alpha_seed_sensitivity import (
    STAT_KEYS,
    ConfigurationModelRow,
    assert_frozen_predictions_unchanged,
    compute_configuration_model_row,
    compute_proxy_diagnostic,
    pearson_correlation,
    row_to_flat_dict,
    summarise_runs,
)
from fairlend.core.config import load_evaluation_config
from fairlend.data.synthetic_gender import generate_synthetic_gender

CONFIG_PATH = "configs/evaluation.yaml"


# --- grid shape (Phase 10 Sec. 2/8) -------------------------------------


def test_configured_grid_has_50_alpha1_x_seed_configurations():
    config = load_evaluation_config(CONFIG_PATH)
    n_configs = len(config.synthetic_attribute.alpha1_values) * len(config.synthetic_attribute.seeds)
    assert n_configs == 50


def test_configured_grid_yields_100_model_level_rows():
    config = load_evaluation_config(CONFIG_PATH)
    n_configs = len(config.synthetic_attribute.alpha1_values) * len(config.synthetic_attribute.seeds)
    n_models = 2  # logistic_regression, random_forest
    assert n_configs * n_models == 100


def test_configured_grid_includes_alpha1_zero_control():
    config = load_evaluation_config(CONFIG_PATH)
    assert 0.0 in config.synthetic_attribute.alpha1_values


# --- alpha1=0 control (Phase 10 Sec. 11) --------------------------------


def test_alpha1_zero_gives_probability_female_exactly_half_for_configured_grid():
    """Uses the CONFIGURED alpha0 (not an assumed 0.0) -- documents the
    exact invariant Phase 10's orchestration script asserts at runtime."""
    config = load_evaluation_config(CONFIG_PATH)
    z = np.linspace(-3.0, 3.0, 500)
    result = generate_synthetic_gender(z, alpha0=config.synthetic_attribute.alpha0, alpha1=0.0, seed=0)
    assert np.allclose(result.probability_female, 0.5)


# --- module never touches credit-model fitting (Phase 10 Sec. 1/4) -----


def test_module_never_imports_credit_models():
    """Structural guard: this module must never need to refit the
    LR/RF credit-decision models (only its own small diagnostic
    classifier, a completely separate model)."""
    import fairlend.audit.alpha_seed_sensitivity as module

    source = inspect.getsource(module)
    assert "credit_models" not in source
    assert "fairlend.models" not in source


# --- assert_frozen_predictions_unchanged (Phase 10 Sec. 4) --------------


def test_assert_frozen_predictions_unchanged_passes_when_identical():
    predictions = pd.DataFrame({"row_index": [1, 2, 3], "y_true": [1, 0, 1], "y_pred": [1, 1, 0]})
    canonical = predictions["y_pred"].to_numpy().copy()
    assert_frozen_predictions_unchanged(predictions, canonical, "logistic_regression")  # no raise


def test_assert_frozen_predictions_unchanged_raises_when_decision_vector_changed():
    predictions = pd.DataFrame({"row_index": [1, 2, 3], "y_true": [1, 0, 1], "y_pred": [1, 1, 0]})
    canonical = np.array([1, 0, 0])  # deliberately different
    with pytest.raises(AssertionError):
        assert_frozen_predictions_unchanged(predictions, canonical, "random_forest")


# --- compute_proxy_diagnostic (Phase 10 Sec. 6) -------------------------


def test_compute_proxy_diagnostic_recovers_a_strong_signal():
    rng = np.random.default_rng(0)
    n = 400
    x = rng.normal(size=n)
    y = (x > 0).astype(int)  # perfectly separable by construction
    X = pd.DataFrame({"feature": x})
    result = compute_proxy_diagnostic(X.iloc[:300], y[:300], X.iloc[300:], y[300:], random_state=0)
    assert result.roc_auc > 0.95
    assert result.n_train == 300
    assert result.n_test == 100


def test_compute_proxy_diagnostic_near_chance_for_unrelated_label():
    rng = np.random.default_rng(1)
    n = 400
    x = rng.normal(size=n)
    y = rng.integers(0, 2, size=n)  # independent of x
    X = pd.DataFrame({"feature": x})
    result = compute_proxy_diagnostic(X.iloc[:300], y[:300], X.iloc[300:], y[300:], random_state=0)
    assert 0.3 < result.roc_auc < 0.7  # near chance, generous bounds for a small sample


# --- compute_configuration_model_row (Phase 10 Sec. 7) -------------------


def _hand_built_frame():
    """19 male + 19 female TEST rows (mirrors the fixture's population
    shape), disjoint TRAIN/VALIDATION, with a known DP/EO by construction."""
    n_test = 20
    row_index = list(range(n_test))
    # 10 approved, 10 rejected; all resolved (y_true present) for simplicity.
    y_pred = [1] * 10 + [0] * 10
    y_true = [1] * 8 + [0] * 2 + [1] * 2 + [0] * 8
    frozen_predictions = pd.DataFrame({"row_index": row_index, "y_true": y_true, "y_pred": y_pred})
    # Perfectly balanced group split, independent of approval decision.
    synthetic_label = [0, 1] * 10
    synthetic_gender_frame = pd.DataFrame({"row_index": row_index, "synthetic_gender_label": synthetic_label})
    return frozen_predictions, synthetic_gender_frame, row_index


def test_compute_configuration_model_row_matches_hand_calculation():
    frozen_predictions, synthetic_gender_frame, row_index = _hand_built_frame()
    test_dp_index = pd.Index(row_index)
    test_eo_index = pd.Index(row_index)  # all resolved
    train_index = pd.Index(range(100, 110))
    validation_index = pd.Index(range(200, 205))
    proxy_result = compute_proxy_diagnostic(
        pd.DataFrame({"f": [0.0, 1.0]}), np.array([0, 1]), pd.DataFrame({"f": [0.0, 1.0]}), np.array([0, 1]), 0
    )

    row = compute_configuration_model_row(
        alpha1=0.7,
        seed=0,
        model_name="logistic_regression",
        tau=0.80,
        frozen_predictions=frozen_predictions,
        synthetic_gender_frame=synthetic_gender_frame,
        probability_female_full=np.full(len(row_index), 0.5),
        test_dp_index=test_dp_index,
        test_eo_index=test_eo_index,
        train_index=train_index,
        validation_index=validation_index,
        proxy_result=proxy_result,
    )

    assert isinstance(row, ConfigurationModelRow)
    assert row.female_n == 10 and row.male_n == 10
    assert row.female_fraction == pytest.approx(0.5)
    assert row.stats["C_m"] == 10 and row.stats["C_f"] == 10
    assert row.stats["A_m"] + row.stats["A_f"] == 10  # exactly 10 approvals total, by construction
    assert set(row.stats) == set(STAT_KEYS)


def test_compute_configuration_model_row_rejects_train_leakage():
    """Reuses fairlend.audit.aggregation.build_audit_frame's existing
    leakage guard -- documents that Phase 10's per-configuration
    computation never bypasses it."""
    frozen_predictions, synthetic_gender_frame, row_index = _hand_built_frame()
    proxy_result = compute_proxy_diagnostic(
        pd.DataFrame({"f": [0.0, 1.0]}), np.array([0, 1]), pd.DataFrame({"f": [0.0, 1.0]}), np.array([0, 1]), 0
    )
    with pytest.raises(ValueError):
        compute_configuration_model_row(
            alpha1=0.7,
            seed=0,
            model_name="logistic_regression",
            tau=0.80,
            frozen_predictions=frozen_predictions,
            synthetic_gender_frame=synthetic_gender_frame,
            probability_female_full=np.full(len(row_index), 0.5),
            test_dp_index=pd.Index(row_index),
            test_eo_index=pd.Index(row_index),
            train_index=pd.Index([0, 1]),  # overlaps TEST -- must raise
            validation_index=pd.Index(range(200, 205)),
            proxy_result=proxy_result,
        )


# --- row_to_flat_dict ----------------------------------------------------


def test_row_to_flat_dict_contains_all_required_columns():
    frozen_predictions, synthetic_gender_frame, row_index = _hand_built_frame()
    proxy_result = compute_proxy_diagnostic(
        pd.DataFrame({"f": [0.0, 1.0]}), np.array([0, 1]), pd.DataFrame({"f": [0.0, 1.0]}), np.array([0, 1]), 0
    )
    row = compute_configuration_model_row(
        alpha1=0.7, seed=0, model_name="logistic_regression", tau=0.80,
        frozen_predictions=frozen_predictions, synthetic_gender_frame=synthetic_gender_frame,
        probability_female_full=np.full(len(row_index), 0.5),
        test_dp_index=pd.Index(row_index), test_eo_index=pd.Index(row_index),
        train_index=pd.Index(range(100, 110)), validation_index=pd.Index(range(200, 205)),
        proxy_result=proxy_result,
    )
    flat = row_to_flat_dict(row, data_scope="real_lendingclub", dataset_sha256="abc123", threshold_policy="validation_balanced_accuracy_max")
    required = {
        "alpha1", "seed", "model", "tau", "approval_rate_overall", "female_n", "male_n",
        "female_fraction", "male_fraction", "mean_probability_female", "proxy_auc", "proxy_accuracy",
        *STAT_KEYS, "approval_rate_m", "approval_rate_f", "TPR_m", "TPR_f", "FPR_m", "FPR_f",
        "DP", "EO", "data_scope", "dataset_sha256", "threshold_policy",
    }
    assert required.issubset(flat.keys())


# --- summarise_runs (Phase 10 Sec. 9) ------------------------------------


def test_summarise_runs_row_count_for_standard_grid():
    alpha1_values = [0.0, 0.4, 0.7, 1.0, 1.3]
    seeds = list(range(10))
    rows = []
    for alpha1 in alpha1_values:
        for seed in seeds:
            for model in ("logistic_regression", "random_forest"):
                rows.append({"alpha1": alpha1, "seed": seed, "model": model,
                             "female_fraction": 0.5, "proxy_auc": 0.6, "DP": 0.01, "EO": 0.02})
    runs_df = pd.DataFrame(rows)
    summary = summarise_runs(runs_df)
    assert len(summary) == 10  # 5 alpha1 x 2 models


def test_summarise_runs_computes_correct_statistics():
    rows = [
        {"alpha1": 0.0, "seed": 0, "model": "logistic_regression", "female_fraction": 0.50, "proxy_auc": 0.50, "DP": 0.01, "EO": 0.02},
        {"alpha1": 0.0, "seed": 1, "model": "logistic_regression", "female_fraction": 0.51, "proxy_auc": 0.52, "DP": 0.03, "EO": 0.04},
    ]
    runs_df = pd.DataFrame(rows)
    summary = summarise_runs(runs_df).iloc[0]
    assert summary["DP_mean"] == pytest.approx(0.02)
    assert summary["DP_min"] == pytest.approx(0.01)
    assert summary["DP_max"] == pytest.approx(0.03)
    assert summary["EO_mean"] == pytest.approx(0.03)
    assert summary["female_fraction_mean"] == pytest.approx(0.505)


# --- pearson_correlation --------------------------------------------------


def test_pearson_correlation_perfect_positive_relationship():
    x = np.array([0.0, 0.4, 0.7, 1.0, 1.3])
    y = x * 2.0 + 1.0
    assert pearson_correlation(x, y) == pytest.approx(1.0)


def test_pearson_correlation_nan_for_zero_variance_input():
    x = np.array([0.7, 0.7, 0.7])
    y = np.array([0.1, 0.2, 0.3])
    assert np.isnan(pearson_correlation(x, y))
