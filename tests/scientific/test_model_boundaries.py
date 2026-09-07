"""Scientific invariant tests for the credit-decision models (Phase G):

  - the synthetic protected attribute cannot enter the credit-model
    feature matrix, even via the full combined proxy+gender table;
  - TRAIN is the only population used for fitting, VALIDATION the only
    population used for hyperparameter/threshold selection, and TEST
    predictions never feed back into fitting or selection;
  - the saved TEST predictions are deterministic given a fixed
    random_state, so both the plaintext and (future) encrypted audit can
    consume the identical, fixed prediction vector.

These exercise the full pipeline end-to-end against the fixture, exactly
as evaluation/train_credit_models.py does.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from fairlend.core.config import load_evaluation_config
from fairlend.data.audit_scope import compute_final_audit_populations
from fairlend.data.loader import load_raw_lendingclub
from fairlend.data.outcomes import map_repayment_outcome
from fairlend.data.populations import classify_outcome_populations
from fairlend.data.proxy_features import compute_train_emp_length_median, fit_proxy_preprocessor
from fairlend.data.splitting import assign_full_population_split
from fairlend.data.synthetic_gender import generate_synthetic_gender
from fairlend.models.credit_models import (
    build_feature_frame,
    select_best_logistic_regression,
    select_best_random_forest,
    select_decision_threshold,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "lendingclub_sample.csv"
CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "evaluation.yaml"
OUTCOME_COLUMN = "fairlend_outcome"


@pytest.fixture()
def prepared():
    config = load_evaluation_config(CONFIG_PATH)
    df = load_raw_lendingclub(FIXTURE_PATH)
    df[OUTCOME_COLUMN] = map_repayment_outcome(df["loan_status"], config.outcome_mapping)
    populations = classify_outcome_populations(df[OUTCOME_COLUMN])
    split = assign_full_population_split(
        df,
        outcome_column=OUTCOME_COLUMN,
        train_fraction=config.dataset.train_fraction,
        validation_fraction=config.dataset.validation_fraction,
        test_fraction=config.dataset.test_fraction,
        seed=config.dataset.split_seed,
    )
    final = compute_final_audit_populations(df, split, populations)

    df_train = df.loc[final.train_model_fit_index]
    df_validation = df.loc[final.validation_model_select_index]
    df_test = df.loc[split.test_index]  # ALL test rows: resolved + unresolved

    emp_length_train_median = compute_train_emp_length_median(df_train["emp_length"])
    X_train = build_feature_frame(df_train, emp_length_train_median)
    X_validation = build_feature_frame(df_validation, emp_length_train_median)
    X_test = build_feature_frame(df_test, emp_length_train_median)
    y_train = df_train[OUTCOME_COLUMN].astype(int).to_numpy()
    y_validation = df_validation[OUTCOME_COLUMN].astype(int).to_numpy()

    return {
        "config": config,
        "df": df,
        "split": split,
        "final": final,
        "df_train": df_train,
        "df_validation": df_validation,
        "df_test": df_test,
        "X_train": X_train,
        "X_validation": X_validation,
        "X_test": X_test,
        "y_train": y_train,
        "y_validation": y_validation,
        "emp_length_train_median": emp_length_train_median,
    }


def _combined_frame_with_gender(prepared) -> pd.DataFrame:
    """The same kind of combined table tests/scientific/test_gender_exclusion.py
    builds: legitimate proxy features side by side with synthetic-gender
    columns -- the exact shape a careless caller might slice X_credit from."""
    config = prepared["config"]
    df = prepared["df"]
    preprocessor = fit_proxy_preprocessor(
        prepared["df_train"],
        winsorize_lower_percentile=config.synthetic_attribute.winsorize_lower_percentile,
        winsorize_upper_percentile=config.synthetic_attribute.winsorize_upper_percentile,
    )
    proxy = preprocessor.transform(df)
    gender = generate_synthetic_gender(
        proxy["z_standardized"].to_numpy(), alpha0=0.0, alpha1=0.7, seed=0
    )
    combined = build_feature_frame(prepared["df_train"], prepared["emp_length_train_median"])
    combined["synthetic_gender_label"] = gender.label[: len(combined)]
    combined["probability_female"] = gender.probability_female[: len(combined)]
    return combined


# --- Protected-attribute exclusion ---------------------------------------


def test_synthetic_gender_cannot_enter_training_via_combined_table(prepared):
    tainted_X_train = _combined_frame_with_gender(prepared)
    with pytest.raises(ValueError, match="protected-attribute"):
        select_best_logistic_regression(
            tainted_X_train,
            prepared["y_train"],
            prepared["X_validation"],
            prepared["y_validation"],
            random_state=0,
        )


def test_random_forest_also_rejects_synthetic_gender_in_training(prepared):
    tainted_X_train = _combined_frame_with_gender(prepared)
    with pytest.raises(ValueError, match="protected-attribute"):
        select_best_random_forest(
            tainted_X_train,
            prepared["y_train"],
            prepared["X_validation"],
            prepared["y_validation"],
            random_state=0,
        )


def test_clean_feature_frames_contain_no_protected_columns(prepared):
    forbidden_substrings = ("gender", "female", "male", "protected_attribute", "sex")
    for X in (prepared["X_train"], prepared["X_validation"], prepared["X_test"]):
        for column in X.columns:
            assert not any(bad in column.lower() for bad in forbidden_substrings)


# --- Train/validation/test boundary enforcement ---------------------------


def test_train_and_validation_populations_are_disjoint_and_resolved(prepared):
    train_ids = set(prepared["final"].train_model_fit_index)
    validation_ids = set(prepared["final"].validation_model_select_index)
    assert train_ids.isdisjoint(validation_ids)
    assert prepared["df_train"][OUTCOME_COLUMN].isna().sum() == 0
    assert prepared["df_validation"][OUTCOME_COLUMN].isna().sum() == 0


def test_fitting_on_train_plus_validation_changes_the_fitted_model(prepared):
    """Proves select_best_logistic_regression actually fits on exactly the
    X_train/y_train it is given -- not silently on a larger population --
    by showing that folding VALIDATION into the training data changes the
    fitted coefficients. If this ever failed (identical coefficients), it
    would mean training was not respecting the TRAIN-only boundary."""
    model_train_only = select_best_logistic_regression(
        prepared["X_train"],
        prepared["y_train"],
        prepared["X_validation"],
        prepared["y_validation"],
        random_state=0,
        C_grid=(1.0,),
    )
    X_train_plus_val = pd.concat([prepared["X_train"], prepared["X_validation"]], ignore_index=True)
    y_train_plus_val = np.concatenate([prepared["y_train"], prepared["y_validation"]])
    model_train_plus_val = select_best_logistic_regression(
        X_train_plus_val,
        y_train_plus_val,
        prepared["X_validation"],
        prepared["y_validation"],
        random_state=0,
        C_grid=(1.0,),
    )
    coef_a = model_train_only.estimator.named_steps["clf"].coef_
    coef_b = model_train_plus_val.estimator.named_steps["clf"].coef_
    assert not np.allclose(coef_a, coef_b)


def test_selection_functions_have_no_test_data_parameter(prepared):
    """Structural guard: the hyperparameter/threshold-selection API surface
    must not even have a place to pass TEST data, so a future caller
    cannot accidentally tune on TEST."""
    for fn in (select_best_logistic_regression, select_best_random_forest, select_decision_threshold):
        params = set(inspect.signature(fn).parameters)
        assert not any("test" in name.lower() for name in params)


def test_threshold_selected_only_from_validation_arguments(prepared):
    """select_decision_threshold's output must depend only on the
    (y_true, proba) it is given -- swapping in different VALIDATION-shaped
    data changes the result, proving there is no hidden dependency on
    TEST or a fixed constant."""
    y_a = np.array([0, 0, 1, 1])
    proba_a = np.array([0.2, 0.3, 0.7, 0.8])
    y_b = np.array([0, 0, 1, 1])
    proba_b = np.array([0.4, 0.9, 0.1, 0.6])  # deliberately mis-ranked
    threshold_a, f1_a = select_decision_threshold(y_a, proba_a)
    threshold_b, f1_b = select_decision_threshold(y_b, proba_b)
    assert f1_a == 1.0
    assert f1_b < 1.0
    assert threshold_a != threshold_b or f1_a != f1_b


# --- Determinism / reusability of the saved TEST predictions --------------


def test_predictions_are_bit_identical_across_two_fits_with_same_seed(prepared):
    """The artifact both the plaintext and encrypted audit will consume
    must be deterministic: refitting from scratch with the same
    random_state must reproduce identical TEST predictions."""
    model_a = select_best_logistic_regression(
        prepared["X_train"],
        prepared["y_train"],
        prepared["X_validation"],
        prepared["y_validation"],
        random_state=0,
    )
    model_b = select_best_logistic_regression(
        prepared["X_train"],
        prepared["y_train"],
        prepared["X_validation"],
        prepared["y_validation"],
        random_state=0,
    )
    proba_a = model_a.predict_probability(prepared["X_test"])
    proba_b = model_b.predict_probability(prepared["X_test"])
    decision_a = model_a.predict_decision(prepared["X_test"])
    decision_b = model_b.predict_decision(prepared["X_test"])
    assert np.array_equal(proba_a, proba_b)
    assert np.array_equal(decision_a, decision_b)
    assert model_a.threshold == model_b.threshold


def test_random_forest_predictions_are_bit_identical_across_two_fits(prepared):
    model_a = select_best_random_forest(
        prepared["X_train"],
        prepared["y_train"],
        prepared["X_validation"],
        prepared["y_validation"],
        random_state=0,
    )
    model_b = select_best_random_forest(
        prepared["X_train"],
        prepared["y_train"],
        prepared["X_validation"],
        prepared["y_validation"],
        random_state=0,
    )
    proba_a = model_a.predict_probability(prepared["X_test"])
    proba_b = model_b.predict_probability(prepared["X_test"])
    assert np.array_equal(proba_a, proba_b)


def test_test_predictions_cover_every_test_row_including_unresolved_outcome(prepared):
    """Y-hat_i must be computable for every TEST row regardless of
    outcome resolution (manuscript Sec. 4.7) -- prediction only requires
    X_i, never Y_i."""
    model = select_best_logistic_regression(
        prepared["X_train"],
        prepared["y_train"],
        prepared["X_validation"],
        prepared["y_validation"],
        random_state=0,
    )
    decisions = model.predict_decision(prepared["X_test"])
    assert len(decisions) == len(prepared["df_test"])
    assert prepared["df_test"][OUTCOME_COLUMN].isna().any()  # fixture has unresolved TEST rows
