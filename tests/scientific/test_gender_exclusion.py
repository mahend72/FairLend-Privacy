"""Scientific invariant tests: the synthetic protected attribute must never
reach the credit-decision model's feature matrix, and equalised-odds-style
computation must never be fed an unresolved outcome (manuscript Sec.
6.1.1, 4.8).

These exercise the full pipeline end-to-end against the fixture, combining
fairlend.data.proxy_features, fairlend.data.synthetic_gender, and
fairlend.data.credit_features exactly as a Phase G model-fitting script
would have to.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from fairlend.core.config import load_evaluation_config
from fairlend.data.credit_features import (
    CREDIT_MODEL_FEATURES,
    assert_no_protected_columns,
    select_credit_model_features,
)
from fairlend.data.loader import load_raw_lendingclub
from fairlend.data.outcomes import map_repayment_outcome
from fairlend.data.populations import classify_outcome_populations, select_model_eligible
from fairlend.data.proxy_features import fit_proxy_preprocessor
from fairlend.data.synthetic_gender import generate_synthetic_gender

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "lendingclub_sample.csv"
CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "evaluation.yaml"


@pytest.fixture()
def full_pipeline_frame():
    """Build the same combined table a careless Phase G implementation
    might be tempted to slice X_credit out of: proxy features AND the
    synthetic-gender columns, side by side."""
    config = load_evaluation_config(CONFIG_PATH)
    df = load_raw_lendingclub(FIXTURE_PATH)
    df["fairlend_outcome"] = map_repayment_outcome(df["loan_status"], config.outcome_mapping)
    df_model_eligible = select_model_eligible(df, "fairlend_outcome")

    preprocessor = fit_proxy_preprocessor(
        df_model_eligible,
        winsorize_lower_percentile=config.synthetic_attribute.winsorize_lower_percentile,
        winsorize_upper_percentile=config.synthetic_attribute.winsorize_upper_percentile,
    )
    proxy = preprocessor.transform(df)
    gender_result = generate_synthetic_gender(
        proxy["z_standardized"].to_numpy(), alpha0=0.0, alpha1=0.7, seed=0
    )

    combined = proxy.copy()
    combined["probability_female"] = gender_result.probability_female
    combined["synthetic_gender_label"] = gender_result.label
    combined["synthetic_gender_one_hot_male"] = gender_result.one_hot[:, 0]
    combined["synthetic_gender_one_hot_female"] = gender_result.one_hot[:, 1]
    return combined


def test_full_combined_table_is_rejected_as_credit_features(full_pipeline_frame):
    """A DataFrame that mixes legitimate proxy features with synthetic-
    gender-derived columns must be rejected wholesale if passed straight
    to the credit-feature guard -- this is the failure mode Phase G's
    model-fitting code must never hit silently."""
    with pytest.raises(ValueError, match="protected-attribute"):
        assert_no_protected_columns(full_pipeline_frame.columns)


def test_select_credit_model_features_strips_gender_columns_from_combined_table(
    full_pipeline_frame,
):
    X_credit = select_credit_model_features(full_pipeline_frame)
    assert set(X_credit.columns) == CREDIT_MODEL_FEATURES
    for forbidden_column in (
        "probability_female",
        "synthetic_gender_label",
        "synthetic_gender_one_hot_male",
        "synthetic_gender_one_hot_female",
        "z",
        "z_standardized",
    ):
        assert forbidden_column not in X_credit.columns
    # The guard used internally must also independently pass on the result.
    assert_no_protected_columns(X_credit.columns)


def test_equalised_odds_style_computation_only_uses_resolved_outcomes(full_pipeline_frame):
    """Stand-in for the not-yet-implemented fairlend.audit.fairness: any
    per-record computation requiring realised Y (as EO's TPR/FPR do) must
    restrict to MODEL_ELIGIBLE rows, never UNRESOLVED_OUTCOME ones."""
    config = load_evaluation_config(CONFIG_PATH)
    df = load_raw_lendingclub(FIXTURE_PATH)
    df["fairlend_outcome"] = map_repayment_outcome(df["loan_status"], config.outcome_mapping)
    populations = classify_outcome_populations(df["fairlend_outcome"])

    eo_eligible_index = populations.model_eligible_index(df)
    assert df.loc[eo_eligible_index, "fairlend_outcome"].isna().sum() == 0
    # None of the unresolved rows may appear in the EO-eligible population.
    unresolved_index = populations.unresolved_outcome_index(df)
    assert set(unresolved_index).isdisjoint(set(eo_eligible_index))
