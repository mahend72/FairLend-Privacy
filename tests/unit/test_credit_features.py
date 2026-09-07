"""Unit tests for the credit-model feature allowlist / protected-attribute
exclusion guard (manuscript Sec. 6.1.1: synthetic gender "not used by the
credit-scoring model")."""
from __future__ import annotations

import pandas as pd
import pytest

from fairlend.data.credit_features import (
    CREDIT_MODEL_FEATURES,
    FORBIDDEN_FEATURE_SUBSTRINGS,
    assert_no_protected_columns,
    select_credit_model_features,
)


def test_allowlist_and_denylist_are_disjoint():
    for feature in CREDIT_MODEL_FEATURES:
        for bad in FORBIDDEN_FEATURE_SUBSTRINGS:
            assert bad not in feature.lower()


def test_exact_allowlist_passes():
    assert_no_protected_columns(CREDIT_MODEL_FEATURES)  # must not raise


@pytest.mark.parametrize(
    "column_name",
    [
        "gender",
        "synthetic_gender",
        "synthetic_gender_label",
        "protected_attribute",
        "probability_female",
        "gender_one_hot",
        "synthetic_gender_one_hot_male",
        "synthetic_gender_one_hot_female",
        "male_indicator",
        "female_indicator",
        "sex",
    ],
)
def test_gender_related_columns_are_rejected(column_name):
    with pytest.raises(ValueError, match="protected-attribute"):
        assert_no_protected_columns(list(CREDIT_MODEL_FEATURES) + [column_name])


def test_unexpected_non_gender_column_is_rejected_with_allowlist_message():
    with pytest.raises(ValueError, match="allowlist"):
        assert_no_protected_columns(list(CREDIT_MODEL_FEATURES) + ["some_unrelated_column"])


def test_missing_expected_feature_is_rejected():
    incomplete = list(CREDIT_MODEL_FEATURES)[:-1]
    with pytest.raises(ValueError):
        assert_no_protected_columns(incomplete)


def test_proxy_transform_output_cannot_be_used_directly_as_credit_features():
    """The proxy-feature preprocessor's transform() output includes z/
    z_standardized columns not in CREDIT_MODEL_FEATURES -- passing it
    straight through must be rejected, forcing an explicit selection step."""
    proxy_transform_columns = list(CREDIT_MODEL_FEATURES) + ["z", "z_standardized"]
    with pytest.raises(ValueError, match="allowlist"):
        assert_no_protected_columns(proxy_transform_columns)


def test_synthetic_gender_output_columns_are_all_rejected():
    """Every column name actually produced by
    evaluation/generate_synthetic_gender.py's output table must be
    rejected as a credit-model feature."""
    synthetic_gender_columns = [
        "probability_female",
        "synthetic_gender_label",
        "synthetic_gender_one_hot_male",
        "synthetic_gender_one_hot_female",
    ]
    for column in synthetic_gender_columns:
        with pytest.raises(ValueError, match="protected-attribute"):
            assert_no_protected_columns(list(CREDIT_MODEL_FEATURES) + [column])


def test_select_credit_model_features_returns_only_allowlisted_columns():
    df = pd.DataFrame(
        {
            "log1p_annual_inc": [1.0, 2.0],
            "emp_length_years": [1.0, 5.0],
            "dti": [10.0, 20.0],
            "home_ownership_indicator": [0.0, 1.0],
            "south_region_indicator": [1.0, 0.0],
            "synthetic_gender_label": [1, 0],  # must be dropped, not passed through
            "probability_female": [0.6, 0.4],  # must be dropped, not passed through
        }
    )
    X = select_credit_model_features(df)
    assert set(X.columns) == CREDIT_MODEL_FEATURES
    assert "synthetic_gender_label" not in X.columns
    assert "probability_female" not in X.columns


def test_select_credit_model_features_raises_if_missing_required_column():
    df = pd.DataFrame({"log1p_annual_inc": [1.0]})
    with pytest.raises(ValueError):
        select_credit_model_features(df)
