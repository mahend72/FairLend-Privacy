"""Unit tests for the five manuscript proxy features (Sec. 6.1.1)."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from fairlend.data.proxy_features import (
    SOUTH_REGION_STATES,
    compute_train_emp_length_median,
    fit_proxy_preprocessor,
    fit_standardize_stats,
    fit_winsorize_bounds,
    home_ownership_indicator,
    parse_emp_length_years,
    south_region_indicator,
)


def test_parse_emp_length_special_cases():
    s = pd.Series(["< 1 year", "10+ years", "1 year", "5 years", "9 years"])
    parsed = parse_emp_length_years(s)
    assert list(parsed) == [0.5, 10.0, 1.0, 5.0, 9.0]


def test_parse_emp_length_missing_uses_supplied_median():
    s = pd.Series(["1 year", None, "3 years"])
    parsed = parse_emp_length_years(s, train_median=7.0)
    assert parsed.iloc[1] == 7.0


def test_compute_train_emp_length_median_ignores_missing():
    s = pd.Series(["1 year", "3 years", None, "5 years"])
    # non-missing parsed values: 1, 3, 5 -> median 3
    assert compute_train_emp_length_median(s) == 3.0


def test_home_ownership_indicator():
    s = pd.Series(["RENT", "OWN", "MORTGAGE", "OTHER", "NONE", "ANY"])
    result = home_ownership_indicator(s)
    assert list(result) == [0.0, 1.0, 1.0, 0.0, 0.0, 0.0]


@pytest.mark.parametrize(
    "state,expected",
    [
        ("TX", 1.0), ("FL", 1.0), ("GA", 1.0), ("MD", 1.0), ("DC", 1.0),
        ("CA", 0.0), ("NY", 0.0), ("WA", 0.0), ("IL", 0.0),
    ],
)
def test_south_region_indicator(state, expected):
    result = south_region_indicator(pd.Series([state]))
    assert result.iloc[0] == expected


def test_south_region_state_set_has_seventeen_states():
    # South Atlantic (9) + East South Central (4) + West South Central (4)
    assert len(SOUTH_REGION_STATES) == 17


def test_winsorize_bounds_fit_on_train_clip_outliers():
    train = pd.Series([1.0] + list(range(2, 99)) + [1000.0])  # 1st/99th pct extremes
    bounds = fit_winsorize_bounds(train, 1.0, 99.0)
    assert bounds.lower < bounds.upper
    assert bounds.lower > 1.0  # the extreme low outlier gets clipped away
    assert bounds.upper < 1000.0  # the extreme high outlier gets clipped away


def test_standardize_zero_std_raises():
    from fairlend.data.proxy_features import apply_standardize

    stats = fit_standardize_stats(pd.Series([5.0, 5.0, 5.0]))
    with pytest.raises(ValueError):
        apply_standardize(pd.Series([5.0]), stats)


def test_fit_proxy_preprocessor_produces_five_standardized_columns_and_z():
    df_train = pd.DataFrame(
        {
            "annual_inc": [30000, 50000, 70000, 90000, 110000, 40000, 60000, 80000],
            "emp_length": ["< 1 year", "1 year", "10+ years", "5 years", None,
                            "2 years", "3 years", "9 years"],
            "dti": [10.0, 15.0, 20.0, 25.0, 30.0, 12.0, 18.0, 22.0],
            "home_ownership": ["RENT", "OWN", "MORTGAGE", "RENT", "OWN",
                                "MORTGAGE", "OTHER", "RENT"],
            "addr_state": ["CA", "TX", "FL", "NY", "GA", "WA", "IL", "VA"],
        }
    )
    preprocessor = fit_proxy_preprocessor(
        df_train, winsorize_lower_percentile=1.0, winsorize_upper_percentile=99.0
    )
    transformed = preprocessor.transform(df_train)
    for col in (
        "log1p_annual_inc", "emp_length_years", "dti",
        "home_ownership_indicator", "south_region_indicator",
        "z", "z_standardized",
    ):
        assert col in transformed.columns
    # z_standardized on the TRAIN set it was fit on should be ~zero mean.
    assert abs(transformed["z_standardized"].mean()) < 1e-8


def test_preprocessor_applies_train_bounds_to_unseen_partition_without_refitting():
    df_train = pd.DataFrame(
        {
            "annual_inc": [30000, 50000, 70000, 90000, 110000, 40000, 60000, 80000, 100000, 45000],
            "emp_length": ["1 year", "2 years", "3 years", "< 1 year", "10+ years",
                            "5 years", "6 years", "7 years", "8 years", "4 years"],
            "dti": [10.0, 15.0, 20.0, 25.0, 30.0, 12.0, 18.0, 22.0, 16.0, 14.0],
            "home_ownership": ["RENT", "OWN", "MORTGAGE", "RENT", "OWN",
                                "MORTGAGE", "OTHER", "RENT", "OWN", "MORTGAGE"],
            "addr_state": ["CA", "TX", "FL", "NY", "GA", "WA", "IL", "VA", "OH", "AZ"],
        }
    )
    preprocessor = fit_proxy_preprocessor(
        df_train, winsorize_lower_percentile=1.0, winsorize_upper_percentile=99.0
    )
    # A held-out row with an extreme income far outside the TRAIN range.
    df_test = pd.DataFrame(
        {
            "annual_inc": [999_000_000.0],
            "emp_length": ["1 year"],
            "dti": [15.0],
            "home_ownership": ["RENT"],
            "addr_state": ["CA"],
        }
    )
    transformed_test = preprocessor.transform(df_test)
    # Winsorisation bound came from TRAIN; the test-set extreme value must
    # be clipped to that TRAIN-derived bound, not to a bound re-fit on the
    # test value itself (which would trivially not clip anything).
    bound = preprocessor.winsorize_bounds["log1p_annual_inc"].upper
    expected_standardized = (
        bound - preprocessor.standardize_stats["log1p_annual_inc"].mean
    ) / preprocessor.standardize_stats["log1p_annual_inc"].std
    assert transformed_test["log1p_annual_inc"].iloc[0] == pytest.approx(
        expected_standardized
    )
