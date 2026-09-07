"""Five-component proxy-feature construction for synthetic protected-attribute
generation (manuscript Sec. 6.1.1).

The manuscript's proxy-feature set is exactly:

    1. log(1 + annual_inc)
    2. emp_length_years
    3. dti
    4. I[home_ownership in {OWN, MORTGAGE}]
    5. I[addr_state in US Census South region]

with continuous variables winsorised at the 1st/99th percentiles (fit on
TRAIN only) before standardisation, employment-length strings converted to
numeric years ("<1 year" -> 0.5, "10+ years" -> 10, missing -> TRAIN
median), all five components standardised using TRAIN mean/std, combined
with the equal unit-normalised weight vector w = (1,1,1,1,1)/sqrt(5), and
the resulting proxy score z_i itself standardised using TRAIN mean/std.

Every fitted statistic in this module (winsorisation bounds, standardisation
mean/std, the employment-length imputation median, and the z-score
mean/std) must be fit on the TRAIN partition only and then applied
unchanged to validation/test -- see ``fit_proxy_preprocessor`` /
``ProxyFeaturePreprocessor.transform``, which is the only place these
statistics are computed, and the leakage-safety tests in
``tests/scientific/test_no_leakage.py``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional

import numpy as np
import pandas as pd

# US Census Bureau South region (South Atlantic + East South Central + West
# South Central divisions). LendingClub's `addr_state` includes DC, which
# the Census Bureau's South Atlantic division also includes.
SOUTH_REGION_STATES = frozenset(
    {
        # South Atlantic
        "DE", "MD", "DC", "VA", "WV", "NC", "SC", "GA", "FL",
        # East South Central
        "KY", "TN", "MS", "AL",
        # West South Central
        "AR", "LA", "OK", "TX",
    }
)

HOME_OWNERSHIP_POSITIVE = frozenset({"OWN", "MORTGAGE"})

PROXY_FEATURE_NAMES = (
    "log1p_annual_inc",
    "emp_length_years",
    "dti",
    "home_ownership_indicator",
    "south_region_indicator",
)

# w = (1,1,1,1,1) / sqrt(5)
PROXY_WEIGHT = 1.0 / np.sqrt(5.0)

_EMP_LENGTH_YEAR_PATTERN = re.compile(r"(\d+)")


def parse_emp_length_years(
    emp_length: pd.Series, train_median: Optional[float] = None
) -> pd.Series:
    """Convert raw LendingClub ``emp_length`` strings to numeric years.

    "< 1 year" -> 0.5, "10+ years" -> 10, "n year(s)" -> n. Missing values
    are imputed with ``train_median`` if provided (this must be the median
    computed on the TRAIN partition via
    ``compute_train_emp_length_median`` -- never the median of the split
    currently being transformed); if ``train_median`` is None, missing
    values are left as NaN (used internally to compute that median itself
    from TRAIN data without circularity).
    """

    def _parse_one(value: object) -> Optional[float]:
        if pd.isna(value):
            return train_median
        text = str(value).strip()
        if text.startswith("<"):
            return 0.5
        if text.startswith("10+"):
            return 10.0
        match = _EMP_LENGTH_YEAR_PATTERN.search(text)
        if match:
            return float(match.group(1))
        return train_median

    return emp_length.map(_parse_one).astype(float)


def compute_train_emp_length_median(emp_length_train: pd.Series) -> float:
    """Median of the numerically-parsed (non-missing) TRAIN employment
    lengths, used to impute missing values in ALL partitions."""
    parsed = parse_emp_length_years(emp_length_train, train_median=None)
    return float(parsed.median(skipna=True))


def home_ownership_indicator(home_ownership: pd.Series) -> pd.Series:
    """I[home_ownership in {OWN, MORTGAGE}]. All other values (RENT, OTHER,
    NONE, ANY, missing) map to 0."""
    return home_ownership.isin(HOME_OWNERSHIP_POSITIVE).astype(float)


def south_region_indicator(addr_state: pd.Series) -> pd.Series:
    """I[addr_state in US Census South region] (see SOUTH_REGION_STATES)."""
    return addr_state.isin(SOUTH_REGION_STATES).astype(float)


@dataclass(frozen=True)
class WinsorizeBounds:
    lower: float
    upper: float


def fit_winsorize_bounds(
    x: pd.Series, lower_percentile: float, upper_percentile: float
) -> WinsorizeBounds:
    lower = float(np.nanpercentile(x, lower_percentile))
    upper = float(np.nanpercentile(x, upper_percentile))
    return WinsorizeBounds(lower=lower, upper=upper)


def apply_winsorize(x: pd.Series, bounds: WinsorizeBounds) -> pd.Series:
    return x.clip(lower=bounds.lower, upper=bounds.upper)


@dataclass(frozen=True)
class StandardizeStats:
    mean: float
    std: float


def fit_standardize_stats(x: pd.Series) -> StandardizeStats:
    return StandardizeStats(mean=float(x.mean()), std=float(x.std(ddof=0)))


def apply_standardize(x: pd.Series, stats: StandardizeStats) -> pd.Series:
    if stats.std == 0:
        raise ValueError(
            "Cannot standardise a feature with zero training-set standard "
            "deviation (division by zero); check the TRAIN partition for "
            "this feature."
        )
    return (x - stats.mean) / stats.std


def _raw_proxy_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute the five raw (pre-winsorisation, pre-standardisation) proxy
    components from a raw LendingClub-schema DataFrame. Employment-length
    missing-value imputation is NOT applied here (that requires the TRAIN
    median, supplied only via ``ProxyFeaturePreprocessor``)."""
    return pd.DataFrame(
        {
            "log1p_annual_inc": np.log1p(df["annual_inc"].astype(float)),
            "emp_length_years": parse_emp_length_years(
                df["emp_length"], train_median=None
            ),
            "dti": df["dti"].astype(float),
            "home_ownership_indicator": home_ownership_indicator(
                df["home_ownership"]
            ),
            "south_region_indicator": south_region_indicator(df["addr_state"]),
        },
        index=df.index,
    )


@dataclass(frozen=True)
class ProxyFeaturePreprocessor:
    """All statistics fit on TRAIN, ready to transform any partition
    (train, validation, or test) without ever re-fitting on that
    partition's own data."""

    emp_length_train_median: float
    winsorize_bounds: Dict[str, WinsorizeBounds]
    standardize_stats: Dict[str, StandardizeStats]
    z_standardize_stats: StandardizeStats

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply the fitted preprocessing to ``df`` and return a DataFrame
        with the five standardised proxy components plus the combined
        proxy score columns ``z`` (pre-standardisation) and
        ``z_standardized`` (manuscript's z_i)."""
        raw = _raw_proxy_features(df)
        raw["emp_length_years"] = parse_emp_length_years(
            df["emp_length"], train_median=self.emp_length_train_median
        )

        standardized = pd.DataFrame(index=df.index)
        for name in PROXY_FEATURE_NAMES:
            column = raw[name]
            if name in self.winsorize_bounds:
                column = apply_winsorize(column, self.winsorize_bounds[name])
            standardized[name] = apply_standardize(
                column, self.standardize_stats[name]
            )

        z = PROXY_WEIGHT * standardized[list(PROXY_FEATURE_NAMES)].sum(axis=1)
        z_standardized = apply_standardize(z, self.z_standardize_stats)

        result = standardized.copy()
        result["z"] = z
        result["z_standardized"] = z_standardized
        return result


# Continuous components that are winsorised before standardisation. The two
# binary indicators are standardised directly (manuscript: "All five proxy
# components are standardised ..."; winsorisation is stated only for
# "Continuous variables").
_CONTINUOUS_PROXY_FEATURES = ("log1p_annual_inc", "emp_length_years", "dti")


def raw_credit_features(df: pd.DataFrame, emp_length_train_median: float) -> pd.DataFrame:
    """The five ``fairlend.data.credit_features.CREDIT_MODEL_FEATURES``
    columns, RAW -- no winsorisation, no standardisation.

    These are ordinary credit-relevant financial features (income, DTI,
    employment length, home ownership, region) used as direct
    credit-decision-model inputs (Phase G), which is a different purpose
    from ``ProxyFeaturePreprocessor.transform()`` (winsorised/standardised,
    combined into the synthetic-gender proxy score ``z``). The only fitted
    statistic either use shares is the TRAIN employment-length median
    imputation value -- passed in explicitly here rather than re-fit, so a
    caller cannot accidentally impute credit-model features from a
    different partition's median than the one used for model fitting.
    """
    raw = _raw_proxy_features(df)
    raw["emp_length_years"] = parse_emp_length_years(
        df["emp_length"], train_median=emp_length_train_median
    )
    return raw[list(PROXY_FEATURE_NAMES)]


def fit_proxy_preprocessor(
    df_train: pd.DataFrame,
    winsorize_lower_percentile: float,
    winsorize_upper_percentile: float,
) -> ProxyFeaturePreprocessor:
    """Fit all proxy-feature preprocessing statistics on ``df_train`` ONLY.

    Args:
        df_train: The TRAIN partition, with raw LendingClub columns
            ``annual_inc``, ``emp_length``, ``dti``, ``home_ownership``,
            ``addr_state``.
        winsorize_lower_percentile / winsorize_upper_percentile: e.g. 1.0
            and 99.0 (manuscript: "winsorised at the first and
            ninety-ninth percentiles").
    """
    emp_length_train_median = compute_train_emp_length_median(
        df_train["emp_length"]
    )

    raw_train = _raw_proxy_features(df_train)
    raw_train["emp_length_years"] = parse_emp_length_years(
        df_train["emp_length"], train_median=emp_length_train_median
    )

    winsorize_bounds: Dict[str, WinsorizeBounds] = {}
    for name in _CONTINUOUS_PROXY_FEATURES:
        winsorize_bounds[name] = fit_winsorize_bounds(
            raw_train[name], winsorize_lower_percentile, winsorize_upper_percentile
        )

    standardize_stats: Dict[str, StandardizeStats] = {}
    for name in PROXY_FEATURE_NAMES:
        column = raw_train[name]
        if name in winsorize_bounds:
            column = apply_winsorize(column, winsorize_bounds[name])
        standardize_stats[name] = fit_standardize_stats(column)

    standardized_train = pd.DataFrame(
        {
            name: apply_standardize(
                apply_winsorize(raw_train[name], winsorize_bounds[name])
                if name in winsorize_bounds
                else raw_train[name],
                standardize_stats[name],
            )
            for name in PROXY_FEATURE_NAMES
        }
    )
    z_train = PROXY_WEIGHT * standardized_train.sum(axis=1)
    z_standardize_stats = fit_standardize_stats(z_train)

    return ProxyFeaturePreprocessor(
        emp_length_train_median=emp_length_train_median,
        winsorize_bounds=winsorize_bounds,
        standardize_stats=standardize_stats,
        z_standardize_stats=z_standardize_stats,
    )
