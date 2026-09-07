"""Explicit credit-decision-model feature allowlist and protected-attribute
exclusion guard.

Manuscript Sec. 6.1.1: "These synthetic labels are not used by the
credit-scoring model; they are used only for FairLend's encrypted gender
matching and fairness auditing." This module is the single place that
names which columns the credit-decision model (Phase G -- logistic
regression / random forest -- not yet implemented) is allowed to consume,
and provides a structural guard, ``assert_no_protected_columns``, that
Phase G's model-fitting code MUST call before any ``model.fit(X, y)`` /
``model.predict(X)``.

This guard is being built now, before the model itself, so the invariant
is enforced by construction the moment Phase G lands rather than
retrofitted after the fact -- and so it can be tested immediately.

``CREDIT_MODEL_FEATURES`` is PROVISIONAL: it currently lists only the
real-valued/indicator features already computable at this checkpoint (the
same underlying raw fields used to construct the proxy score, which is
legitimate -- income/DTI/employment-length/home-ownership/region are
ordinary credit-relevant financial features in their own right; reusing
them as proxy-construction inputs does not make them protected). It will
be extended, not silently replaced, when Phase G adds further
LendingClub-specific risk features (e.g. grade, revol_util, fico range).
"""
from __future__ import annotations

from typing import FrozenSet, Iterable, Tuple

import pandas as pd

CREDIT_MODEL_FEATURES: FrozenSet[str] = frozenset(
    {
        "log1p_annual_inc",
        "emp_length_years",
        "dti",
        "home_ownership_indicator",
        "south_region_indicator",
    }
)

# Any column name containing one of these (case-insensitive) substrings is
# forbidden as a credit-model feature. Checked separately from, and before,
# the allowlist comparison so that a protected-attribute-related column
# always fails with a specific, actionable message rather than a generic
# "unexpected column" message.
FORBIDDEN_FEATURE_SUBSTRINGS: Tuple[str, ...] = (
    "gender",
    "protected_attribute",
    "probability_female",
    "female",
    "male",
    "sex",
    "g_i",
)


def _validate_allowlist_disjoint_from_forbidden() -> None:
    for feature in CREDIT_MODEL_FEATURES:
        lowered = feature.lower()
        for bad in FORBIDDEN_FEATURE_SUBSTRINGS:
            if bad in lowered:
                raise AssertionError(
                    f"CREDIT_MODEL_FEATURES entry {feature!r} contains the "
                    f"forbidden substring {bad!r}; the allowlist and the "
                    "denylist must never overlap."
                )


_validate_allowlist_disjoint_from_forbidden()


def assert_no_protected_columns(feature_columns: Iterable[str]) -> None:
    """Raise ``ValueError`` if any name in ``feature_columns`` matches a
    forbidden substring, or the column set does not exactly equal
    ``CREDIT_MODEL_FEATURES``.

    Call this immediately before any credit-decision model
    ``.fit(X, y)`` / ``.predict(X)`` call.
    """
    columns = list(feature_columns)

    violations = [
        c
        for c in columns
        if any(bad in c.lower() for bad in FORBIDDEN_FEATURE_SUBSTRINGS)
    ]
    if violations:
        raise ValueError(
            "Refusing to use protected-attribute-related column(s) as "
            f"credit-model features: {sorted(violations)!r}. The synthetic "
            "protected attribute (and anything derived from it) must never "
            "be a credit-decision model input (manuscript Sec. 6.1.1)."
        )

    column_set = set(columns)
    unexpected = column_set - CREDIT_MODEL_FEATURES
    if unexpected:
        raise ValueError(
            "Credit-model feature columns do not match the explicit "
            f"CREDIT_MODEL_FEATURES allowlist. Unexpected columns: "
            f"{sorted(unexpected)!r}. If this is a deliberate feature-set "
            "extension (e.g. Phase G adding LendingClub-specific risk "
            "features), update CREDIT_MODEL_FEATURES explicitly rather "
            "than silently passing a different column set."
        )
    missing = CREDIT_MODEL_FEATURES - column_set
    if missing:
        raise ValueError(
            "Credit-model feature columns are missing expected members of "
            f"CREDIT_MODEL_FEATURES: {sorted(missing)!r}."
        )


def select_credit_model_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return exactly the ``CREDIT_MODEL_FEATURES`` columns of ``df`` as
    the credit-decision model's ``X``, after validating that none of
    ``df``'s OTHER columns leaking into this call would even be possible
    (this function only ever reads the allowlisted names, so a caller
    cannot accidentally pass through a protected column by including it
    in ``df`` -- but callers should still prefer
    ``assert_no_protected_columns(df.columns)`` at the call site for a
    clear, early failure over a silent narrowing).
    """
    missing = CREDIT_MODEL_FEATURES - set(df.columns)
    if missing:
        raise ValueError(
            f"Input DataFrame is missing required feature columns: "
            f"{sorted(missing)!r}."
        )
    ordered_columns = sorted(CREDIT_MODEL_FEATURES)
    X = df[ordered_columns]
    assert_no_protected_columns(X.columns)
    return X
