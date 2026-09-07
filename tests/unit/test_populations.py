"""Unit tests for MODEL_ELIGIBLE / UNRESOLVED_OUTCOME / AUDIT_ELIGIBLE
population classification (manuscript Sec. 4.7, 4.8, 6.8)."""
from __future__ import annotations

import pandas as pd
import pytest

from fairlend.data.populations import (
    OutcomePopulations,
    classify_outcome_populations,
    select_model_eligible,
)


def _outcome_series() -> pd.Series:
    # 3 positive, 2 negative, 4 unresolved
    return pd.array([1, 1, 1, 0, 0, pd.NA, pd.NA, pd.NA, pd.NA], dtype="Int64")


def test_model_eligible_is_exactly_resolved_rows():
    outcome = pd.Series(_outcome_series())
    populations = classify_outcome_populations(outcome)
    assert populations.model_eligible.sum() == 5
    assert populations.unresolved_outcome.sum() == 4


def test_audit_eligible_is_the_full_population():
    outcome = pd.Series(_outcome_series())
    populations = classify_outcome_populations(outcome)
    assert populations.audit_eligible.sum() == len(outcome)
    assert populations.audit_eligible.all()


def test_counts_sum_correctly():
    outcome = pd.Series(_outcome_series())
    populations = classify_outcome_populations(outcome)
    counts = populations.counts()
    assert counts["model_eligible"] == 5
    assert counts["unresolved_outcome"] == 4
    assert counts["audit_eligible"] == 9
    assert counts["model_eligible"] + counts["unresolved_outcome"] == counts["audit_eligible"]


def test_model_eligible_and_unresolved_are_mutually_exclusive_by_construction():
    model_eligible = pd.Series([True, True])
    unresolved = pd.Series([True, False])  # overlaps on row 0
    with pytest.raises(ValueError):
        OutcomePopulations(model_eligible=model_eligible, unresolved_outcome=unresolved)


def test_no_unresolved_status_is_silently_counted_as_positive_or_negative():
    """A row with NA outcome must appear in unresolved_outcome, never in
    model_eligible -- i.e. classification never "resolves" an NA."""
    outcome = pd.Series(pd.array([1, 0, pd.NA], dtype="Int64"))
    populations = classify_outcome_populations(outcome)
    na_row_index = outcome.index[outcome.isna()]
    assert populations.model_eligible.loc[na_row_index].sum() == 0
    assert populations.unresolved_outcome.loc[na_row_index].all()


def test_select_model_eligible_excludes_unresolved_rows():
    df = pd.DataFrame({"fairlend_outcome": _outcome_series(), "x": range(9)})
    model_eligible_df = select_model_eligible(df, "fairlend_outcome")
    assert len(model_eligible_df) == 5
    assert model_eligible_df["fairlend_outcome"].isna().sum() == 0


def test_select_model_eligible_never_returns_unresolved_row_indices():
    df = pd.DataFrame({"fairlend_outcome": _outcome_series(), "x": range(9)})
    unresolved_indices = set(df.index[df["fairlend_outcome"].isna()])
    model_eligible_df = select_model_eligible(df, "fairlend_outcome")
    assert unresolved_indices.isdisjoint(set(model_eligible_df.index))
