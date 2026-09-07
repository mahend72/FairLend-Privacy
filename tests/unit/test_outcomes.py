"""Unit tests for realised repayment-outcome mapping."""
from __future__ import annotations

import pandas as pd
import pytest

from fairlend.core.config import OutcomeMappingConfig
from fairlend.data.outcomes import map_repayment_outcome, unmapped_statuses

MAPPING = OutcomeMappingConfig(
    positive=["Fully Paid", "Does not meet the credit policy. Status:Fully Paid"],
    negative=["Charged Off", "Default", "Does not meet the credit policy. Status:Charged Off"],
    excluded=["Current", "In Grace Period", "Late (16-30 days)", "Late (31-120 days)", "Issued"],
)


def test_positive_statuses_map_to_one():
    s = pd.Series(["Fully Paid", "Does not meet the credit policy. Status:Fully Paid"])
    result = map_repayment_outcome(s, MAPPING)
    assert list(result) == [1, 1]


def test_negative_statuses_map_to_zero():
    s = pd.Series(["Charged Off", "Default", "Does not meet the credit policy. Status:Charged Off"])
    result = map_repayment_outcome(s, MAPPING)
    assert list(result) == [0, 0, 0]


def test_excluded_statuses_map_to_na():
    s = pd.Series(["Current", "In Grace Period", "Late (16-30 days)"])
    result = map_repayment_outcome(s, MAPPING)
    assert result.isna().all()


def test_unrecognised_status_maps_to_na_not_zero():
    """An unrecognised loan_status must not be silently treated as a
    negative (default) outcome."""
    s = pd.Series(["Some Unexpected New Status"])
    result = map_repayment_outcome(s, MAPPING)
    assert result.isna().all()


def test_overlap_between_positive_and_negative_is_rejected():
    bad_mapping = OutcomeMappingConfig(
        positive=["Fully Paid", "X"],
        negative=["X", "Charged Off"],
        excluded=[],
    )
    with pytest.raises(ValueError):
        map_repayment_outcome(pd.Series(["Fully Paid"]), bad_mapping)


def test_unmapped_statuses_reports_unknown_values():
    s = pd.Series(["Fully Paid", "Totally New Status", "Charged Off"])
    unmapped = unmapped_statuses(s, MAPPING)
    assert "Totally New Status" in unmapped.index
    assert "Fully Paid" not in unmapped.index
