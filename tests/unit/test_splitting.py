"""Unit tests for the leakage-safe train/validation/test split.

This split is for SUPERVISED MODEL FITTING and must only ever operate on
the MODEL_ELIGIBLE population (resolved outcomes) -- see
fairlend.data.populations. It structurally refuses input containing an
unresolved outcome; retention of unresolved rows for auditing purposes is
tested separately in tests/unit/test_populations.py.
"""
from __future__ import annotations

import pandas as pd
import pytest

from fairlend.data.splitting import (
    assign_full_population_split,
    stratified_train_validation_test_split,
)


def _make_resolved_df(n: int) -> pd.DataFrame:
    """A MODEL_ELIGIBLE fixture: every row has a resolved (0/1) outcome."""
    outcomes = ([1] * (n // 2)) + ([0] * (n - n // 2))
    return pd.DataFrame({"fairlend_outcome": pd.array(outcomes, dtype="Int64")})


def _make_mixed_df(n: int) -> pd.DataFrame:
    """A mixed AUDIT_ELIGIBLE fixture: some rows resolved, some unresolved."""
    third = n // 3
    outcomes = ([1] * third) + ([0] * third) + ([pd.NA] * (n - 2 * third))
    return pd.DataFrame({"fairlend_outcome": pd.array(outcomes, dtype="Int64")})


def test_split_fractions_approximately_match_request():
    df = _make_resolved_df(3000)
    split = stratified_train_validation_test_split(
        df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=42
    )
    total = len(df)
    assert abs(len(split.train_index) / total - 0.70) < 0.02
    assert abs(len(split.validation_index) / total - 0.10) < 0.02
    assert abs(len(split.test_index) / total - 0.20) < 0.02


def test_split_partitions_are_disjoint_and_complete():
    df = _make_resolved_df(900)
    split = stratified_train_validation_test_split(
        df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=1
    )
    split.assert_disjoint_and_complete(df.index)  # must not raise


def test_split_overlap_detected_by_guard():
    df = _make_resolved_df(300)
    split = stratified_train_validation_test_split(
        df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=1
    )
    tampered = split.__class__(
        train_index=split.train_index,
        validation_index=split.validation_index.append(split.train_index[:1]),
        test_index=split.test_index,
    )
    with pytest.raises(ValueError):
        tampered.assert_disjoint_and_complete(df.index)


def test_split_is_reproducible_given_same_seed():
    df = _make_resolved_df(600)
    split_a = stratified_train_validation_test_split(
        df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=7
    )
    split_b = stratified_train_validation_test_split(
        df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=7
    )
    assert list(split_a.train_index) == list(split_b.train_index)
    assert list(split_a.validation_index) == list(split_b.validation_index)
    assert list(split_a.test_index) == list(split_b.test_index)


def test_fractions_must_sum_to_one():
    df = _make_resolved_df(100)
    with pytest.raises(ValueError):
        stratified_train_validation_test_split(
            df, "fairlend_outcome", 0.70, 0.10, 0.10, seed=1
        )


def test_unresolved_outcome_rows_are_structurally_rejected():
    """The core correction: a split intended for supervised model fitting
    must refuse (not silently accommodate) any row lacking a realised
    outcome."""
    df = _make_resolved_df(300)
    df.loc[df.index[:5], "fairlend_outcome"] = pd.NA
    with pytest.raises(ValueError, match="unresolved"):
        stratified_train_validation_test_split(
            df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=1
        )


# --- assign_full_population_split (the source-of-truth audit partition) --


def test_full_population_split_covers_every_row_including_unresolved():
    df = _make_mixed_df(900)
    split = assign_full_population_split(
        df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=1
    )
    split.assert_disjoint_and_complete(df.index)  # must not raise, over ALL rows


def test_full_population_split_every_row_has_exactly_one_partition():
    df = _make_mixed_df(600)
    split = assign_full_population_split(
        df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=3
    )
    all_assigned = list(split.train_index) + list(split.validation_index) + list(split.test_index)
    assert len(all_assigned) == len(df)
    assert len(set(all_assigned)) == len(df)  # no duplicates -> exactly one each


def test_full_population_split_preserves_unresolved_rows_in_each_partition_proportionally():
    """Because unresolved rows form their own stratum, they should appear
    in all three partitions roughly at the requested 70/10/20 proportions,
    not be concentrated in (or absent from) any one partition."""
    df = _make_mixed_df(3000)
    split = assign_full_population_split(
        df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=1
    )
    unresolved_mask = df["fairlend_outcome"].isna()
    n_unresolved = unresolved_mask.sum()
    unresolved_in_train = df.loc[split.train_index, "fairlend_outcome"].isna().sum()
    assert abs(unresolved_in_train / n_unresolved - 0.70) < 0.05


def test_full_population_split_is_reproducible():
    df = _make_mixed_df(600)
    split_a = assign_full_population_split(df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=9)
    split_b = assign_full_population_split(df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=9)
    assert list(split_a.train_index) == list(split_b.train_index)
    assert list(split_a.validation_index) == list(split_b.validation_index)
    assert list(split_a.test_index) == list(split_b.test_index)


def test_full_population_split_resolved_only_dataset_still_works():
    """Sanity: assign_full_population_split must also work correctly when
    there happen to be no unresolved rows at all."""
    df = _make_resolved_df(300)
    split = assign_full_population_split(df, "fairlend_outcome", 0.70, 0.10, 0.20, seed=1)
    split.assert_disjoint_and_complete(df.index)
