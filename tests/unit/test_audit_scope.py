"""Unit tests for fairlend.data.audit_scope: combining the train/
validation/test partition with outcome-resolution status into the final
model-fitting / model-selection / DP / EO populations."""
from __future__ import annotations

import pandas as pd
import pytest

from fairlend.data.audit_scope import compute_final_audit_populations
from fairlend.data.populations import classify_outcome_populations
from fairlend.data.splitting import DatasetSplit


def _make_df() -> pd.DataFrame:
    # 12 rows: indices 0-11.
    # TRAIN = 0..5 (6 rows: 4 resolved, 2 unresolved)
    # VALIDATION = 6..7 (2 rows: 1 resolved, 1 unresolved)
    # TEST = 8..11 (4 rows: 2 resolved, 2 unresolved)
    outcomes = [1, 0, 1, 0, pd.NA, pd.NA,  # train
                1, pd.NA,                  # validation
                1, 0, pd.NA, pd.NA]        # test
    return pd.DataFrame({"fairlend_outcome": pd.array(outcomes, dtype="Int64")})


def _make_split(df: pd.DataFrame) -> DatasetSplit:
    return DatasetSplit(
        train_index=df.index[0:6],
        validation_index=df.index[6:8],
        test_index=df.index[8:12],
    )


def test_train_model_fit_excludes_unresolved_train_rows():
    df = _make_df()
    split = _make_split(df)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    final = compute_final_audit_populations(df, split, populations)
    assert len(final.train_model_fit_index) == 4  # rows 0-3 only
    assert set(final.train_model_fit_index) == set(df.index[0:4])


def test_validation_model_select_excludes_unresolved_validation_rows():
    df = _make_df()
    split = _make_split(df)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    final = compute_final_audit_populations(df, split, populations)
    assert len(final.validation_model_select_index) == 1
    assert set(final.validation_model_select_index) == {df.index[6]}


def test_test_dp_index_includes_all_test_rows_resolved_and_unresolved():
    df = _make_df()
    split = _make_split(df)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    final = compute_final_audit_populations(df, split, populations)
    assert set(final.test_dp_index) == set(split.test_index)
    assert len(final.test_dp_index) == 4


def test_test_eo_index_excludes_unresolved_test_rows():
    df = _make_df()
    split = _make_split(df)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    final = compute_final_audit_populations(df, split, populations)
    assert len(final.test_eo_index) == 2  # rows 8, 9 only
    assert set(final.test_eo_index) == set(df.index[8:10])


def test_unresolved_test_rows_are_in_dp_but_not_eo():
    df = _make_df()
    split = _make_split(df)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    final = compute_final_audit_populations(df, split, populations)
    unresolved_test_rows = set(df.index[10:12])
    assert unresolved_test_rows <= set(final.test_dp_index)
    assert unresolved_test_rows.isdisjoint(set(final.test_eo_index))


def test_no_train_or_validation_row_in_either_final_population():
    df = _make_df()
    split = _make_split(df)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    final = compute_final_audit_populations(df, split, populations)
    train_or_validation = set(split.train_index) | set(split.validation_index)
    assert train_or_validation.isdisjoint(set(final.test_dp_index))
    assert train_or_validation.isdisjoint(set(final.test_eo_index))


def test_assert_no_leakage_raises_when_tampered():
    df = _make_df()
    split = _make_split(df)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    final = compute_final_audit_populations(df, split, populations)
    # Tamper: inject a train row into the DP population.
    tampered = final.__class__(
        train_model_fit_index=final.train_model_fit_index,
        validation_model_select_index=final.validation_model_select_index,
        test_dp_index=final.test_dp_index.append(split.train_index[:1]),
        test_eo_index=final.test_eo_index,
    )
    with pytest.raises(ValueError):
        tampered.assert_no_train_or_validation_leakage(split)


def test_counts_are_consistent():
    df = _make_df()
    split = _make_split(df)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    final = compute_final_audit_populations(df, split, populations)
    counts = final.counts()
    assert counts["train_model_fit"] == 4
    assert counts["validation_model_select"] == 1
    assert counts["test_dp"] == 4
    assert counts["test_eo"] == 2
