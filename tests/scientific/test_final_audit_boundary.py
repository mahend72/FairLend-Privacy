"""End-to-end scientific invariant tests for the final audit-scope boundary
(manuscript Sec. 4.7, 4.8, 6.2.8): fairness statistics must be reported
only over the held-out TEST partition, never over TRAIN/VALIDATION
records used to fit or select the credit-decision model, and equalised
odds must never include an unresolved-outcome record.

Exercised end-to-end against tests/fixtures/lendingclub_sample.csv, since
the real LendingClub file is not available in this environment.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from fairlend.core.config import load_evaluation_config
from fairlend.data.audit_scope import compute_final_audit_populations
from fairlend.data.loader import load_raw_lendingclub
from fairlend.data.outcomes import map_repayment_outcome
from fairlend.data.populations import classify_outcome_populations
from fairlend.data.splitting import assign_full_population_split

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "lendingclub_sample.csv"
CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "evaluation.yaml"


@pytest.fixture()
def prepared():
    config = load_evaluation_config(CONFIG_PATH)
    df = load_raw_lendingclub(FIXTURE_PATH)
    df["fairlend_outcome"] = map_repayment_outcome(df["loan_status"], config.outcome_mapping)

    populations = classify_outcome_populations(df["fairlend_outcome"])
    split = assign_full_population_split(
        df,
        outcome_column="fairlend_outcome",
        train_fraction=config.dataset.train_fraction,
        validation_fraction=config.dataset.validation_fraction,
        test_fraction=config.dataset.test_fraction,
        seed=config.dataset.split_seed,
    )
    final = compute_final_audit_populations(df, split, populations)
    return df, populations, split, final


def test_every_record_has_exactly_one_split_assignment(prepared):
    df, _, split, _ = prepared
    split.assert_disjoint_and_complete(df.index)  # must not raise
    assigned = list(split.train_index) + list(split.validation_index) + list(split.test_index)
    assert len(assigned) == len(df)
    assert len(set(assigned)) == len(df)


def test_no_split_overlap_exists(prepared):
    _, _, split, _ = prepared
    train, validation, test = set(split.train_index), set(split.validation_index), set(split.test_index)
    assert train & validation == set()
    assert train & test == set()
    assert validation & test == set()


def test_final_dp_contains_no_train_or_validation_ids(prepared):
    _, _, split, final = prepared
    train_or_validation = set(split.train_index) | set(split.validation_index)
    assert train_or_validation.isdisjoint(set(final.test_dp_index))


def test_final_eo_contains_no_train_or_validation_ids(prepared):
    _, _, split, final = prepared
    train_or_validation = set(split.train_index) | set(split.validation_index)
    assert train_or_validation.isdisjoint(set(final.test_eo_index))


def test_unresolved_test_records_contribute_to_dp_only(prepared):
    df, populations, split, final = prepared
    unresolved_test = set(split.test_index) & set(populations.unresolved_outcome_index(df))
    assert len(unresolved_test) > 0  # sanity: fixture actually has such rows
    assert unresolved_test <= set(final.test_dp_index)
    assert unresolved_test.isdisjoint(set(final.test_eo_index))


def test_unresolved_records_never_enter_eo_anywhere(prepared):
    df, populations, split, final = prepared
    unresolved_index = set(populations.unresolved_outcome_index(df))
    assert unresolved_index.isdisjoint(set(final.test_eo_index))
    assert unresolved_index.isdisjoint(set(final.train_model_fit_index))
    assert unresolved_index.isdisjoint(set(final.validation_model_select_index))


def test_resolved_test_and_unresolved_test_partition_test_exactly(prepared):
    df, populations, split, final = prepared
    resolved_test = set(final.test_eo_index)
    unresolved_test = set(split.test_index) - resolved_test
    assert resolved_test | unresolved_test == set(split.test_index)
    assert resolved_test & unresolved_test == set()
    assert unresolved_test == set(split.test_index) & set(populations.unresolved_outcome_index(df))
