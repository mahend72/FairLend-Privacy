"""Train/validation/test partitioning, stratified by repayment outcome
(manuscript Sec. 6.1.4/6.2.8: "70% training, 10% validation, and 20% test
sets, stratified by the repayment-outcome label").

This module provides TWO split functions with different scopes, and it
matters which one a caller uses:

``assign_full_population_split`` is the SOURCE OF TRUTH partition for the
whole pipeline: it assigns a train/validation/test label to EVERY row of
the cleaned dataset -- resolved-outcome AND unresolved-outcome rows alike
-- using a single stratified split (unresolved rows form their own
stratum). Because every row gets exactly one label from exactly one split
call, the same physical record can never simultaneously be assigned to
TRAIN for model-fitting purposes and to TEST for the final held-out audit
-- which would otherwise silently leak a training record into a reported
fairness statistic. Downstream code (``fairlend.data.audit_scope``)
intersects this partition with MODEL_ELIGIBLE (``fairlend.data.populations``)
to decide which TRAIN/VALIDATION rows may actually be used for model
fitting/selection, and which TEST rows may contribute to demographic
parity vs. equalised odds.

``stratified_train_validation_test_split`` is a narrower utility retained
for callers that already hold a resolved-outcome-only DataFrame in hand
(e.g. a future cross-validation routine) and want the same structural
guarantee in isolation: it raises ``ValueError`` if given any unresolved
(``pandas.NA``) outcome value, rather than silently giving such rows their
own stratum. It is NOT used by the top-level data-preparation pipeline
(``evaluation/split_dataset.py``) precisely because running it
independently from ``assign_full_population_split`` would risk assigning
the same record to different partitions under the two calls.
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from sklearn.model_selection import train_test_split


def _stratum_label(value: object) -> str:
    if pd.isna(value):
        return "unresolved"
    return f"outcome_{int(value)}"


def _two_stage_stratified_split(
    index: pd.Index,
    strata: "pd.Series",
    train_fraction: float,
    validation_fraction: float,
    test_fraction: float,
    seed: int,
) -> "DatasetSplit":
    total = train_fraction + validation_fraction + test_fraction
    if abs(total - 1.0) > 1e-9:
        raise ValueError(
            f"train_fraction + validation_fraction + test_fraction must "
            f"sum to 1.0, got {total}"
        )

    strata_array = strata.to_numpy()
    rest_fraction = validation_fraction + test_fraction
    train_index, rest_index, _, strata_rest = train_test_split(
        index.to_numpy(),
        strata_array,
        test_size=rest_fraction,
        random_state=seed,
        stratify=strata_array,
    )

    test_share_of_rest = test_fraction / rest_fraction
    validation_index, test_index = train_test_split(
        rest_index,
        test_size=test_share_of_rest,
        random_state=seed,
        stratify=strata_rest,
    )

    split = DatasetSplit(
        train_index=pd.Index(train_index),
        validation_index=pd.Index(validation_index),
        test_index=pd.Index(test_index),
    )
    split.assert_disjoint_and_complete(index)
    return split


@dataclass(frozen=True)
class DatasetSplit:
    """Row-index partitions. Indices are into the ORIGINAL DataFrame's
    index (``df.index``), not positional, so callers can safely
    ``df.loc[split.train_index]`` regardless of how ``df`` was indexed."""

    train_index: pd.Index
    validation_index: pd.Index
    test_index: pd.Index

    def assert_disjoint_and_complete(self, full_index: pd.Index) -> None:
        """Raise if the three partitions overlap or do not exactly
        reconstruct ``full_index``. Used by tests and by scripts as a
        cheap runtime guard against accidental leakage."""
        train, val, test = (
            set(self.train_index),
            set(self.validation_index),
            set(self.test_index),
        )
        if train & val:
            raise ValueError("train/validation index overlap detected")
        if train & test:
            raise ValueError("train/test index overlap detected")
        if val & test:
            raise ValueError("validation/test index overlap detected")
        union = train | val | test
        if union != set(full_index):
            raise ValueError(
                "train+validation+test does not exactly reconstruct the "
                "full dataset index (missing or extra rows)"
            )


def stratified_train_validation_test_split(
    df: pd.DataFrame,
    outcome_column: str,
    train_fraction: float,
    validation_fraction: float,
    test_fraction: float,
    seed: int,
) -> DatasetSplit:
    """Split ``df`` into train/validation/test, stratified by
    ``df[outcome_column]`` (an Int64 column that must contain ONLY
    resolved values, 0 or 1 -- see module docstring).

    Implemented as two successive stratified splits (train vs. rest, then
    validation vs. test out of "rest") using a single fixed ``seed``, so
    the full three-way partition is reproducible from that one seed alone.

    Raises:
        ValueError: if ``df[outcome_column]`` contains any unresolved
            (``pandas.NA``) value. This is a structural guard, not just a
            documentation note: it is impossible to obtain a
            model-fitting split that includes an unresolved-outcome row
            through this function.
    """
    outcome = df[outcome_column]
    if outcome.isna().any():
        n_unresolved = int(outcome.isna().sum())
        raise ValueError(
            f"{n_unresolved} row(s) have an unresolved outcome (NA) in "
            f"'{outcome_column}'. This function produces a split for "
            "SUPERVISED MODEL FITTING and must only ever be called on the "
            "MODEL_ELIGIBLE population -- filter with "
            "fairlend.data.populations.select_model_eligible(df, "
            f"'{outcome_column}') first."
        )

    strata = outcome.astype(int).astype(str)
    return _two_stage_stratified_split(
        df.index, strata, train_fraction, validation_fraction, test_fraction, seed
    )


def assign_full_population_split(
    df: pd.DataFrame,
    outcome_column: str,
    train_fraction: float,
    validation_fraction: float,
    test_fraction: float,
    seed: int,
) -> DatasetSplit:
    """Assign a train/validation/test partition label to EVERY row of
    ``df`` -- resolved-outcome rows AND unresolved-outcome rows alike.

    This is the SOURCE OF TRUTH partition for the pipeline (see module
    docstring): call this ONCE per dataset preparation run, then derive
    model-fitting/selection/audit sub-populations from its result via
    ``fairlend.data.audit_scope.compute_final_audit_populations`` --
    never call ``stratified_train_validation_test_split`` on a
    model-eligible subset independently, which could assign the same
    physical record to a different partition than this function would.

    Unresolved-outcome rows are stratified under their own label
    ("unresolved") alongside the resolved 0/1 labels, so their
    train/validation/test proportions are preserved too, without ever
    treating an unresolved row as though it had a resolved outcome.
    """
    strata = df[outcome_column].map(_stratum_label)
    return _two_stage_stratified_split(
        df.index, strata, train_fraction, validation_fraction, test_fraction, seed
    )
