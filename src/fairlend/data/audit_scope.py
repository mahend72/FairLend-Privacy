"""Final audit-scope computation: which records may legitimately appear in
model fitting, model/threshold selection, and the FINAL REPORTED
demographic-parity / equalised-odds statistics.

This module is where ``fairlend.data.splitting``'s partition assignment
(``DatasetSplit``, from ``assign_full_population_split``) and
``fairlend.data.populations``'s outcome-resolution classification
(``OutcomePopulations``) are combined. Neither module alone determines
what may be reported -- BOTH the partition (train/validation/test) AND the
outcome-resolution status (model_eligible/unresolved_outcome) must be
consulted together, which is exactly what ``compute_final_audit_populations``
does.

Design (interpreting the manuscript, since it does not spell this out
record-by-record for the LendingClub evaluation -- documented explicitly
here rather than silently choosing):

    TRAIN partition  AND model_eligible   -> may fit the credit-decision
                                             model (Sec. 6.9-6.10: model
                                             fitting needs a realised
                                             outcome as label).
    VALIDATION part. AND model_eligible   -> may be used for hyperparameter
                                             / diagnostic-threshold
                                             selection (Sec. 6.2.8; the
                                             same realised-outcome
                                             requirement applies).
    TEST partition, ALL rows              -> may contribute to
                                             demographic parity's C_k/A_k
                                             (Sec. 4.7: "Every valid
                                             application is included in
                                             ... HE.C_k, regardless of
                                             whether the application is
                                             approved or rejected" -- this
                                             does not depend on Y being
                                             resolved, only on a decision
                                             Y-hat_i being computable,
                                             which it is for every TEST
                                             row once the model is fit).
    TEST partition, model_eligible only   -> may contribute to equalised
                                             odds' P_k/N_k/TP_k/FP_k
                                             (Sec. 4.8: "Equalised odds is
                                             a retrospective audit because
                                             it additionally requires
                                             observed repayment outcomes.").

No TRAIN or VALIDATION row -- resolved or unresolved -- may ever appear in
either final reported population. This module's dataclass makes that
structurally checkable (``assert_no_train_or_validation_leakage``), and
every population it exposes is computed by set intersection against the
SAME ``DatasetSplit``, so there is no way for a TRAIN row to end up in
``test_dp_index`` short of the split itself being wrong (which
``DatasetSplit.assert_disjoint_and_complete`` already guards).
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from fairlend.data.populations import OutcomePopulations
from fairlend.data.splitting import DatasetSplit


@dataclass(frozen=True)
class FinalAuditPopulations:
    """The record sets legitimately usable at each stage of the pipeline,
    after intersecting the train/validation/test partition with
    outcome-resolution status.
    """

    train_model_fit_index: pd.Index
    validation_model_select_index: pd.Index
    test_dp_index: pd.Index
    test_eo_index: pd.Index

    def assert_no_train_or_validation_leakage(self, split: DatasetSplit) -> None:
        """Raise if any TRAIN or VALIDATION row appears in either final
        reported population (DP or EO)."""
        train_or_validation = set(split.train_index) | set(split.validation_index)
        dp_leak = train_or_validation & set(self.test_dp_index)
        if dp_leak:
            raise ValueError(
                f"{len(dp_leak)} train/validation record(s) leaked into the "
                "final demographic-parity population."
            )
        eo_leak = train_or_validation & set(self.test_eo_index)
        if eo_leak:
            raise ValueError(
                f"{len(eo_leak)} train/validation record(s) leaked into the "
                "final equalised-odds population."
            )

    def counts(self) -> dict:
        return {
            "train_model_fit": int(len(self.train_model_fit_index)),
            "validation_model_select": int(len(self.validation_model_select_index)),
            "test_dp": int(len(self.test_dp_index)),
            "test_eo": int(len(self.test_eo_index)),
        }


def compute_final_audit_populations(
    df: pd.DataFrame,
    split: DatasetSplit,
    outcome_populations: OutcomePopulations,
) -> FinalAuditPopulations:
    """Combine ``split`` (from ``assign_full_population_split``) with
    ``outcome_populations`` (from ``classify_outcome_populations``) into
    the four populations that may legitimately feed model fitting, model
    selection, and the two final fairness statistics.

    Args:
        df: The full cleaned (audit-eligible) DataFrame that both ``split``
            and ``outcome_populations`` were computed against.
        split: The SOURCE OF TRUTH partition, from
            ``fairlend.data.splitting.assign_full_population_split`` --
            NOT from ``stratified_train_validation_test_split`` run on a
            pre-filtered subset, which could assign a record to a
            different partition than this ``df``'s split did.
        outcome_populations: From
            ``fairlend.data.populations.classify_outcome_populations``.
    """
    model_eligible_index = outcome_populations.model_eligible_index(df)

    final = FinalAuditPopulations(
        train_model_fit_index=split.train_index.intersection(model_eligible_index),
        validation_model_select_index=split.validation_index.intersection(
            model_eligible_index
        ),
        test_dp_index=split.test_index,
        test_eo_index=split.test_index.intersection(model_eligible_index),
    )
    final.assert_no_train_or_validation_leakage(split)
    return final
