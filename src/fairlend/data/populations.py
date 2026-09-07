"""Explicit outcome-eligible population definitions.

Manuscript Sec. 4.7 / 4.8 / 6.8 distinguish two different uses of a record
in the audit, with two different data requirements:

  - Demographic parity (C_k, A_k) requires only the application's group
    membership and the LPU's approval decision Y-hat_i -- NOT the realised
    repayment outcome Y_i. Sec. 4.7: "Every valid application is included
    in the encrypted group total HE.C_k, regardless of whether the
    application is approved or rejected." Y-hat_i is a function of the
    (always-available) credit score s_i, never of Y_i.

  - Equalised odds (P_k, N_k, TP_k, FP_k) is explicitly retrospective and
    requires a realised repayment outcome: Sec. 4.8: "Equalised odds is a
    retrospective audit because it additionally requires observed
    repayment outcomes."

Supervised fitting (and held-out predictive evaluation) of the
credit-decision model likewise requires a realised outcome as the
training/evaluation label (Sec. 6.9-6.10) -- there is no label to fit
against, or score to validate, for a LendingClub record whose
``loan_status`` is still unresolved (e.g. "Current").

This module defines three explicit, documented population masks over the
cleaned dataset. It intentionally does NOT compute Y-hat_i, C_k, or A_k
itself -- that lives in ``fairlend.audit.aggregation`` (Phase 8), which
must accept an AUDIT_ELIGIBLE population that includes UNRESOLVED_OUTCOME
rows, and must require a non-null Y_i specifically wherever it computes
P_k/N_k/TP_k/FP_k.

    MODEL_ELIGIBLE      realised outcome (Y_i in {0, 1}). May enter
                        supervised model train/validation/test fitting
                        AND contributes to equalised odds' P_k/N_k/TP_k/FP_k.
    UNRESOLVED_OUTCOME  Y_i is unresolved (NA). Must NEVER enter supervised
                        model fitting or equalised-odds denominators.
    AUDIT_ELIGIBLE      the full cleaned population (MODEL_ELIGIBLE union
                        UNRESOLVED_OUTCOME).

Why AUDIT_ELIGIBLE is the full population, not just MODEL_ELIGIBLE:
restricting demographic-parity's audit population to MODEL_ELIGIBLE would
exclude valid applications for a reason the manuscript never states --
Sec. 4.7 explicitly rejects filtering C_k by the *decision* (approved vs.
rejected); nothing in the manuscript restricts C_k by outcome resolution
either, and doing so would arbitrarily undercount one side of a
demographic-parity comparison whenever the female/male split of
resolved-vs-unresolved outcomes is not itself balanced. This IS a design
decision made in this codebase (the manuscript's LendingClub description
does not spell it out record-by-record), documented here rather than left
implicit, per the review that requested this file.
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class OutcomePopulations:
    """Boolean masks (aligned to the input DataFrame's index) for the three
    populations. Constructing this is the ONLY sanctioned way downstream
    code should decide which rows may enter supervised model fitting vs.
    which rows are audit-only."""

    model_eligible: pd.Series
    unresolved_outcome: pd.Series

    def __post_init__(self) -> None:
        overlap = self.model_eligible & self.unresolved_outcome
        if overlap.any():
            raise ValueError(
                "model_eligible and unresolved_outcome must be mutually "
                f"exclusive; {int(overlap.sum())} row(s) were flagged as both."
            )

    @property
    def audit_eligible(self) -> pd.Series:
        """All True: see module docstring for why demographic-parity's
        audit population is the full cleaned dataset, not just
        model_eligible."""
        return pd.Series(True, index=self.model_eligible.index)

    def model_eligible_index(self, df: pd.DataFrame) -> pd.Index:
        return df.index[self.model_eligible.reindex(df.index, fill_value=False)]

    def unresolved_outcome_index(self, df: pd.DataFrame) -> pd.Index:
        return df.index[self.unresolved_outcome.reindex(df.index, fill_value=False)]

    def audit_eligible_index(self, df: pd.DataFrame) -> pd.Index:
        return df.index

    def counts(self) -> dict:
        return {
            "model_eligible": int(self.model_eligible.sum()),
            "unresolved_outcome": int(self.unresolved_outcome.sum()),
            "audit_eligible": int(self.audit_eligible.sum()),
        }


def classify_outcome_populations(outcome: pd.Series) -> OutcomePopulations:
    """Classify every row of ``outcome`` (an Int64 column with possible
    ``pandas.NA``, as produced by
    ``fairlend.data.outcomes.map_repayment_outcome``) into MODEL_ELIGIBLE
    vs. UNRESOLVED_OUTCOME.

    No status is ever silently mapped into MODEL_ELIGIBLE except a value
    that ``map_repayment_outcome`` already resolved to 0 or 1 -- this
    function performs no additional interpretation of raw ``loan_status``
    strings, only of the already-mapped Int64 outcome column, so there is
    exactly one place (``fairlend.data.outcomes``) where that judgement is
    made.
    """
    model_eligible = outcome.notna()
    unresolved_outcome = outcome.isna()
    return OutcomePopulations(
        model_eligible=model_eligible, unresolved_outcome=unresolved_outcome
    )


def select_model_eligible(df: pd.DataFrame, outcome_column: str) -> pd.DataFrame:
    """Return the subset of ``df`` eligible for supervised model
    train/validation/test fitting (realised outcome only).

    This is the ONLY function that should be used to produce the input to
    ``fairlend.data.splitting.stratified_train_validation_test_split`` when
    that split feeds a supervised credit-decision model -- see that
    function's own NA guard, which raises if called on data still
    containing unresolved outcomes, as a second, structural line of
    defence against this filter being skipped by accident.
    """
    populations = classify_outcome_populations(df[outcome_column])
    return df.loc[populations.model_eligible_index(df)]
