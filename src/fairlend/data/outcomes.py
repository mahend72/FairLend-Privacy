"""Realised repayment-outcome mapping.

Manuscript Sec. 6.8 (Table 1: Y_i): "Y_i = 1 if the loan has a satisfactory
repayment outcome, Y_i = 0 if the loan defaults or has another adverse
repayment outcome." The manuscript does not enumerate LendingClub
``loan_status`` strings; the concrete mapping used here lives in
``configs/evaluation.yaml`` (``outcome_mapping``) and is loaded via
``fairlend.core.config.load_evaluation_config`` -- it is an explicit,
documented instantiation of the manuscript's definition, not a
manuscript-specified table, and this module does not duplicate it as a
second hidden copy.

Values not listed under ``positive`` or ``negative`` map to ``pandas.NA``
(outcome unresolved/unknown), not to 0. This matters: silently treating an
unresolved "Current" loan as a negative outcome would fabricate adverse
events that have not occurred, while silently treating it as positive would
fabricate successful repayments that have not (yet) been observed. Records
with an unresolved outcome may still be valid *applications* for
demographic-parity purposes (C_k/A_k); see
``fairlend.audit.aggregation`` (Phase 8) for where that distinction is
enforced.
"""
from __future__ import annotations

import pandas as pd

from fairlend.core.config import OutcomeMappingConfig


def map_repayment_outcome(
    loan_status: pd.Series, mapping: OutcomeMappingConfig
) -> pd.Series:
    """Map raw ``loan_status`` strings to {1, 0, <NA>} per ``mapping``.

    Args:
        loan_status: Raw ``loan_status`` column.
        mapping: The positive/negative/excluded string lists from
            ``configs/evaluation.yaml``.

    Returns:
        A nullable ``Int64`` Series: 1 for positive outcomes, 0 for
        negative outcomes, ``pandas.NA`` for anything in ``excluded`` or
        not otherwise recognised. A value that is in neither list is
        treated the same as one explicitly listed as ``excluded`` -- an
        unrecognised status must never silently become a resolved
        outcome -- but callers should validate the configuration against
        the dataset's full ``value_counts()`` before running an
        experiment (see ``evaluation/prepare_lendingclub.py``), so unknown
        strings surface for review rather than accumulating unnoticed.
    """
    positive = set(mapping.positive)
    negative = set(mapping.negative)
    overlap = positive & negative
    if overlap:
        raise ValueError(
            "outcome_mapping.positive and outcome_mapping.negative overlap "
            f"on {sorted(overlap)!r}; a loan_status value cannot be both."
        )

    def _map_one(status: object) -> object:
        if status in positive:
            return 1
        if status in negative:
            return 0
        return pd.NA

    return loan_status.map(_map_one).astype("Int64")


def unmapped_statuses(
    loan_status: pd.Series, mapping: OutcomeMappingConfig
) -> pd.Series:
    """Report ``loan_status`` values present in the data but absent from
    ALL THREE of ``positive``/``negative``/``excluded`` in the config.

    A non-empty result means the configuration is incomplete for this
    dataset vintage and must be reviewed/extended before the mapping is
    trusted -- it does not mean those records are silently dropped (they
    already map to unresolved via ``map_repayment_outcome``), only that
    nobody has yet decided whether they belong in ``excluded`` or should
    be recognised as a positive/negative outcome under a different label
    string.
    """
    known = set(mapping.positive) | set(mapping.negative) | set(mapping.excluded)
    counts = loan_status.value_counts(dropna=False)
    return counts[~counts.index.isin(known)]
