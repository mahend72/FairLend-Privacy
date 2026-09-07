"""Unit tests for fairlend.audit.aggregation: typed count structures,
hand-calculated counting, and the join/identity-integrity guard."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from fairlend.audit.aggregation import (
    GROUP_FEMALE,
    GROUP_MALE,
    GroupAuditCounts,
    build_audit_frame,
    compute_group_counts,
    compute_plaintext_audit,
)

# --- GroupAuditCounts structural invariants --------------------------------


def test_group_audit_counts_accepts_valid_values():
    counts = GroupAuditCounts(group=GROUP_MALE, C=10, A=4, P=5, TP=3, N=3, FP=1)
    assert counts.C == 10


def test_group_audit_counts_rejects_unknown_group():
    with pytest.raises(ValueError):
        GroupAuditCounts(group="nonbinary", C=1, A=0, P=0, TP=0, N=0, FP=0)


def test_group_audit_counts_rejects_a_greater_than_c():
    with pytest.raises(ValueError, match="A_k"):
        GroupAuditCounts(group=GROUP_MALE, C=5, A=6, P=0, TP=0, N=0, FP=0)


def test_group_audit_counts_rejects_tp_greater_than_p():
    with pytest.raises(ValueError, match="TP_k"):
        GroupAuditCounts(group=GROUP_MALE, C=5, A=2, P=2, TP=3, N=0, FP=0)


def test_group_audit_counts_rejects_fp_greater_than_n():
    with pytest.raises(ValueError, match="FP_k"):
        GroupAuditCounts(group=GROUP_MALE, C=5, A=2, P=0, TP=0, N=2, FP=3)


def test_group_audit_counts_rejects_negative_value():
    with pytest.raises(ValueError):
        GroupAuditCounts(group=GROUP_MALE, C=-1, A=0, P=0, TP=0, N=0, FP=0)


# --- compute_group_counts / compute_plaintext_audit: hand-calculated ------


def _toy_audit_frame() -> pd.DataFrame:
    """8 rows: 4 male, 4 female. 1 male and 1 female row are unresolved
    (y_true is NaN) -- they must contribute to C/A but not P/TP/N/FP.

    Male:   C=4, A=2 (rows 0,1 approved)
            resolved: rows 0,1,2 (row 3 unresolved)
              row0: y=1,pred=1 -> TP
              row1: y=0,pred=1 -> FP
              row2: y=1,pred=0 -> (P but not TP)
            P_m=2 (rows0,2), TP_m=1 (row0), N_m=1 (row1), FP_m=1 (row1)
    Female: C=4, A=3 (rows4,5,6 approved)
            resolved: rows 4,5,6 (row7 unresolved)
              row4: y=1,pred=1 -> TP
              row5: y=1,pred=1 -> TP
              row6: y=0,pred=1 -> FP
            P_f=2 (rows4,5), TP_f=2, N_f=1 (row6), FP_f=1 (row6)
    """
    return pd.DataFrame(
        {
            "row_index": list(range(8)),
            "group": [GROUP_MALE] * 4 + [GROUP_FEMALE] * 4,
            "y_true": [1, 0, 1, np.nan, 1, 1, 0, np.nan],
            "y_pred": [1, 1, 0, 0, 1, 1, 1, 0],
        }
    )


def test_compute_group_counts_male_matches_hand_calculation():
    frame = _toy_audit_frame()
    counts = compute_group_counts(frame, GROUP_MALE)
    assert counts.C == 4
    assert counts.A == 2
    assert counts.P == 2
    assert counts.TP == 1
    assert counts.N == 1
    assert counts.FP == 1


def test_compute_group_counts_female_matches_hand_calculation():
    frame = _toy_audit_frame()
    counts = compute_group_counts(frame, GROUP_FEMALE)
    assert counts.C == 4
    assert counts.A == 3
    assert counts.P == 2
    assert counts.TP == 2
    assert counts.N == 1
    assert counts.FP == 1


def test_compute_plaintext_audit_population_accounting():
    frame = _toy_audit_frame()
    result = compute_plaintext_audit(frame, model_name="toy_model")
    assert result.full_test_n == 8
    assert result.resolved_test_n == 6
    assert result.unresolved_test_n == 2
    result.assert_consistent()  # must not raise


def test_unresolved_rows_excluded_from_p_tp_n_fp_but_included_in_c():
    """Directly proves the core population rule: an unresolved row (y_true
    NaN) counts in C (and A if approved) but never in P/TP/N/FP."""
    frame = pd.DataFrame(
        {
            "row_index": [0, 1],
            "group": [GROUP_MALE, GROUP_MALE],
            "y_true": [np.nan, np.nan],
            "y_pred": [1, 0],
        }
    )
    counts = compute_group_counts(frame, GROUP_MALE)
    assert counts.C == 2
    assert counts.A == 1
    assert counts.P == 0
    assert counts.N == 0
    assert counts.TP == 0
    assert counts.FP == 0


def test_compute_group_counts_missing_column_raises():
    frame = pd.DataFrame({"row_index": [0], "group": [GROUP_MALE], "y_pred": [1]})
    with pytest.raises(ValueError, match="missing required column"):
        compute_group_counts(frame, GROUP_MALE)


# --- build_audit_frame: identity-integrity guard --------------------------


def _base_predictions() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "row_index": [10, 11, 12, 13],
            "y_true": [1.0, 0.0, np.nan, 1.0],
            "y_pred": [1, 0, 1, 1],
        }
    )


def _base_gender() -> pd.DataFrame:
    return pd.DataFrame(
        {"row_index": [10, 11, 12, 13], "synthetic_gender_label": [0, 1, 0, 1]}
    )


def test_build_audit_frame_succeeds_on_consistent_input():
    predictions = _base_predictions()
    gender = _base_gender()
    test_dp = pd.Index([10, 11, 12, 13])
    test_eo = pd.Index([10, 11, 13])  # row 12 is unresolved
    frame = build_audit_frame(
        predictions, gender, test_dp, test_eo, train_index=pd.Index([1, 2]), validation_index=pd.Index([3])
    )
    assert set(frame["group"]) == {GROUP_MALE, GROUP_FEMALE}
    assert len(frame) == 4


def test_build_audit_frame_rejects_duplicate_prediction_row_index():
    predictions = pd.concat([_base_predictions(), _base_predictions().iloc[[0]]], ignore_index=True)
    with pytest.raises(ValueError, match="duplicate row_index"):
        build_audit_frame(
            predictions, _base_gender(), pd.Index([10, 11, 12, 13]), pd.Index([10, 11, 13]),
            pd.Index([]), pd.Index([]),
        )


def test_build_audit_frame_rejects_prediction_outside_test_population():
    predictions = _base_predictions()
    with pytest.raises(ValueError, match="TEST"):
        build_audit_frame(
            predictions, _base_gender(), pd.Index([10, 11, 12]), pd.Index([10, 11]),
            pd.Index([]), pd.Index([]),
        )  # row 13 is a prediction outside the declared TEST population


def test_build_audit_frame_rejects_missing_test_row():
    predictions = _base_predictions()
    with pytest.raises(ValueError, match="TEST"):
        build_audit_frame(
            predictions, _base_gender(), pd.Index([10, 11, 12, 13, 99]), pd.Index([10, 11, 13]),
            pd.Index([]), pd.Index([]),
        )  # row 99 is in the declared TEST population but has no prediction


def test_build_audit_frame_rejects_train_validation_leakage():
    predictions = _base_predictions()
    with pytest.raises(ValueError, match="train/validation"):
        build_audit_frame(
            predictions, _base_gender(), pd.Index([10, 11, 12, 13]), pd.Index([10, 11, 13]),
            train_index=pd.Index([11]), validation_index=pd.Index([]),
        )


def test_build_audit_frame_rejects_missing_gender_assignment():
    predictions = _base_predictions()
    gender = _base_gender().iloc[:-1]  # drop row 13's assignment
    with pytest.raises(ValueError, match="protected-attribute assignment"):
        build_audit_frame(
            predictions, gender, pd.Index([10, 11, 12, 13]), pd.Index([10, 11, 13]),
            pd.Index([]), pd.Index([]),
        )


def test_build_audit_frame_rejects_duplicate_gender_assignment():
    gender = pd.concat([_base_gender(), _base_gender().iloc[[0]]], ignore_index=True)
    with pytest.raises(ValueError, match="duplicate row_index"):
        build_audit_frame(
            _base_predictions(), gender, pd.Index([10, 11, 12, 13]), pd.Index([10, 11, 13]),
            pd.Index([]), pd.Index([]),
        )


def test_build_audit_frame_rejects_test_eo_disagreement_with_y_true():
    predictions = _base_predictions()  # row 12's y_true is NaN (unresolved)
    with pytest.raises(ValueError, match="disagree"):
        build_audit_frame(
            predictions, _base_gender(), pd.Index([10, 11, 12, 13]),
            test_eo_index=pd.Index([10, 11, 12, 13]),  # falsely claims row 12 is resolved
            train_index=pd.Index([]), validation_index=pd.Index([]),
        )
