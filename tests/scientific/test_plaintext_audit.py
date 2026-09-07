"""Scientific invariant tests for the plaintext fairness audit, exercised
end-to-end against the fixture: ingestion -> split -> model fitting (via
fairlend.models.credit_models, exactly as Phase 1's script does) ->
synthetic gender -> join -> plaintext aggregation -> DP/EO.

Hand-calculated DP/EO correctness, zero-denominator handling, and k_min
release-status behaviour are covered in tests/unit/test_fairness.py; this
file focuses on the population-boundary invariants that only show up once
real TRAIN/VALIDATION/TEST/resolved/unresolved populations and two
independently-fit models are involved.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from fairlend.audit.aggregation import (
    GROUP_FEMALE,
    GROUP_MALE,
    build_audit_frame,
    compute_plaintext_audit,
)
from fairlend.audit.fairness import compute_demographic_parity, compute_equalised_odds
from fairlend.core.config import load_evaluation_config
from fairlend.data.audit_scope import compute_final_audit_populations
from fairlend.data.loader import load_raw_lendingclub
from fairlend.data.outcomes import map_repayment_outcome
from fairlend.data.populations import classify_outcome_populations
from fairlend.data.proxy_features import compute_train_emp_length_median, fit_proxy_preprocessor
from fairlend.data.splitting import assign_full_population_split
from fairlend.data.synthetic_gender import generate_synthetic_gender
from fairlend.models.credit_models import (
    RANDOM_FOREST,
    LOGISTIC_REGRESSION,
    build_feature_frame,
    select_best_logistic_regression,
    select_best_random_forest,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "lendingclub_sample.csv"
CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "evaluation.yaml"
OUTCOME_COLUMN = "fairlend_outcome"


@pytest.fixture(scope="module")
def pipeline():
    config = load_evaluation_config(CONFIG_PATH)
    df = load_raw_lendingclub(FIXTURE_PATH)
    df[OUTCOME_COLUMN] = map_repayment_outcome(df["loan_status"], config.outcome_mapping)
    populations = classify_outcome_populations(df[OUTCOME_COLUMN])
    split = assign_full_population_split(
        df,
        outcome_column=OUTCOME_COLUMN,
        train_fraction=config.dataset.train_fraction,
        validation_fraction=config.dataset.validation_fraction,
        test_fraction=config.dataset.test_fraction,
        seed=config.dataset.split_seed,
    )
    final = compute_final_audit_populations(df, split, populations)

    df_train = df.loc[final.train_model_fit_index]
    df_validation = df.loc[final.validation_model_select_index]
    df_test = df.loc[split.test_index]

    emp_length_train_median = compute_train_emp_length_median(df_train["emp_length"])
    X_train = build_feature_frame(df_train, emp_length_train_median)
    X_validation = build_feature_frame(df_validation, emp_length_train_median)
    X_test = build_feature_frame(df_test, emp_length_train_median)
    y_train = df_train[OUTCOME_COLUMN].astype(int).to_numpy()
    y_validation = df_validation[OUTCOME_COLUMN].astype(int).to_numpy()

    lr_model = select_best_logistic_regression(X_train, y_train, X_validation, y_validation, random_state=0)
    rf_model = select_best_random_forest(X_train, y_train, X_validation, y_validation, random_state=0)

    def _predictions_for(model, model_name) -> pd.DataFrame:
        proba = model.predict_probability(X_test)
        return pd.DataFrame(
            {
                "row_index": df_test.index,
                "y_true": df_test[OUTCOME_COLUMN].to_numpy(),
                "y_proba": proba,
                "y_pred": model.predict_decision(X_test),
                "model": model_name,
            }
        )

    predictions = pd.concat(
        [_predictions_for(lr_model, LOGISTIC_REGRESSION), _predictions_for(rf_model, RANDOM_FOREST)],
        ignore_index=True,
    )

    proxy_preprocessor = fit_proxy_preprocessor(
        df_train,
        winsorize_lower_percentile=config.synthetic_attribute.winsorize_lower_percentile,
        winsorize_upper_percentile=config.synthetic_attribute.winsorize_upper_percentile,
    )
    z = proxy_preprocessor.transform(df)["z_standardized"].to_numpy()
    gender_result = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=0)
    synthetic_gender = pd.DataFrame(
        {"row_index": df.index, "synthetic_gender_label": gender_result.label}
    )

    return {
        "split": split,
        "final": final,
        "df_test": df_test,
        "predictions": predictions,
        "synthetic_gender": synthetic_gender,
    }


def _audit_for_model(pipeline, model_name: str):
    preds = pipeline["predictions"]
    model_predictions = preds[preds["model"] == model_name]
    frame = build_audit_frame(
        model_predictions,
        pipeline["synthetic_gender"],
        test_dp_index=pipeline["split"].test_index,
        test_eo_index=pipeline["final"].test_eo_index,
        train_index=pipeline["split"].train_index,
        validation_index=pipeline["split"].validation_index,
    )
    return frame, compute_plaintext_audit(frame, model_name=model_name)


# --- 1/2/3/4/5: population-membership rules --------------------------------


def test_rejected_test_rows_remain_in_c_k(pipeline):
    """On this tiny fixture, heavy L2 regularisation (C=0.01, selected on
    VALIDATION) can push every LR probability above 0.5, leaving no
    natural rejection to observe at its own selected threshold -- that is
    a property of this fixture's scale, not of the aggregation logic
    (already proven on a hand-built counterexample in
    tests/unit/test_aggregation.py::test_compute_group_counts_*). To
    exercise the real TEST population here, force a guaranteed-mixed
    decision vector via a median split of the SAME model's predicted
    probabilities, then verify C_k still counts every row regardless of
    the (now genuinely mixed) decision."""
    preds = pipeline["predictions"]
    model_predictions = preds[preds["model"] == LOGISTIC_REGRESSION].copy()
    median_proba = model_predictions["y_proba"].median()
    model_predictions["y_pred"] = (model_predictions["y_proba"] > median_proba).astype(int)

    frame = build_audit_frame(
        model_predictions,
        pipeline["synthetic_gender"],
        test_dp_index=pipeline["split"].test_index,
        test_eo_index=pipeline["final"].test_eo_index,
        train_index=pipeline["split"].train_index,
        validation_index=pipeline["split"].validation_index,
    )
    result = compute_plaintext_audit(frame, model_name=LOGISTIC_REGRESSION)

    rejected = frame[frame["y_pred"] == 0]
    assert len(rejected) > 0  # the forced split must actually produce rejections
    # C_k counts every valid TEST row regardless of decision -- rejected
    # rows are not subtracted out.
    assert result.male().C + result.female().C == len(frame)
    for group, counts in result.groups.items():
        assert counts.C == int((frame["group"] == group).sum())


def test_approved_rows_alone_enter_a_k(pipeline):
    frame, result = _audit_for_model(pipeline, LOGISTIC_REGRESSION)
    for group, counts in result.groups.items():
        expected_a = int((frame[(frame["group"] == group) & (frame["y_pred"] == 1)]).shape[0])
        assert counts.A == expected_a


def test_unresolved_test_rows_contribute_to_c_and_a(pipeline):
    frame, result = _audit_for_model(pipeline, LOGISTIC_REGRESSION)
    unresolved = frame[frame["y_true"].isna()]
    assert len(unresolved) > 0  # fixture must actually have unresolved TEST rows
    # Every unresolved row must be inside C (trivially true by construction,
    # but assert the accounting explicitly): full_test_n includes them.
    assert result.unresolved_test_n == len(unresolved)
    assert result.full_test_n == len(frame)


def test_unresolved_rows_cannot_enter_p_tp_n_fp(pipeline):
    frame, result = _audit_for_model(pipeline, LOGISTIC_REGRESSION)
    unresolved_ids = set(frame.loc[frame["y_true"].isna(), "row_index"])
    resolved_ids_used = set(frame.loc[frame["y_true"].notna(), "row_index"])
    assert unresolved_ids.isdisjoint(resolved_ids_used)
    # P_m+P_f+N_m+N_f must equal exactly the resolved count, not more.
    m, f = result.male(), result.female()
    assert (m.P + f.P + m.N + f.N) == result.resolved_test_n


def test_eo_uses_only_resolved_outcomes(pipeline):
    frame, result = _audit_for_model(pipeline, LOGISTIC_REGRESSION)
    eo = compute_equalised_odds(result)
    # TPR/FPR denominators (P, N) are resolved-only by construction of
    # compute_group_counts; cross-check against the frame directly.
    resolved = frame[frame["y_true"].notna()]
    male_resolved = resolved[resolved["group"] == GROUP_MALE]
    assert result.male().P == int((male_resolved["y_true"] == 1).sum())
    assert result.male().N == int((male_resolved["y_true"] == 0).sum())
    assert eo.tpr_m.available in (True, False)  # must not raise; may be unavailable on a tiny fixture


# --- 6/7: train/validation leakage ------------------------------------------


def test_train_ids_never_enter_audit(pipeline):
    frame, _ = _audit_for_model(pipeline, LOGISTIC_REGRESSION)
    assert set(frame["row_index"]).isdisjoint(set(pipeline["split"].train_index))


def test_validation_ids_never_enter_audit(pipeline):
    frame, _ = _audit_for_model(pipeline, LOGISTIC_REGRESSION)
    assert set(frame["row_index"]).isdisjoint(set(pipeline["split"].validation_index))


def test_build_audit_frame_raises_if_train_id_is_injected(pipeline):
    """If a caller passed a TEST index that (incorrectly) included a TRAIN
    row, build_audit_frame must refuse rather than silently auditing it."""
    preds = pipeline["predictions"]
    model_predictions = preds[preds["model"] == LOGISTIC_REGRESSION]
    contaminated_test_index = pipeline["split"].test_index.append(pipeline["split"].train_index[:1])
    with pytest.raises(ValueError):
        build_audit_frame(
            model_predictions,
            pipeline["synthetic_gender"],
            test_dp_index=contaminated_test_index,
            test_eo_index=pipeline["final"].test_eo_index,
            train_index=pipeline["split"].train_index,
            validation_index=pipeline["split"].validation_index,
        )


# --- 8/9/10: model separation and population accounting --------------------


def test_each_model_is_audited_independently(pipeline):
    frame_lr, result_lr = _audit_for_model(pipeline, LOGISTIC_REGRESSION)
    frame_rf, result_rf = _audit_for_model(pipeline, RANDOM_FOREST)
    assert result_lr.model_name == LOGISTIC_REGRESSION
    assert result_rf.model_name == RANDOM_FOREST
    # Each model's audit frame must be built from ONLY that model's
    # predictions -- never a mix of both models' y_pred for the same row.
    assert len(frame_lr) == len(pipeline["df_test"])
    assert len(frame_rf) == len(pipeline["df_test"])
    assert set(frame_lr["row_index"]) == set(frame_rf["row_index"])
    # The two models may (and, on this fixture, do) make different
    # decisions for the same row -- proving they were not accidentally
    # merged into one shared prediction column.
    merged = frame_lr.merge(frame_rf, on="row_index", suffixes=("_lr", "_rf"))
    assert not (merged["y_pred_lr"] == merged["y_pred_rf"]).all()


def test_c_m_plus_c_f_equals_full_test_size_for_both_models(pipeline):
    for model_name in (LOGISTIC_REGRESSION, RANDOM_FOREST):
        _, result = _audit_for_model(pipeline, model_name)
        assert result.male().C + result.female().C == len(pipeline["df_test"])


def test_group_outcome_counts_sum_to_resolved_test_size_for_both_models(pipeline):
    expected_resolved = int(pipeline["df_test"][OUTCOME_COLUMN].notna().sum())
    for model_name in (LOGISTIC_REGRESSION, RANDOM_FOREST):
        _, result = _audit_for_model(pipeline, model_name)
        m, f = result.male(), result.female()
        assert (m.P + f.P + m.N + f.N) == expected_resolved
        assert result.resolved_test_n == expected_resolved


def test_dp_and_eo_computable_without_raising_for_both_models(pipeline):
    for model_name in (LOGISTIC_REGRESSION, RANDOM_FOREST):
        _, result = _audit_for_model(pipeline, model_name)
        dp = compute_demographic_parity(result)
        eo = compute_equalised_odds(result)
        assert isinstance(dp.dp_gap.available, bool)
        assert isinstance(eo.eo_gap.available, bool)
