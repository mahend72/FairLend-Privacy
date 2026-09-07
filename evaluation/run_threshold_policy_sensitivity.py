#!/usr/bin/env python3
"""Threshold-policy sensitivity audit: compares several VALIDATION-only
tau-selection policies for the credit-decision models, freezes each
policy's tau, and reports its TEST consequences (predictive metrics and
DP/EO) -- WITHOUT retraining any model and WITHOUT changing what TEST
data means or how it is used.

Motivation: on real LendingClub data, the existing default policy
(``validation_f1_max``, unchanged and still the default for
``evaluation/train_credit_models.py``) selected tau=0.05 for both models,
which approves 100% of TEST applicants and makes DP_plain=EO_plain=0 for
both -- mathematically correct, but a degenerate decision policy that
tells us little about how encrypted reconstruction would behave under a
more discriminating (in the classifier sense) decision rule. This script
answers: is that degeneracy specific to the F1-maximising selection rule,
or does the classifier's ranking ability remain weak under ANY reasonable
VALIDATION-only threshold?

WHAT IS AND IS NOT RECOMPUTED:
  - Hyperparameters are NOT changed: this script re-runs
    ``fairlend.models.credit_models.select_best_logistic_regression``/
    ``select_best_random_forest`` with the IDENTICAL arguments
    ``evaluation/train_credit_models.py`` uses, which is deterministic
    (fixed random_state) and reproduces the IDENTICAL fitted estimator
    and hyperparameters as the primary run -- this is not a retraining
    decision, it is the only way to obtain VALIDATION-set predicted
    probabilities, which the primary run does not persist to disk.
  - TEST is NEVER touched by this re-fit. Every TEST prediction used here
    is ``y_proba`` read VERBATIM from the FROZEN
    ``model_predictions.parquet`` the primary run already wrote -- tau
    does not affect ``y_proba`` (only hyperparameters do, and those are
    unchanged), so re-using the frozen probability column is exact, not
    an approximation.
  - Only the DECISION THRESHOLD (tau) varies across policies; it is
    selected from VALIDATION ONLY (see
    ``fairlend.models.threshold_policies``, every policy function of
    which has no TEST-shaped parameter at all) and then applied, frozen,
    to the frozen TEST probabilities -- never re-selected from TEST.

Writes results/evaluation/threshold_policy_sensitivity.csv WITHOUT
touching model_predictions.parquet, model_metrics.csv, or
plaintext_audit.csv (the existing primary-run artifacts).

Usage:
    python evaluation/run_threshold_policy_sensitivity.py \\
        --input data/processed/loan_with_outcome.parquet \\
        --predictions results/evaluation/model_predictions.parquet \\
        --synthetic-gender data/processed/synthetic_gender_alpha1_0.7_seed_0.parquet \\
        --split-dir data/processed/ \\
        --data-scope real_lendingclub \\
        --output results/evaluation/threshold_policy_sensitivity.csv
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd

from fairlend.audit.aggregation import build_audit_frame, compute_plaintext_audit
from fairlend.audit.fairness import compute_demographic_parity, compute_equalised_odds
from fairlend.core.config import load_evaluation_config
from fairlend.data.loader import VALID_DATA_SCOPES, stamp_data_scope
from fairlend.data.proxy_features import compute_train_emp_length_median
from fairlend.models.credit_models import (
    MODEL_NAMES,
    build_feature_frame,
    select_best_logistic_regression,
    select_best_random_forest,
)
from fairlend.models.threshold_policies import ALL_POLICIES, evaluate_at_threshold, select_threshold

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"
OUTCOME_COLUMN = "fairlend_outcome"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="loan_with_outcome.parquet")
    parser.add_argument("--predictions", required=True, help="FROZEN model_predictions.parquet (read-only).")
    parser.add_argument("--synthetic-gender", required=True)
    parser.add_argument("--split-dir", required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--random-state", type=int, default=None)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def _read_index(path: Path) -> pd.Index:
    return pd.Index(pd.read_parquet(path)["index"])


def _drop_rows_with_missing_features(X: pd.DataFrame, y: np.ndarray, label: str):
    """Identical, minimal handling to evaluation/train_credit_models.py's
    helper of the same purpose (see that script's REAL-DATA MISSING-VALUE
    HANDLING note) -- kept as a second, independent instance since this
    is data-hygiene plumbing, not a scientific formula; duplicating it
    avoids importing a sibling evaluation script as a library module."""
    mask = X.notna().all(axis=1).to_numpy()
    n_dropped = int((~mask).sum())
    if n_dropped:
        print(f"  {label}: dropping {n_dropped} row(s) with a missing raw feature.")
    return X[mask], y[mask], n_dropped


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)
    random_state = args.random_state if args.random_state is not None else config.dataset.split_seed

    df = pd.read_parquet(args.input)
    frozen_predictions = pd.read_parquet(args.predictions)
    synthetic_gender = pd.read_parquet(args.synthetic_gender)

    split_dir = Path(args.split_dir)
    train_model_fit_index = _read_index(split_dir / "train_model_fit_index.parquet")
    validation_model_select_index = _read_index(split_dir / "validation_model_select_index.parquet")
    train_index = _read_index(split_dir / "train_index.parquet")
    validation_index = _read_index(split_dir / "validation_index.parquet")
    test_dp_index = _read_index(split_dir / "test_index.parquet")
    test_eo_index = _read_index(split_dir / "test_eo_index.parquet")

    df_train = df.loc[train_model_fit_index]
    df_validation = df.loc[validation_model_select_index]
    emp_length_train_median = compute_train_emp_length_median(df_train["emp_length"])

    X_train = build_feature_frame(df_train, emp_length_train_median)
    X_validation = build_feature_frame(df_validation, emp_length_train_median)
    y_train = df_train[OUTCOME_COLUMN].astype(int).to_numpy()
    y_validation = df_validation[OUTCOME_COLUMN].astype(int).to_numpy()

    X_train, y_train, _ = _drop_rows_with_missing_features(X_train, y_train, "TRAIN")
    X_validation, y_validation, _ = _drop_rows_with_missing_features(X_validation, y_validation, "VALIDATION")

    fitters = {
        "logistic_regression": select_best_logistic_regression,
        "random_forest": select_best_random_forest,
    }

    rows: List[dict] = []
    for model_name in MODEL_NAMES:
        # Re-derives the IDENTICAL fitted model (same hyperparameters) as
        # evaluation/train_credit_models.py -- see module docstring.
        model = fitters[model_name](X_train, y_train, X_validation, y_validation, random_state)
        proba_validation = model.predict_probability(X_validation)

        model_predictions = frozen_predictions[frozen_predictions["model"] == model_name].copy()
        resolved_mask = model_predictions["y_true"].notna()
        y_true_test_resolved = model_predictions.loc[resolved_mask, "y_true"].astype(int).to_numpy()
        proba_test_resolved = model_predictions.loc[resolved_mask, "y_proba"].to_numpy()
        proba_test_all = model_predictions["y_proba"].to_numpy()

        for policy in ALL_POLICIES:
            policy_result = select_threshold(policy, y_validation, proba_validation)
            tau = policy_result.tau

            validation_metrics = evaluate_at_threshold(y_validation, proba_validation, tau)
            test_metrics = evaluate_at_threshold(y_true_test_resolved, proba_test_resolved, tau)

            y_pred_test_all = (proba_test_all >= tau).astype(int)
            policy_predictions = pd.DataFrame(
                {
                    "row_index": model_predictions["row_index"].to_numpy(),
                    "y_true": model_predictions["y_true"].to_numpy(),
                    "y_pred": y_pred_test_all,
                }
            )
            audit_frame = build_audit_frame(
                policy_predictions, synthetic_gender, test_dp_index, test_eo_index, train_index, validation_index
            )
            plaintext_result = compute_plaintext_audit(audit_frame, model_name=model_name)
            dp = compute_demographic_parity(plaintext_result)
            eo = compute_equalised_odds(plaintext_result)
            m, f = plaintext_result.male(), plaintext_result.female()

            rows.append(
                stamp_data_scope(
                    {
                        "model": model_name,
                        "threshold_policy": policy,
                        "tau": tau,
                        "selection_score_name": policy_result.selection_score_name,
                        "selection_score": policy_result.selection_score,
                        "validation_n": int(len(y_validation)),
                        "validation_approval_rate": validation_metrics["predicted_positive_rate"],
                        "validation_accuracy": validation_metrics["accuracy"],
                        "validation_precision": validation_metrics["precision"],
                        "validation_recall": validation_metrics["recall"],
                        "validation_f1": validation_metrics["f1"],
                        "validation_roc_auc": validation_metrics["roc_auc"],
                        "validation_balanced_accuracy": validation_metrics["balanced_accuracy"],
                        "validation_tpr": validation_metrics["tpr"],
                        "validation_fpr": validation_metrics["fpr"],
                        "test_n_all": int(len(proba_test_all)),
                        "test_n_resolved": int(len(y_true_test_resolved)),
                        "test_approval_rate_all": float(y_pred_test_all.mean()),
                        "test_accuracy": test_metrics["accuracy"],
                        "test_precision": test_metrics["precision"],
                        "test_recall": test_metrics["recall"],
                        "test_f1": test_metrics["f1"],
                        "test_roc_auc": test_metrics["roc_auc"],
                        "C_m": m.C, "C_f": f.C,
                        "A_m": m.A, "A_f": f.A,
                        "P_m": m.P, "P_f": f.P,
                        "TP_m": m.TP, "TP_f": f.TP,
                        "N_m": m.N, "N_f": f.N,
                        "FP_m": m.FP, "FP_f": f.FP,
                        "DP_plain": dp.dp_gap.value,
                        "EO_plain": eo.eo_gap.value,
                    },
                    args.data_scope,
                )
            )
            print(
                f"model={model_name} policy={policy} tau={tau} "
                f"val_approval_rate={validation_metrics['predicted_positive_rate']:.4f} "
                f"test_approval_rate_all={rows[-1]['test_approval_rate_all']:.4f} "
                f"DP_plain={dp.dp_gap.value} EO_plain={eo.eo_gap.value}"
            )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output_path, index=False)
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
