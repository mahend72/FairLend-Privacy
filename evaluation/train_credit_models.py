#!/usr/bin/env python3
"""Fit the plaintext credit-decision models (logistic regression, random
forest; manuscript Sec. 6.9-6.10) and save FIXED held-out TEST predictions
for later plaintext (Phase 2) and encrypted (Phases 5-8) fairness audits.

This script does NOT compute any fairness statistic itself -- it only
produces Y-hat_i (approval decision) and the predicted probability for
every TEST record, for both model families, and writes them once. Every
downstream audit reads model_predictions.parquet rather than recomputing
predictions, so the plaintext and encrypted audits are provably scored
against the identical decisions.

Population boundaries (see fairlend.data.audit_scope):
    TRAIN (train_model_fit_index):        fit only.
    VALIDATION (validation_model_select_index): hyperparameter + decision
                                           threshold (tau) selection only.
    TEST (test_index -- ALL test rows, resolved + unresolved outcome):
                                           prediction only, never fitting
                                           or selection. Y-hat_i does not
                                           require a realised outcome, so
                                           every TEST row gets a
                                           prediction (manuscript Sec.
                                           4.7); y_true is null for
                                           unresolved-outcome TEST rows.

REAL-DATA MISSING-VALUE HANDLING (discovered running this script against
real LendingClub data; the small fixture has no missing `annual_inc`/
`dti` values and never exercised this path -- see
evaluation/run_proxy_diagnostic.py's identical note): a handful of real
records have a null raw `annual_inc` or `dti`, which
`fairlend.models.credit_models.build_feature_frame` (unchanged, not
touched here) faithfully propagates as NaN -- neither
`LogisticRegression` nor `RandomForestClassifier` can fit or predict on a
NaN feature. This script (not the model/feature-definition code) handles
this explicitly:
  - TRAIN/VALIDATION: any row with a NaN feature is DROPPED before
    fitting/selection (a negligible fraction; exact counts printed and
    saved) -- these rows never influence the fitted model.
  - TEST: EVERY row must still receive a prediction (manuscript Sec.
    4.7; every downstream audit asserts predictions exactly cover
    test_index) -- so any remaining NaN in a TEST feature is imputed
    with that feature's TRAIN median (computed on the already-cleaned
    X_train) SOLELY for the purpose of producing a defined prediction
    for that row. This exactly mirrors this codebase's existing
    precedent for `emp_length` missingness (train-median imputation,
    `fairlend.data.proxy_features.compute_train_emp_length_median`),
    extended here at the orchestration level to `annual_inc`/`dti`,
    which the feature-definition code itself does not yet handle.

Usage:
    python evaluation/train_credit_models.py \\
        --input data/processed/loan_with_outcome.parquet \\
        --split-dir data/processed/ \\
        --data-scope synthetic_fixture
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd

from fairlend.core.config import load_evaluation_config
from fairlend.data.loader import VALID_DATA_SCOPES, results_subdir
from fairlend.data.proxy_features import compute_train_emp_length_median
from fairlend.models.credit_models import (
    FittedCreditModel,
    build_feature_frame,
    select_best_logistic_regression,
    select_best_random_forest,
)
from fairlend.models.metrics import classification_metrics

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"
OUTCOME_COLUMN = "fairlend_outcome"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="loan_with_outcome.parquet")
    parser.add_argument(
        "--split-dir",
        required=True,
        help="Directory containing train_model_fit_index.parquet, "
        "validation_model_select_index.parquet, test_index.parquet "
        "(see split_dataset.py).",
    )
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument(
        "--random-state",
        type=int,
        default=None,
        help="Defaults to configs/evaluation.yaml's dataset.split_seed, so "
        "model fitting reuses the same documented seed as the data split "
        "rather than introducing a second undocumented constant.",
    )
    return parser.parse_args()


def _read_index(path: Path) -> pd.Index:
    return pd.Index(pd.read_parquet(path)["index"])


def _drop_rows_with_missing_features(X: pd.DataFrame, y: np.ndarray, df: pd.DataFrame, label: str):
    """TRAIN/VALIDATION only: explicit, reported drop of any row with a
    NaN feature -- see this module's REAL-DATA MISSING-VALUE HANDLING
    note. Returns (X_clean, y_clean, df_clean, n_dropped)."""
    mask = X.notna().all(axis=1).to_numpy()
    n_dropped = int((~mask).sum())
    if n_dropped:
        print(f"  {label}: dropping {n_dropped} row(s) with a missing raw feature (see module docstring).")
    return X[mask], y[mask], df[mask], n_dropped


def _impute_test_features_with_train_median(X_test: pd.DataFrame, X_train: pd.DataFrame) -> pd.DataFrame:
    """TEST only: fills any remaining NaN with that column's TRAIN
    median so every TEST row still receives a prediction -- see this
    module's REAL-DATA MISSING-VALUE HANDLING note. Never touches
    TRAIN/VALIDATION, and never changes a non-missing TEST value."""
    n_missing = int(X_test.isna().any(axis=1).sum())
    if n_missing:
        print(f"  TEST: imputing {n_missing} row(s)' missing raw feature with the TRAIN median (see module docstring).")
        X_test = X_test.fillna(X_train.median())
    return X_test


def _predict_rows(
    model: FittedCreditModel, X: pd.DataFrame, df: pd.DataFrame
) -> pd.DataFrame:
    proba = model.predict_probability(X)
    decision = model.predict_decision(X)
    return pd.DataFrame(
        {
            "row_index": df.index,
            "id": df["id"].to_numpy(),
            "model": model.model_name,
            "y_true": df[OUTCOME_COLUMN].to_numpy(),
            "y_proba": proba,
            "y_pred": decision,
            "threshold": model.threshold,
        }
    )


def _metrics_row(model: FittedCreditModel, predictions: pd.DataFrame) -> dict:
    resolved = predictions[predictions["y_true"].notna()]
    y_true = resolved["y_true"].astype(int).to_numpy()
    y_pred = resolved["y_pred"].astype(int).to_numpy()
    y_proba = resolved["y_proba"].to_numpy()
    metrics = classification_metrics(y_true, y_pred, y_proba)
    return {
        "model": model.model_name,
        "hyperparameters": json.dumps(model.hyperparameters, sort_keys=True),
        "selection_metric": model.selection_metric,
        "selection_score": model.selection_score,
        "threshold": model.threshold,
        "n_test_predictions": int(len(predictions)),
        "n_test_resolved_for_metrics": int(len(resolved)),
        **metrics,
    }


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)
    random_state = (
        args.random_state if args.random_state is not None else config.dataset.split_seed
    )

    df = pd.read_parquet(args.input)
    split_dir = Path(args.split_dir)
    train_index = _read_index(split_dir / "train_model_fit_index.parquet")
    validation_index = _read_index(split_dir / "validation_model_select_index.parquet")
    test_index = _read_index(split_dir / "test_index.parquet")

    df_train = df.loc[train_index]
    df_validation = df.loc[validation_index]
    df_test = df.loc[test_index]

    if df_train[OUTCOME_COLUMN].isna().any():
        raise ValueError(
            "train_model_fit_index.parquet must contain only resolved-outcome rows."
        )
    if df_validation[OUTCOME_COLUMN].isna().any():
        raise ValueError(
            "validation_model_select_index.parquet must contain only resolved-outcome rows."
        )

    emp_length_train_median = compute_train_emp_length_median(df_train["emp_length"])

    X_train = build_feature_frame(df_train, emp_length_train_median)
    X_validation = build_feature_frame(df_validation, emp_length_train_median)
    X_test = build_feature_frame(df_test, emp_length_train_median)

    y_train = df_train[OUTCOME_COLUMN].astype(int).to_numpy()
    y_validation = df_validation[OUTCOME_COLUMN].astype(int).to_numpy()

    X_train, y_train, df_train, n_dropped_train = _drop_rows_with_missing_features(X_train, y_train, df_train, "TRAIN")
    X_validation, y_validation, df_validation, n_dropped_validation = _drop_rows_with_missing_features(
        X_validation, y_validation, df_validation, "VALIDATION"
    )
    X_test = _impute_test_features_with_train_median(X_test, X_train)

    logistic_model = select_best_logistic_regression(
        X_train, y_train, X_validation, y_validation, random_state
    )
    forest_model = select_best_random_forest(
        X_train, y_train, X_validation, y_validation, random_state
    )

    prediction_frames: List[pd.DataFrame] = [
        _predict_rows(logistic_model, X_test, df_test),
        _predict_rows(forest_model, X_test, df_test),
    ]
    predictions = pd.concat(prediction_frames, ignore_index=True)

    output_dir = results_subdir(REPO_ROOT, args.data_scope, "evaluation")
    output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = output_dir / "model_predictions.parquet"
    predictions.to_parquet(predictions_path, index=False)

    metrics_rows = [
        _metrics_row(logistic_model, prediction_frames[0]),
        _metrics_row(forest_model, prediction_frames[1]),
    ]
    metrics_df = pd.DataFrame(metrics_rows)
    metrics_df.insert(0, "data_scope", args.data_scope)
    metrics_df.insert(1, "is_real_lendingclub", args.data_scope == "real_lendingclub")
    metrics_df.insert(2, "n_train", len(df_train))
    metrics_df.insert(3, "n_validation", len(df_validation))
    metrics_df.insert(4, "n_train_dropped_missing_feature", n_dropped_train)
    metrics_df.insert(5, "n_validation_dropped_missing_feature", n_dropped_validation)
    metrics_path = output_dir / "model_metrics.csv"
    metrics_df.to_csv(metrics_path, index=False)

    for row in metrics_rows:
        print(
            f"model={row['model']} hyperparameters={row['hyperparameters']} "
            f"threshold={row['threshold']:.2f} "
            f"n_test_predictions={row['n_test_predictions']} "
            f"n_test_resolved={row['n_test_resolved_for_metrics']} "
            f"accuracy={row['accuracy']:.4f} precision={row['precision']:.4f} "
            f"recall={row['recall']:.4f} f1={row['f1']:.4f} "
            f"roc_auc={row['roc_auc']}"
        )
    print(f"Wrote predictions to {predictions_path}")
    print(f"Wrote metrics to {metrics_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
