#!/usr/bin/env python3
"""Manuscript proxy diagnostic (Sec. 6.1.1): how well do the five
winsorised/standardised proxy components (income, DTI, employment length,
home ownership, region) predict the SYNTHETIC protected-attribute label?

This is a DIAGNOSTIC model, entirely separate from the credit-decision
models (`fairlend.models.credit_models`): its target is the synthetic
protected-attribute label, never a credit outcome, and its output is
never fed back into, or compared against, the credit-decision models'
predictions. It reuses `fairlend.data.proxy_features.
fit_proxy_preprocessor`/`ProxyFeaturePreprocessor.transform` unchanged
(the SAME preprocessing already used to build the synthetic-gender proxy
score `z`, fit on `train_model_fit_index` -- resolved-outcome TRAIN rows
-- exactly as `evaluation/generate_synthetic_gender.py` does) -- no new
preprocessing logic is introduced here.

TRAIN/TEST populations: the diagnostic model is fit on ALL of TRAIN
(`train_index.parquet`, resolved + unresolved outcome -- the synthetic
label exists for every row regardless of credit-outcome resolution) and
evaluated on ALL of TEST (`test_index.parquet`), for the same reason.

REAL-DATA MISSING-VALUE HANDLING (discovered running this script against
real LendingClub data; the small fixture has no missing `annual_inc`/
`dti` values and never exercised this path): a handful of real records
have a null raw `annual_inc` or `dti`. `ProxyFeaturePreprocessor.
transform()`'s `z`/`z_standardized` columns silently tolerate this via
pandas' default `skipna=True` summation (the affected row's `z` is
computed from its other four standardized components only) -- that
existing behaviour is untouched here. sklearn's `LogisticRegression`,
however, cannot fit on a NaN feature at all, so THIS diagnostic-only
script explicitly drops any TRAIN/TEST row with a NaN in one of the five
proxy columns before fitting/evaluating, and reports exactly how many
rows were dropped from each split -- never a silent drop.

Usage:
    python evaluation/run_proxy_diagnostic.py \\
        --input data/processed/loan_with_outcome.parquet \\
        --synthetic-gender data/processed/synthetic_gender_alpha1_0.7_seed_0.parquet \\
        --split-dir data/processed/ \\
        --data-scope real_lendingclub \\
        --output results/evaluation/proxy_diagnostic.csv
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score

from fairlend.core.config import load_evaluation_config
from fairlend.data.loader import VALID_DATA_SCOPES, stamp_data_scope
from fairlend.data.proxy_features import PROXY_FEATURE_NAMES, fit_proxy_preprocessor

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"
OUTCOME_COLUMN = "fairlend_outcome"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="loan_with_outcome.parquet")
    parser.add_argument("--synthetic-gender", required=True)
    parser.add_argument("--split-dir", required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--random-state", type=int, default=None)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def _read_index(path: Path) -> pd.Index:
    return pd.Index(pd.read_parquet(path)["index"])


def _drop_rows_with_missing_proxy_features(X: pd.DataFrame, y, label: str) -> tuple:
    """Explicit, reported drop of any row with a NaN in one of the five
    proxy columns -- see this module's REAL-DATA MISSING-VALUE HANDLING
    note. Returns (X_clean, y_clean, n_dropped)."""
    mask = X.notna().all(axis=1)
    n_dropped = int((~mask).sum())
    if n_dropped:
        print(f"  {label}: dropping {n_dropped} row(s) with a missing raw proxy feature (see module docstring).")
    return X[mask], y[mask.to_numpy()], n_dropped


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)
    random_state = args.random_state if args.random_state is not None else config.dataset.split_seed

    df = pd.read_parquet(args.input)
    synthetic_gender = pd.read_parquet(args.synthetic_gender).set_index("row_index")

    split_dir = Path(args.split_dir)
    train_index = _read_index(split_dir / "train_index.parquet")
    train_model_fit_index = _read_index(split_dir / "train_model_fit_index.parquet")
    test_index = _read_index(split_dir / "test_index.parquet")

    # Same preprocessing fit as evaluation/generate_synthetic_gender.py:
    # TRAIN, resolved-outcome subset only.
    df_train_model_fit = df.loc[train_model_fit_index]
    preprocessor = fit_proxy_preprocessor(
        df_train_model_fit,
        winsorize_lower_percentile=config.synthetic_attribute.winsorize_lower_percentile,
        winsorize_upper_percentile=config.synthetic_attribute.winsorize_upper_percentile,
    )

    df_train = df.loc[train_index]
    df_test = df.loc[test_index]
    X_train = preprocessor.transform(df_train)[list(PROXY_FEATURE_NAMES)]
    X_test = preprocessor.transform(df_test)[list(PROXY_FEATURE_NAMES)]
    y_train = synthetic_gender.loc[train_index, "synthetic_gender_label"].to_numpy()
    y_test = synthetic_gender.loc[test_index, "synthetic_gender_label"].to_numpy()

    X_train, y_train, n_dropped_train = _drop_rows_with_missing_proxy_features(X_train, y_train, "TRAIN")
    X_test, y_test, n_dropped_test = _drop_rows_with_missing_proxy_features(X_test, y_test, "TEST")

    model = LogisticRegression(max_iter=1000, random_state=random_state)
    model.fit(X_train, y_train)
    proba_test = model.predict_proba(X_test)[:, 1]
    pred_test = model.predict(X_test)

    roc_auc = float(roc_auc_score(y_test, proba_test))
    accuracy = float(accuracy_score(y_test, pred_test))
    class_balance_test = float(y_test.mean())
    class_balance_train = float(y_train.mean())

    row = stamp_data_scope(
        {
            "proxy_features": list(PROXY_FEATURE_NAMES),
            "n_train": int(len(X_train)),
            "n_test": int(len(X_test)),
            "n_train_dropped_missing_proxy_feature": n_dropped_train,
            "n_test_dropped_missing_proxy_feature": n_dropped_test,
            "class_balance_train_female_fraction": class_balance_train,
            "class_balance_test_female_fraction": class_balance_test,
            "roc_auc": roc_auc,
            "accuracy": accuracy,
            "note": (
                "Diagnostic model predicting the SYNTHETIC protected-attribute "
                "label from proxy features only -- entirely separate from the "
                "credit-decision models; never used as a credit-model input. "
                "Rows with a missing raw annual_inc/dti are explicitly dropped "
                "(see n_*_dropped_missing_proxy_feature), not imputed or silently "
                "included."
            ),
        },
        args.data_scope,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([row]).to_csv(output_path, index=False)

    print(
        f"proxy diagnostic: n_train={row['n_train']} n_test={row['n_test']} "
        f"roc_auc={roc_auc:.4f} accuracy={accuracy:.4f} "
        f"class_balance_test(female_fraction)={class_balance_test:.4f}"
    )
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
