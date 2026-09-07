#!/usr/bin/env python3
"""Phase 10: real-data alpha1 x seed sensitivity analysis -- PLAINTEXT
ONLY, no CKKS/cryptography anywhere in this script.

Evaluates how the controlled proxy-correlation strength (alpha1) and the
synthetic-gender RNG seed affect protected-group balance, proxy
recoverability, and the plaintext fairness audit of the ALREADY-FROZEN
LR/RF decision vectors (frozen at threshold_policy=
validation_balanced_accuracy_max, tau=0.80 -- see
evaluation/run_primary_policy_encrypted_audit.py, Stages 2/3). Nothing
here refits a model, reselects a threshold, or touches TEST during
fitting:

  - LR/RF decision vectors are read VERBATIM from
    results/evaluation/{lr,rf}_balanced_accuracy_predictions.parquet
    (already thresholded at tau=0.80) and asserted invariant across every
    configuration.
  - The proxy-recoverability diagnostic (identical methodology to
    evaluation/run_proxy_diagnostic.py) is fit on TRAIN and evaluated on
    TEST for every configuration, since its target (the synthetic label)
    genuinely changes per configuration -- only its FEATURES (the five
    proxy components) are fixed, computed once.
  - The synthetic protected-attribute proxy score z_standardized is fit
    once (TRAIN, resolved-outcome subset only -- identical to
    evaluation/generate_synthetic_gender.py) and reused for every
    configuration; only alpha0/alpha1/seed change how it is turned into a
    label.

FairLend's encrypted-fidelity claim is NOT re-established here -- this is
a real-data STATISTICAL SENSITIVITY study of the plaintext audit result,
not an encrypted-reconstruction result. See
docs/MANUSCRIPT_EVIDENCE_STATUS.md's Phase 10 section for how the two are
kept distinct.

Usage:
    python evaluation/run_alpha1_seed_sensitivity.py \\
        --input data/processed/loan_with_outcome.parquet \\
        --split-dir data/processed/ \\
        --lr-predictions results/evaluation/lr_balanced_accuracy_predictions.parquet \\
        --rf-predictions results/evaluation/rf_balanced_accuracy_predictions.parquet \\
        --dataset-sha256 3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a \\
        --data-scope real_lendingclub \\
        --output-runs results/evaluation/alpha1_seed_sensitivity_runs.csv \\
        --output-summary results/evaluation/alpha1_seed_sensitivity_summary.csv
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd

from fairlend.audit.alpha_seed_sensitivity import (
    assert_frozen_predictions_unchanged,
    compute_configuration_model_row,
    compute_proxy_diagnostic,
    pearson_correlation,
    row_to_flat_dict,
    summarise_runs,
)
from fairlend.core.config import load_evaluation_config
from fairlend.data.loader import VALID_DATA_SCOPES
from fairlend.data.proxy_features import PROXY_FEATURE_NAMES, fit_proxy_preprocessor
from fairlend.data.synthetic_gender import generate_synthetic_gender

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"
EXPECTED_THRESHOLD_POLICY = "validation_balanced_accuracy_max"

# Regression check (Phase 10 Sec. 12): the already-stored primary real-data
# plaintext DP/EO for alpha1=0.7, seed=0 -- NOT used in any computation
# here, only compared against this script's own independently computed
# result for that one configuration.
PRIMARY_REGRESSION_CHECK = {
    "logistic_regression": {"DP": 0.0006298858929396633, "EO": 0.0042204779429118044},
    "random_forest": {"DP": 0.009959793549564666, "EO": 0.013518800643769757},
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="loan_with_outcome.parquet")
    parser.add_argument("--split-dir", required=True)
    parser.add_argument("--lr-predictions", required=True, help="lr_balanced_accuracy_predictions.parquet (tau=0.80).")
    parser.add_argument("--rf-predictions", required=True, help="rf_balanced_accuracy_predictions.parquet (tau=0.80).")
    parser.add_argument("--dataset-sha256", required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--random-state", type=int, default=None)
    parser.add_argument("--output-runs", required=True)
    parser.add_argument("--output-summary", required=True)
    return parser.parse_args()


def _read_index(path: Path) -> pd.Index:
    return pd.Index(pd.read_parquet(path)["index"])


def _load_frozen_predictions(path: str, expected_tau: float) -> pd.DataFrame:
    df = pd.read_parquet(path)
    observed_policies = set(df["threshold_policy"].unique())
    observed_taus = set(df["tau"].unique())
    if observed_policies != {EXPECTED_THRESHOLD_POLICY}:
        raise ValueError(
            f"{path}: expected threshold_policy=={EXPECTED_THRESHOLD_POLICY!r} for every row, "
            f"found {observed_policies!r} -- refusing to use a non-primary-policy prediction "
            "artifact (e.g. validation_f1_max) for the primary sensitivity sweep."
        )
    if observed_taus != {expected_tau}:
        raise ValueError(f"{path}: expected tau=={expected_tau!r} for every row, found {observed_taus!r}.")
    return df[["row_index", "y_true", "y_pred"]].copy()


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)
    random_state = args.random_state if args.random_state is not None else config.dataset.split_seed
    alpha0 = config.synthetic_attribute.alpha0
    alpha1_values: List[float] = config.synthetic_attribute.alpha1_values
    seeds: List[int] = config.synthetic_attribute.seeds

    n_expected_configs = len(alpha1_values) * len(seeds)
    print(f"Grid: alpha1 in {alpha1_values} x seed in {seeds} = {n_expected_configs} configurations x 2 models "
          f"= {n_expected_configs * 2} rows.")

    df = pd.read_parquet(args.input)
    split_dir = Path(args.split_dir)
    train_model_fit_index = _read_index(split_dir / "train_model_fit_index.parquet")
    train_index = _read_index(split_dir / "train_index.parquet")
    validation_index = _read_index(split_dir / "validation_index.parquet")
    test_dp_index = _read_index(split_dir / "test_index.parquet")
    test_eo_index = _read_index(split_dir / "test_eo_index.parquet")

    lr_predictions = _load_frozen_predictions(args.lr_predictions, expected_tau=0.80)
    rf_predictions = _load_frozen_predictions(args.rf_predictions, expected_tau=0.80)
    canonical_lr_y_pred = lr_predictions["y_pred"].to_numpy().copy()
    canonical_rf_y_pred = rf_predictions["y_pred"].to_numpy().copy()

    # --- Proxy preprocessor: fit ONCE (resolved-outcome TRAIN only),
    # identical to evaluation/generate_synthetic_gender.py /
    # run_proxy_diagnostic.py. z_standardized and the proxy-diagnostic
    # features are therefore IDENTICAL across every configuration; only
    # the synthetic label (which depends on alpha0/alpha1/seed) varies. ---
    df_train_model_fit = df.loc[df.index.isin(train_model_fit_index)]
    assert df_train_model_fit["fairlend_outcome"].isna().sum() == 0, (
        "train_model_fit_index.parquet must contain only resolved-outcome rows"
    )
    preprocessor = fit_proxy_preprocessor(
        df_train_model_fit,
        winsorize_lower_percentile=config.synthetic_attribute.winsorize_lower_percentile,
        winsorize_upper_percentile=config.synthetic_attribute.winsorize_upper_percentile,
    )
    z_standardized_full = preprocessor.transform(df)["z_standardized"].to_numpy()

    df_train = df.loc[train_index]
    df_test = df.loc[test_dp_index]
    X_train_proxy = preprocessor.transform(df_train)[list(PROXY_FEATURE_NAMES)]
    X_test_proxy = preprocessor.transform(df_test)[list(PROXY_FEATURE_NAMES)]
    train_mask = X_train_proxy.notna().all(axis=1)
    test_mask = X_test_proxy.notna().all(axis=1)
    n_train_dropped = int((~train_mask).sum())
    n_test_dropped = int((~test_mask).sum())
    if n_train_dropped or n_test_dropped:
        print(f"Proxy diagnostic: dropping {n_train_dropped} TRAIN / {n_test_dropped} TEST row(s) "
              "with a missing raw proxy feature (see evaluation/run_proxy_diagnostic.py's identical handling).")
    X_train_proxy = X_train_proxy[train_mask]
    X_test_proxy = X_test_proxy[test_mask]

    rows = []
    start = time.perf_counter()
    for alpha1 in alpha1_values:
        for seed in seeds:
            result = generate_synthetic_gender(z_standardized_full, alpha0=alpha0, alpha1=alpha1, seed=seed)

            if alpha1 == 0.0:
                if not np.allclose(result.probability_female, 0.5):
                    raise AssertionError(
                        "alpha1=0.0 must give probability_female == 0.5 for every record "
                        "(sigmoid(alpha0 + 0*z) == sigmoid(0) == 0.5 when alpha0=0)."
                    )

            synthetic_gender_frame = pd.DataFrame({"row_index": df.index, "synthetic_gender_label": result.label})
            label_full = pd.Series(result.label, index=df.index)
            y_train_cfg = label_full.loc[X_train_proxy.index].to_numpy()
            y_test_cfg = label_full.loc[X_test_proxy.index].to_numpy()
            proxy_result = compute_proxy_diagnostic(X_train_proxy, y_train_cfg, X_test_proxy, y_test_cfg, random_state)

            for model_name, frozen_predictions, canonical_y_pred, tau in (
                ("logistic_regression", lr_predictions, canonical_lr_y_pred, 0.80),
                ("random_forest", rf_predictions, canonical_rf_y_pred, 0.80),
            ):
                assert_frozen_predictions_unchanged(frozen_predictions, canonical_y_pred, model_name)
                row = compute_configuration_model_row(
                    alpha1=alpha1,
                    seed=seed,
                    model_name=model_name,
                    tau=tau,
                    frozen_predictions=frozen_predictions,
                    synthetic_gender_frame=synthetic_gender_frame,
                    probability_female_full=result.probability_female,
                    test_dp_index=test_dp_index,
                    test_eo_index=test_eo_index,
                    train_index=train_index,
                    validation_index=validation_index,
                    proxy_result=proxy_result,
                )
                rows.append(row_to_flat_dict(
                    row, data_scope=args.data_scope, dataset_sha256=args.dataset_sha256,
                    threshold_policy=EXPECTED_THRESHOLD_POLICY,
                ))
    total_runtime = time.perf_counter() - start

    runs_df = pd.DataFrame(rows)
    if len(runs_df) != n_expected_configs * 2:
        raise AssertionError(f"Expected {n_expected_configs * 2} rows, got {len(runs_df)}.")

    output_runs_path = Path(args.output_runs)
    output_runs_path.parent.mkdir(parents=True, exist_ok=True)
    runs_df.to_csv(output_runs_path, index=False)
    print(f"Wrote {len(runs_df)} rows to {output_runs_path}")

    # --- Regression check (Phase 10 Sec. 12) ---
    check_row = runs_df[(runs_df["alpha1"] == 0.7) & (runs_df["seed"] == 0)]
    for model_name, expected in PRIMARY_REGRESSION_CHECK.items():
        observed = check_row[check_row["model"] == model_name].iloc[0]
        if observed["DP"] != expected["DP"] or observed["EO"] != expected["EO"]:
            raise AssertionError(
                f"REGRESSION CHECK FAILED for {model_name} at alpha1=0.7, seed=0: "
                f"expected DP={expected['DP']!r} EO={expected['EO']!r}, "
                f"got DP={observed['DP']!r} EO={observed['EO']!r}. STOP and investigate."
            )
        print(f"Regression check PASSED for {model_name}: DP={observed['DP']!r} EO={observed['EO']!r} "
              "exactly matches the stored primary real-data result.")

    # --- Summary (Phase 10 Sec. 9) ---
    summary_df = summarise_runs(runs_df)
    output_summary_path = Path(args.output_summary)
    summary_df.to_csv(output_summary_path, index=False)
    print(f"Wrote {len(summary_df)} rows to {output_summary_path}")

    # --- Correlation / trend analysis (Phase 10 Sec. 10) ---
    proxy_alpha1 = runs_df.drop_duplicates(["alpha1", "seed"])[["alpha1", "proxy_auc"]]
    corr_alpha1_proxy_auc = pearson_correlation(proxy_alpha1["alpha1"].to_numpy(), proxy_alpha1["proxy_auc"].to_numpy())
    correlations = {"alpha1_vs_proxy_auc": corr_alpha1_proxy_auc}
    for model_name in ("logistic_regression", "random_forest"):
        model_rows = runs_df[runs_df["model"] == model_name]
        correlations[f"alpha1_vs_DP_{model_name}"] = pearson_correlation(
            model_rows["alpha1"].to_numpy(), model_rows["DP"].to_numpy()
        )
        correlations[f"alpha1_vs_EO_{model_name}"] = pearson_correlation(
            model_rows["alpha1"].to_numpy(), model_rows["EO"].to_numpy()
        )
    print("Correlations (Pearson r, alpha1 vs. metric, no causal claim beyond this controlled synthetic-generation "
          f"experiment): {correlations}")

    # --- alpha1=0 control (Phase 10 Sec. 11) ---
    control_rows = runs_df[runs_df["alpha1"] == 0.0]
    control_proxy_auc = control_rows.drop_duplicates("seed")["proxy_auc"]
    for model_name in ("logistic_regression", "random_forest"):
        control_model_rows = control_rows[control_rows["model"] == model_name]
        print(
            f"alpha1=0 control ({model_name}): proxy_auc mean={control_proxy_auc.mean():.4f} "
            f"std={control_proxy_auc.std():.4f}; DP mean={control_model_rows['DP'].mean():.6e} "
            f"std={control_model_rows['DP'].std():.6e}; EO mean={control_model_rows['EO'].mean():.6e} "
            f"std={control_model_rows['EO'].std():.6e}"
        )

    print(f"Total runtime for {len(runs_df)} plaintext configuration-model rows: {total_runtime:.2f}s "
          f"({total_runtime / n_expected_configs:.3f}s per configuration).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
