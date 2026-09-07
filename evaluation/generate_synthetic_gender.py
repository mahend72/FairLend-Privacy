#!/usr/bin/env python3
"""Fit proxy-feature preprocessing on TRAIN and generate the synthetic
protected attribute for one (alpha0, alpha1, seed) configuration (manuscript
Sec. 6.1.1).

Usage:
    python evaluation/generate_synthetic_gender.py \\
        --input data/processed/loan_with_outcome.parquet \\
        --split-dir data/processed/ \\
        --alpha1 0.7 \\
        --seed 0 \\
        --output data/processed/synthetic_gender_alpha1_0.7_seed_0.parquet

This script fits the proxy preprocessor (winsorisation bounds,
standardisation stats, employment-length median) on the TRAIN partition of
the MODEL_ELIGIBLE population ONLY (``train_index.parquet``, as written by
``split_dataset.py`` -- which itself only ever indexes model-eligible
rows), then applies it unchanged to EVERY row of the full dataset --
including UNRESOLVED_OUTCOME rows -- before drawing the synthetic label.
This is deliberate: the synthetic protected attribute is defined for the
AUDIT_ELIGIBLE population (manuscript demographic parity requires group
membership for every valid application, resolved outcome or not; see
``fairlend.data.populations``), even though the preprocessing STATISTICS
are fit only on resolved-outcome TRAIN rows. It never uses this output as
a credit-model feature -- see ``fairlend.data.synthetic_gender``'s module
docstring and ``fairlend.data.credit_features`` for the structural guard.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from fairlend.core.config import load_evaluation_config
from fairlend.data.loader import VALID_DATA_SCOPES, results_subdir, save_json, stamp_data_scope
from fairlend.data.proxy_features import fit_proxy_preprocessor
from fairlend.data.synthetic_gender import generate_synthetic_gender

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Processed parquet table.")
    parser.add_argument(
        "--split-dir",
        required=True,
        help="Directory containing train_model_fit_index.parquet (see split_dataset.py).",
    )
    parser.add_argument("--alpha0", type=float, default=None, help="Defaults to config value.")
    parser.add_argument("--alpha1", type=float, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--output", required=True, help="Output parquet path.")
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)
    alpha0 = args.alpha0 if args.alpha0 is not None else config.synthetic_attribute.alpha0

    df = pd.read_parquet(args.input)
    split_dir = Path(args.split_dir)
    train_model_fit_index = pd.read_parquet(split_dir / "train_model_fit_index.parquet")["index"]
    df_train = df.loc[df.index.isin(train_model_fit_index)]
    assert df_train["fairlend_outcome"].isna().sum() == 0, (
        "train_model_fit_index.parquet must contain only resolved-outcome rows"
    )

    preprocessor = fit_proxy_preprocessor(
        df_train,
        winsorize_lower_percentile=config.synthetic_attribute.winsorize_lower_percentile,
        winsorize_upper_percentile=config.synthetic_attribute.winsorize_upper_percentile,
    )
    proxy = preprocessor.transform(df)

    result = generate_synthetic_gender(
        proxy["z_standardized"].to_numpy(),
        alpha0=alpha0,
        alpha1=args.alpha1,
        seed=args.seed,
    )

    output_df = pd.DataFrame(
        {
            "row_index": df.index,
            "z_standardized": proxy["z_standardized"].to_numpy(),
            "probability_female": result.probability_female,
            "synthetic_gender_label": result.label,
            "synthetic_gender_one_hot_male": result.one_hot[:, 0],
            "synthetic_gender_one_hot_female": result.one_hot[:, 1],
        }
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_df.to_parquet(output_path, index=False)

    metadata = stamp_data_scope(
        {**result.metadata(), "output_path": str(output_path)}, args.data_scope
    )
    metadata_path = (
        results_subdir(REPO_ROOT, args.data_scope, "evaluation")
        / f"synthetic_gender_alpha1_{args.alpha1}_seed_{args.seed}.json"
    )
    save_json(metadata, metadata_path)
    print(
        f"alpha0={alpha0} alpha1={args.alpha1} seed={args.seed} "
        f"female_fraction={metadata['female_fraction']:.4f} "
        f"n_records={metadata['n_records']}"
    )
    print(f"Wrote metadata to {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
