#!/usr/bin/env python3
"""Assign every cleaned record a train/validation/test partition
(manuscript Sec. 6.1.4/6.2.8: 70/10/20, stratified by repayment outcome,
fixed seed), then compute the FINAL AUDIT SCOPE: which records may fit the
credit-decision model, which may be used for model/threshold selection,
and which may contribute to the FINAL REPORTED demographic-parity /
equalised-odds statistics.

This is a single, unified partition covering EVERY record in the cleaned
dataset -- resolved-outcome AND unresolved-outcome rows alike (see
``fairlend.data.splitting.assign_full_population_split``) -- so the same
physical record can never be assigned to TRAIN for model fitting and also
end up in the held-out audit population. See ``fairlend.data.audit_scope``
for the full rationale on which populations may feed which stage.

Usage:
    python evaluation/split_dataset.py \\
        --input data/processed/loan_with_outcome.parquet \\
        --output data/processed/ \\
        --data-scope real_lendingclub

Writes:
    train_index.parquet / validation_index.parquet / test_index.parquet
        The full partition (every row, resolved + unresolved).
    train_model_fit_index.parquet
        TRAIN rows with a resolved outcome -- may fit the credit model.
    validation_model_select_index.parquet
        VALIDATION rows with a resolved outcome -- may be used for
        hyperparameter/threshold selection.
    test_eo_index.parquet
        TEST rows with a resolved outcome -- may contribute to equalised
        odds. (test_index.parquet itself IS the demographic-parity
        population: ALL test rows, resolved or not.)
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from fairlend.core.config import load_evaluation_config
from fairlend.data.audit_scope import compute_final_audit_populations
from fairlend.data.loader import VALID_DATA_SCOPES, results_subdir, save_json, stamp_data_scope
from fairlend.data.populations import classify_outcome_populations
from fairlend.data.splitting import assign_full_population_split

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Processed parquet table.")
    parser.add_argument("--output", required=True, help="Directory to write index files into.")
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)

    df = pd.read_parquet(args.input)
    populations = classify_outcome_populations(df["fairlend_outcome"])
    population_counts = populations.counts()

    split = assign_full_population_split(
        df,
        outcome_column="fairlend_outcome",
        train_fraction=config.dataset.train_fraction,
        validation_fraction=config.dataset.validation_fraction,
        test_fraction=config.dataset.test_fraction,
        seed=config.dataset.split_seed,
    )
    split.assert_disjoint_and_complete(df.index)  # covers the FULL dataset now

    final = compute_final_audit_populations(df, split, populations)
    final.assert_no_train_or_validation_leakage(split)  # redundant re-check; cheap insurance
    final_counts = final.counts()

    resolved_test = final_counts["test_eo"]
    unresolved_test = len(split.test_index) - resolved_test

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    def _write(name: str, index: pd.Index) -> None:
        pd.DataFrame({"index": index}).to_parquet(output_dir / name, index=False)

    _write("train_index.parquet", split.train_index)
    _write("validation_index.parquet", split.validation_index)
    _write("test_index.parquet", split.test_index)
    _write("train_model_fit_index.parquet", final.train_model_fit_index)
    _write("validation_model_select_index.parquet", final.validation_model_select_index)
    _write("test_eo_index.parquet", final.test_eo_index)

    def _outcome_counts(index: pd.Index) -> dict:
        counts = df.loc[index, "fairlend_outcome"].value_counts(dropna=False)
        return {str(k): int(v) for k, v in counts.to_dict().items()}

    summary = stamp_data_scope(
        {
            "split_seed": config.dataset.split_seed,
            "train_fraction": config.dataset.train_fraction,
            "validation_fraction": config.dataset.validation_fraction,
            "test_fraction": config.dataset.test_fraction,
            "population_counts": population_counts,
            "total_audit_population": len(df),
            "train_audit_population": len(split.train_index),
            "validation_audit_population": len(split.validation_index),
            "test_audit_population": len(split.test_index),
            "resolved_test": resolved_test,
            "unresolved_test": unresolved_test,
            "final_audit_populations": final_counts,
            "train_outcome_counts": _outcome_counts(split.train_index),
            "validation_outcome_counts": _outcome_counts(split.validation_index),
            "test_outcome_counts": _outcome_counts(split.test_index),
            "note": (
                "train/validation/test_audit_population partition ALL "
                "records (resolved + unresolved outcome). "
                "final_audit_populations.train_model_fit / "
                ".validation_model_select are the resolved-outcome subsets "
                "of TRAIN/VALIDATION eligible for model fitting/selection. "
                "final_audit_populations.test_dp (== test_audit_population, "
                "all TEST rows) is the demographic-parity population; "
                ".test_eo (== resolved_test) is the equalised-odds "
                "population. No train/validation record can appear in "
                "either final population -- see "
                "fairlend.data.audit_scope.FinalAuditPopulations."
                "assert_no_train_or_validation_leakage, checked above."
            ),
        },
        args.data_scope,
    )
    summary_path = results_subdir(REPO_ROOT, args.data_scope, "evaluation") / "split_summary.json"
    save_json(summary, summary_path)

    print(
        f"total_audit_population={len(df)} "
        f"train_audit_population={len(split.train_index)} "
        f"validation_audit_population={len(split.validation_index)} "
        f"test_audit_population={len(split.test_index)}"
    )
    print(f"  within TEST: resolved_test={resolved_test} unresolved_test={unresolved_test}")
    print(
        f"model_eligible={population_counts['model_eligible']} "
        f"unresolved_outcome={population_counts['unresolved_outcome']} "
        f"audit_eligible={population_counts['audit_eligible']}"
    )
    print(
        f"train_model_fit={final_counts['train_model_fit']} "
        f"validation_model_select={final_counts['validation_model_select']} "
        f"test_dp={final_counts['test_dp']} test_eo={final_counts['test_eo']}"
    )
    print(f"Wrote split summary to {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
