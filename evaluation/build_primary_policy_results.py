#!/usr/bin/env python3
"""Stage 4: consolidate the ALREADY-COMPLETED Stage 1 (matching fidelity),
Stage 2 (LR encrypted audit), and Stage 3 (RF encrypted audit) real-data
artifacts into one canonical primary-policy result
(``results/evaluation/primary_policy_results.{csv,json}``).

This script performs NO cryptography, NO model fitting, and NO threshold
selection -- it only reads the stored JSON/CSV artifacts those earlier
stages already wrote, independently re-verifies their internal
consistency (see ``fairlend.audit.primary_policy``), and combines them.
Running this script twice on the same input artifacts produces identical
output; it never regenerates a CKKS packet or a prediction.

CREDIT-MODEL PERFORMANCE vs. FAIRLEND AUDIT FIDELITY: the two credit
models (logistic regression, random forest) -- not FairLend -- produced
the frozen loan-approval decisions being audited. FairLend's OWN result is
that its privacy-preserving pipeline reproduces the plaintext audit of
those decisions exactly (matching fidelity, aggregate reconstruction,
DP/EO reconstruction). The output JSON keeps these two kinds of fact in
clearly separate top-level sections so neither can be read as the other.

Usage:
    python evaluation/build_primary_policy_results.py \\
        --lr-audit results/evaluation/lr_balanced_accuracy_encrypted_audit.json \\
        --lr-fairness results/evaluation/lr_balanced_accuracy_fairness_reconstruction.json \\
        --rf-audit results/evaluation/rf_balanced_accuracy_encrypted_audit.json \\
        --rf-fairness results/evaluation/rf_balanced_accuracy_fairness_reconstruction.json \\
        --matching-runs results/evaluation/matching_fidelity_runs.csv \\
        --matching-threshold results/evaluation/matching_threshold.json \\
        --dataset-sha256 3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a \\
        --alpha1 0.7 --seed 0 \\
        --threshold-policy validation_balanced_accuracy_max \\
        --lr-tau 0.80 --rf-tau 0.80 \\
        --data-scope real_lendingclub \\
        --output-csv results/evaluation/primary_policy_results.csv \\
        --output-json results/evaluation/primary_policy_results.json
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from fairlend.audit.primary_policy import (
    assert_distinct_realisations,
    build_primary_policy_row,
    verify_matching_dataset_hash,
    verify_provenance,
)
from fairlend.data.loader import VALID_DATA_SCOPES, stamp_data_scope

REPO_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lr-audit", required=True)
    parser.add_argument("--lr-fairness", required=True)
    parser.add_argument("--rf-audit", required=True)
    parser.add_argument("--rf-fairness", required=True)
    parser.add_argument("--matching-runs", required=True, help="matching_fidelity_runs.csv")
    parser.add_argument("--matching-threshold", required=True, help="matching_threshold.json")
    parser.add_argument("--dataset-sha256", required=True)
    parser.add_argument("--alpha1", type=float, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--threshold-policy", required=True)
    parser.add_argument("--lr-tau", type=float, required=True)
    parser.add_argument("--rf-tau", type=float, required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--expected-test-population-n", type=int, default=177489)
    parser.add_argument("--expected-resolved-test-n", type=int, default=165872)
    parser.add_argument("--expected-unresolved-test-n", type=int, default=11617)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--output-json", required=True)
    return parser.parse_args()


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _atomic_write_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, default=str)
    os.replace(tmp_path, path)


def _atomic_write_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    df.to_csv(tmp_path, index=False)
    os.replace(tmp_path, path)


def main() -> int:
    args = parse_args()

    lr_audit = _load_json(args.lr_audit)
    lr_fairness = _load_json(args.lr_fairness)
    rf_audit = _load_json(args.rf_audit)
    rf_fairness = _load_json(args.rf_fairness)
    matching_threshold = _load_json(args.matching_threshold)
    matching_runs = pd.read_csv(args.matching_runs)
    if len(matching_runs) != 1:
        raise ValueError(
            f"Expected exactly one matching-fidelity run row (Stage 1 used --n-runs 1), "
            f"found {len(matching_runs)}. Refusing to guess which row is canonical."
        )
    matching_row = matching_runs.iloc[0]

    # --- Step 2: verify provenance for both models (audit + fairness
    # reports each), and the matching artifact's dataset hash. ---
    common_provenance = dict(
        expected_dataset_sha256=args.dataset_sha256,
        expected_alpha1=args.alpha1,
        expected_seed=args.seed,
        expected_threshold_policy=args.threshold_policy,
        expected_data_scope=args.data_scope,
        expected_test_population_n=args.expected_test_population_n,
        expected_resolved_test_n=args.expected_resolved_test_n,
        expected_unresolved_test_n=args.expected_unresolved_test_n,
    )
    # Fairness-reconstruction reports carry no population-size fields, so
    # their provenance check omits those three keys entirely (rather than
    # passing an expected value the artifact could never satisfy).
    fairness_provenance = {
        k: v
        for k, v in common_provenance.items()
        if k not in ("expected_test_population_n", "expected_resolved_test_n", "expected_unresolved_test_n")
    }
    verify_provenance(lr_audit, expected_tau=args.lr_tau, label="LR audit report", **common_provenance)
    verify_provenance(lr_fairness, expected_tau=args.lr_tau, label="LR fairness report", **fairness_provenance)
    verify_provenance(rf_audit, expected_tau=args.rf_tau, label="RF audit report", **common_provenance)
    verify_provenance(rf_fairness, expected_tau=args.rf_tau, label="RF fairness report", **fairness_provenance)

    verify_matching_dataset_hash(
        matching_threshold,
        matching_row,
        expected_dataset_sha256=args.dataset_sha256,
        expected_data_scope=args.data_scope,
    )

    # --- Step 3: re-verify all 24 aggregates (never trusting the stored
    # absolute_error field without recomputing it), and combine. ---
    lr_row = build_primary_policy_row(lr_audit, lr_fairness, "logistic_regression")
    rf_row = build_primary_policy_row(rf_audit, rf_fairness, "random_forest")
    assert_distinct_realisations({"logistic_regression": lr_row, "random_forest": rf_row})

    print("All 24/24 aggregates (12 LR + 12 RF) independently re-verified: rounded_encrypted == plaintext.")
    print(f"LR:  max_abs_error={lr_row.aggregate_max_abs_error:.6e} mean_abs_error={lr_row.aggregate_mean_abs_error:.6e}")
    print(f"RF:  max_abs_error={rf_row.aggregate_max_abs_error:.6e} mean_abs_error={rf_row.aggregate_mean_abs_error:.6e}")

    # --- Step 4/7: canonical primary-policy table (CREDIT-MODEL
    # PERFORMANCE columns; FairLend audits these, does not produce them). ---
    def _row_dict(row) -> Dict[str, Any]:
        d = {"model": row.model, "tau": row.tau, "approval_count": row.approval_count, "approval_rate": row.approval_rate}
        d.update(row.stats)
        d.update(
            {
                "DP_plain": row.dp_plain,
                "DP_encrypted": row.dp_encrypted,
                "DP_reconstruction_error": row.dp_reconstruction_error,
                "EO_plain": row.eo_plain,
                "EO_encrypted": row.eo_encrypted,
                "EO_reconstruction_error": row.eo_reconstruction_error,
                "DP_raw_ckks": row.dp_raw_ckks,
                "EO_raw_ckks": row.eo_raw_ckks,
                "aggregate_max_abs_error": row.aggregate_max_abs_error,
                "aggregate_mean_abs_error": row.aggregate_mean_abs_error,
                "rounding_safety_margin": row.rounding_safety_margin,
                "runtime_seconds": row.runtime_seconds,
                "records_per_second": row.records_per_second,
                "run_id": row.run_id,
                "packet_sha256": row.packet_sha256,
                "reference_fingerprint": row.reference_fingerprint,
            }
        )
        return d

    primary_rows = [_row_dict(lr_row), _row_dict(rf_row)]
    primary_df = pd.DataFrame(primary_rows)
    _atomic_write_csv(primary_df, Path(args.output_csv))
    print(f"Wrote {args.output_csv}")

    # --- Step 6: Stage-1 matching fidelity, unchanged, not rerun. ---
    matching_fidelity = {
        "delta_star": float(matching_row["delta_star"]),
        "validation_n": int(matching_row["validation_n"]),
        "test_n": int(matching_row["test_n"]),
        "matching_accuracy": float(matching_row["accuracy"]),
        "matching_macro_f1": float(matching_row["macro_f1"]),
        "unmatched_rate": float(matching_row["unmatched_rate"]),
        "expected_one_mae": float(matching_row["expected_one_mae"]),
        "expected_one_max_abs_error": float(matching_row["expected_one_max_abs_error"]),
        "expected_zero_mae": float(matching_row["expected_zero_mae"]),
        "expected_zero_max_abs_error": float(matching_row["expected_zero_max_abs_error"]),
        "combined_mae": float(matching_row["combined_mae"]),
        "combined_max_abs_error": float(matching_row["combined_max_abs_error"]),
        "runtime_seconds": float(matching_row["elapsed_seconds"]),
        "records_per_second": float(matching_row["records_per_second"]),
        "run_id": str(matching_row["run_id"]),
        "reference_fingerprint": str(matching_row["reference_fingerprint"]),
    }

    total_runtime_seconds = matching_fidelity["runtime_seconds"] + lr_row.runtime_seconds + rf_row.runtime_seconds

    document = stamp_data_scope(
        {
            "dataset_sha256": args.dataset_sha256,
            "alpha1": args.alpha1,
            "synthetic_seed": args.seed,
            "threshold_policy": args.threshold_policy,
            "test_population_n": args.expected_test_population_n,
            "resolved_test_n": args.expected_resolved_test_n,
            "unresolved_test_n": args.expected_unresolved_test_n,
            "note": (
                "CREDIT-MODEL PERFORMANCE (credit_model_decisions section): the "
                "logistic-regression and random-forest credit models -- not "
                "FairLend -- produced these frozen loan-approval decisions. "
                "FAIRLEND AUDIT FIDELITY (fairlend_audit_fidelity section): "
                "FairLend's own scientific result is that its privacy-preserving "
                "encrypted pipeline reproduces the plaintext audit of those "
                "already-made decisions exactly (matching fidelity, 24/24 exact "
                "aggregate reconstruction, e_DP=e_EO=0 for both models). FairLend "
                "does not choose, and did not influence, either model's decisions "
                "or threshold."
            ),
            "credit_model_decisions": {"logistic_regression": _row_dict(lr_row), "random_forest": _row_dict(rf_row)},
            "fairlend_audit_fidelity": {
                "matching_fidelity": matching_fidelity,
                "aggregate_reconstruction": {
                    "logistic_regression_12_of_12_match": True,
                    "random_forest_12_of_12_match": True,
                    "all_24_of_24_exact": True,
                },
                "total_real_encrypted_runtime_seconds": total_runtime_seconds,
            },
        },
        args.data_scope,
    )
    _atomic_write_json(document, Path(args.output_json))
    print(f"Wrote {args.output_json}")
    print(f"Total real encrypted runtime (matching + LR + RF) = {total_runtime_seconds:.1f}s ({total_runtime_seconds / 60:.1f} min)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
