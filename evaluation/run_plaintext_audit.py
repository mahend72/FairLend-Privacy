#!/usr/bin/env python3
"""Plaintext fairness audit (manuscript Sec. 4.7/4.8, Algorithm 6's
plaintext analogue): compute C/A/P/TP/N/FP and DP/EO per protected-
attribute group, per model, from the FROZEN TEST predictions written by
``evaluation/train_credit_models.py`` (Phase 1).

This script does NOT fit, retrain, or re-threshold any model. It reads
``model_predictions.parquet`` and treats it as fixed input -- see
``fairlend.audit.aggregation``/``fairlend.audit.fairness`` for the actual
counting/metric logic, which this script only wires together and writes
to disk. The encrypted audit (Phases 5-8) must read the SAME
``model_predictions.parquet``, never a recomputed copy, so both audit
paths score the identical decisions.

Two implementation choices exercised here are NOT manuscript-specified
values -- see docs/MANUSCRIPT_EVIDENCE_STATUS.md:
  1. the credit-model feature list (fairlend.data.credit_features.
     CREDIT_MODEL_FEATURES);
  2. the decision threshold tau (selected on VALIDATION by maximising F1;
     fairlend.models.credit_models.select_decision_threshold).

Usage (fixture):
    python evaluation/run_plaintext_audit.py \\
        --predictions results/fixture_validation/evaluation/model_predictions.parquet \\
        --prepared-data data/processed/fixture_validation/loan_with_outcome.parquet \\
        --synthetic-gender data/processed/fixture_validation/synthetic_gender_alpha1_0.7_seed_0.parquet \\
        --split-dir data/processed/fixture_validation/ \\
        --alpha1 0.7 --seed 0 \\
        --data-scope synthetic_fixture \\
        --output results/fixture_validation/evaluation/plaintext_audit.csv
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional

import pandas as pd

from fairlend.audit.aggregation import (
    GROUP_FEMALE,
    GROUP_MALE,
    build_audit_frame,
    compute_plaintext_audit,
)
from fairlend.audit.fairness import (
    compute_demographic_parity,
    compute_equalised_odds,
    dp_release_status,
    eo_release_status,
)
from fairlend.core.config import load_evaluation_config
from fairlend.data.loader import VALID_DATA_SCOPES
from fairlend.models.credit_models import MODEL_NAMES

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"
OUTCOME_COLUMN = "fairlend_outcome"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", required=True, help="Frozen model_predictions.parquet.")
    parser.add_argument(
        "--prepared-data",
        required=True,
        help="loan_with_outcome.parquet (the SAME data_scope as --predictions) -- "
        "used only to independently cross-check y_true, never to refit anything.",
    )
    parser.add_argument(
        "--synthetic-gender",
        required=True,
        help="synthetic_gender_alpha1_<a1>_seed_<seed>.parquet from "
        "evaluation/generate_synthetic_gender.py.",
    )
    parser.add_argument(
        "--split-dir",
        required=True,
        help="Directory with train_index.parquet, validation_index.parquet, "
        "test_index.parquet, test_eo_index.parquet (see split_dataset.py).",
    )
    parser.add_argument("--alpha1", type=float, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument(
        "--minimum-cell-size",
        type=int,
        default=None,
        help="Overrides configs/evaluation.yaml's fairness.minimum_cell_size "
        "(default: null/unconfigured). Used mainly for tests exercising "
        "configured suppression.",
    )
    parser.add_argument("--output", required=True, help="Output CSV path.")
    parser.add_argument("--output-json", default=None, help="Optional output JSON path.")
    return parser.parse_args()


def _read_index(path: Path) -> pd.Index:
    return pd.Index(pd.read_parquet(path)["index"])


def _rate_dict(rate) -> dict:
    return {"value": rate.value, "available": rate.available, "reason": rate.reason}


def build_model_row(
    predictions: pd.DataFrame,
    synthetic_gender: pd.DataFrame,
    test_dp_index: pd.Index,
    test_eo_index: pd.Index,
    train_index: pd.Index,
    validation_index: pd.Index,
    model_name: str,
    data_scope: str,
    alpha1: float,
    seed: int,
    minimum_cell_size: Optional[int],
) -> dict:
    model_predictions = predictions[predictions["model"] == model_name]
    if model_predictions.empty:
        raise ValueError(f"No predictions found for model={model_name!r}.")

    audit_frame = build_audit_frame(
        model_predictions,
        synthetic_gender,
        test_dp_index=test_dp_index,
        test_eo_index=test_eo_index,
        train_index=train_index,
        validation_index=validation_index,
    )
    result = compute_plaintext_audit(audit_frame, model_name=model_name)
    dp = compute_demographic_parity(result)
    eo = compute_equalised_odds(result)

    m, f = result.male(), result.female()
    return {
        "model": model_name,
        "data_scope": data_scope,
        "is_real_lendingclub": data_scope == "real_lendingclub",
        "alpha1": alpha1,
        "seed": seed,
        "test_population_n": result.full_test_n,
        "resolved_test_n": result.resolved_test_n,
        "unresolved_test_n": result.unresolved_test_n,
        "C_m": m.C,
        "C_f": f.C,
        "A_m": m.A,
        "A_f": f.A,
        "P_m": m.P,
        "P_f": f.P,
        "TP_m": m.TP,
        "TP_f": f.TP,
        "N_m": m.N,
        "N_f": f.N,
        "FP_m": m.FP,
        "FP_f": f.FP,
        "approval_rate_m": dp.approval_rate_m.value,
        "approval_rate_f": dp.approval_rate_f.value,
        "TPR_m": eo.tpr_m.value,
        "TPR_f": eo.tpr_f.value,
        "FPR_m": eo.fpr_m.value,
        "FPR_f": eo.fpr_f.value,
        "DP_plain": dp.dp_gap.value,
        "EO_plain": eo.eo_gap.value,
        "minimum_cell_size": minimum_cell_size,
        "DP_release_status": dp_release_status(result, minimum_cell_size),
        "EO_release_status": eo_release_status(result, minimum_cell_size),
        # Not part of the requested flat schema, but preserved for the
        # optional JSON output so an "unavailable, and why" is never lost.
        "_detail": {
            "approval_rate_m": _rate_dict(dp.approval_rate_m),
            "approval_rate_f": _rate_dict(dp.approval_rate_f),
            "TPR_m": _rate_dict(eo.tpr_m),
            "TPR_f": _rate_dict(eo.tpr_f),
            "FPR_m": _rate_dict(eo.fpr_m),
            "FPR_f": _rate_dict(eo.fpr_f),
            "DP_plain": _rate_dict(dp.dp_gap),
            "EO_plain": _rate_dict(eo.eo_gap),
        },
    }


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)
    minimum_cell_size = (
        args.minimum_cell_size
        if args.minimum_cell_size is not None
        else config.fairness.minimum_cell_size
    )

    predictions = pd.read_parquet(args.predictions)
    prepared = pd.read_parquet(args.prepared_data)
    synthetic_gender = pd.read_parquet(args.synthetic_gender)

    split_dir = Path(args.split_dir)
    train_index = _read_index(split_dir / "train_index.parquet")
    validation_index = _read_index(split_dir / "validation_index.parquet")
    test_dp_index = _read_index(split_dir / "test_index.parquet")
    test_eo_index = _read_index(split_dir / "test_eo_index.parquet")

    # Independent cross-check: y_true already embedded in the frozen
    # predictions must match the realised outcome in --prepared-data --
    # never trust the frozen artifact's y_true without this.
    joined = predictions.merge(
        prepared[[OUTCOME_COLUMN]], left_on="row_index", right_index=True, how="left"
    )
    mismatch = ~(
        (joined["y_true"].isna() & joined[OUTCOME_COLUMN].isna())
        | (joined["y_true"] == joined[OUTCOME_COLUMN])
    )
    if mismatch.any():
        raise ValueError(
            f"{int(mismatch.sum())} prediction row(s) have y_true that does not "
            "match --prepared-data's realised outcome; refusing to audit "
            "against a possibly stale/mismatched prediction artifact."
        )

    rows: List[dict] = []
    for model_name in MODEL_NAMES:
        rows.append(
            build_model_row(
                predictions,
                synthetic_gender,
                test_dp_index=test_dp_index,
                test_eo_index=test_eo_index,
                train_index=train_index,
                validation_index=validation_index,
                model_name=model_name,
                data_scope=args.data_scope,
                alpha1=args.alpha1,
                seed=args.seed,
                minimum_cell_size=minimum_cell_size,
            )
        )

    flat_rows = [{k: v for k, v in row.items() if k != "_detail"} for row in rows]
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(flat_rows).to_csv(output_path, index=False)
    print(f"Wrote plaintext audit CSV to {output_path}")

    if args.output_json:
        json_path = Path(args.output_json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2, sort_keys=True, default=str)
        print(f"Wrote plaintext audit JSON to {json_path}")

    for row in rows:
        print(
            f"model={row['model']} C_m={row['C_m']} C_f={row['C_f']} "
            f"A_m={row['A_m']} A_f={row['A_f']} P_m={row['P_m']} P_f={row['P_f']} "
            f"N_m={row['N_m']} N_f={row['N_f']} TP_m={row['TP_m']} TP_f={row['TP_f']} "
            f"FP_m={row['FP_m']} FP_f={row['FP_f']} DP_plain={row['DP_plain']} "
            f"EO_plain={row['EO_plain']} minimum_cell_size={row['minimum_cell_size']} "
            f"DP_release_status={row['DP_release_status']} "
            f"EO_release_status={row['EO_release_status']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
