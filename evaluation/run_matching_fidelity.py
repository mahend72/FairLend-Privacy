#!/usr/bin/env python3
"""Encrypted protected-attribute matching-fidelity diagnostic (Phase 7):
validation-selected delta*, then TEST matching accuracy/macro-F1/unmatched
rate/CKKS numerical error, repeated across multiple independent
cryptographic realisations (fresh CKKS keys + fresh randomised
credential encryption each run, since CKKS encryption is non-deterministic
by design -- see docs/MANUSCRIPT_EVIDENCE_STATUS.md's Phase 6 provenance
note for the same behaviour in the encrypted-aggregation scripts).

This is a MODEL-INDEPENDENT diagnostic: it evaluates the fidelity of the
encrypted protected-attribute credential/compSim path itself, which has
no dependency on the credit-decision model or its predictions -- unlike
Phases 2/5/6, this script does not read model_predictions.parquet at all.

Uses the REAL IP -> LPU-verified compSim -> FLA/evaluator-diagnostic-
decryption path for every record (``fairlend.audit.matching.
compute_paired_scores``, which itself calls
``fairlend.audit.similarity.comp_sim``/``decrypt_similarity_pair_for_
diagnostics`` unmodified) -- no raw encrypted one-hot value is ever
constructed directly in this script.

Do not confuse the repeated CRYPTOGRAPHIC realisations here with the
manuscript's separate alpha1 x seed SENSITIVITY experiment (Sec. 6.1.1) --
this script always uses the single frozen alpha1=0.7, seed=0 synthetic-
gender assignment; only the CKKS encryption randomness varies run to run.

Usage (fixture):
    python evaluation/run_matching_fidelity.py \\
        --synthetic-gender data/processed/fixture_validation/synthetic_gender_alpha1_0.7_seed_0.parquet \\
        --split-dir data/processed/fixture_validation/ \\
        --data-scope synthetic_fixture \\
        --n-runs 10 \\
        --output-dir results/fixture_validation/evaluation/
"""
from __future__ import annotations

import argparse
import statistics
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

from fairlend.audit.aggregation import GROUP_FEMALE, GROUP_MALE
from fairlend.audit.matching import DELTA_STAR_GRID, MatchingInputRecord, run_matching_fidelity_diagnostic
from fairlend.core.config import CKKSConfig
from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
from fairlend.crypto.hashing import sha256_hex
from fairlend.audit.similarity import generate_encrypted_references, load_reference_vectors
from fairlend.data.loader import VALID_DATA_SCOPES, save_json, stamp_data_scope
from fairlend.roles.identity_provider import IdentityProvider

REPO_ROOT = Path(__file__).resolve().parents[1]
DELTA_STAR_SELECTION_METHOD = (
    "largest threshold in DELTA_STAR_GRID achieving the maximum VALIDATION "
    "matching accuracy (ties broken toward the larger threshold, widening "
    "the conservative 'unmatched' rejection zone without sacrificing "
    "validation accuracy) -- an implementation choice, not a manuscript-"
    "prescribed algorithm; see fairlend.audit.matching's module docstring "
    "and docs/MANUSCRIPT_EVIDENCE_STATUS.md."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthetic-gender", required=True)
    parser.add_argument("--split-dir", required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--n-runs", type=int, default=10)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--alpha1", type=float, required=True, help="Synthetic-attribute alpha1 used to build --synthetic-gender.")
    parser.add_argument("--seed", type=int, required=True, help="Synthetic-attribute seed used to build --synthetic-gender.")
    parser.add_argument(
        "--dataset-sha256",
        default=None,
        help="SHA-256 of the raw dataset this run's split/synthetic-gender were derived from "
        "(provenance only; not recomputed here to avoid re-hashing a multi-GB file per run).",
    )
    return parser.parse_args()


def _git_commit() -> Optional[str]:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return None


def _read_index(path: Path) -> pd.Index:
    return pd.Index(pd.read_parquet(path)["index"])


class _LazyRecords:
    """A ``Sized``/``Iterable`` of ``MatchingInputRecord`` that issues
    each credential only at iteration time, one at a time, instead of
    eagerly materializing the full split in memory. Each real credential
    holds a serialized CKKS ciphertext of roughly a few hundred KB; on
    the full real LendingClub validation+test partitions (~266k records)
    eagerly building the list (the previous behaviour of this function)
    requires on the order of tens of GB and gets OOM-killed. Consumers
    (``fairlend.audit.matching.compute_paired_scores`` /
    ``run_matching_fidelity_diagnostic``) only ever call ``len(...)`` and
    iterate once, so this drop-in replacement changes nothing about the
    matching/delta* algorithm itself -- only how records are supplied to
    it -- and each record's credential becomes eligible for garbage
    collection as soon as the consumer's loop advances past it."""

    def __init__(self, indices: pd.Index, labels_by_index: dict, ip: IdentityProvider):
        self._indices = indices
        self._labels_by_index = labels_by_index
        self._ip = ip

    def __len__(self) -> int:
        return len(self._indices)

    def __iter__(self):
        for idx in self._indices:
            expected_group = GROUP_FEMALE if int(self._labels_by_index[idx]) == 1 else GROUP_MALE
            credential = self._ip.issue_credential(str(idx), expected_group)
            yield MatchingInputRecord(identifier=str(idx), credential=credential, expected_group=expected_group)


def _build_records(indices: pd.Index, synthetic_gender: pd.DataFrame, ip: IdentityProvider) -> _LazyRecords:
    """Diagnostic-only: reads each row's SYNTHETIC protected-attribute
    label (never observed gender) and asks the Identity Provider to issue
    a real credential for it -- exactly the "harness may know the label"
    boundary in IdentityProvider.issue_credential's docstring. Returns a
    lazy, memory-bounded collection (see ``_LazyRecords``) rather than a
    fully materialized list."""
    labels_by_index = synthetic_gender.set_index("row_index")["synthetic_gender_label"].to_dict()
    return _LazyRecords(indices, labels_by_index, ip)


def _reference_fingerprint(references) -> str:
    return sha256_hex(references.male_reference_bytes + references.female_reference_bytes)


def _ckks_config_dict(config: CKKSConfig) -> dict:
    return {
        "poly_modulus_degree": config.poly_modulus_degree,
        "coeff_mod_bit_sizes": list(config.coeff_mod_bit_sizes),
        "global_scale_power": config.global_scale_power,
    }


def main() -> int:
    args = parse_args()
    synthetic_gender = pd.read_parquet(args.synthetic_gender)
    split_dir = Path(args.split_dir)
    validation_index = _read_index(split_dir / "validation_index.parquet")
    test_index = _read_index(split_dir / "test_index.parquet")

    ckks_config = _ckks_config_dict(CKKSConfig())
    git_commit = _git_commit()
    run_rows = []

    for _ in range(args.n_runs):
        run_id = uuid.uuid4().hex
        run_timestamp_utc = datetime.now(timezone.utc).isoformat()

        start = time.perf_counter()
        fla_context = build_fla_context()
        lpu_context = derive_lpu_context(fla_context)
        ip = IdentityProvider(lpu_context)
        references_bytes = generate_encrypted_references(fla_context)
        references = load_reference_vectors(references_bytes, lpu_context)

        validation_records = _build_records(validation_index, synthetic_gender, ip)
        test_records = _build_records(test_index, synthetic_gender, ip)

        result = run_matching_fidelity_diagnostic(
            validation_records, test_records, ip.public_key, references, lpu_context, fla_context
        )
        elapsed_seconds = time.perf_counter() - start
        n_records = result.validation_n + result.test_n
        records_per_second = n_records / elapsed_seconds if elapsed_seconds > 0 else float("inf")

        run_rows.append(
            {
                "run_id": run_id,
                "run_timestamp_utc": run_timestamp_utc,
                "git_commit": git_commit,
                "dataset_sha256": args.dataset_sha256,
                "alpha1": args.alpha1,
                "synthetic_seed": args.seed,
                "reference_fingerprint": _reference_fingerprint(references_bytes),
                "elapsed_seconds": elapsed_seconds,
                "records_per_second": records_per_second,
                "delta_star": result.delta_star,
                "validation_n": result.validation_n,
                "validation_accuracy_at_delta_star": result.validation_accuracy_at_delta_star,
                "test_n": result.test_n,
                "accuracy": result.test_metrics.accuracy,
                "macro_f1": result.test_metrics.macro_f1,
                "unmatched_count": result.test_metrics.unmatched_count,
                "unmatched_rate": result.test_metrics.unmatched_rate,
                "combined_mae": result.combined_mae,
                "combined_max_abs_error": result.combined_max_abs_error,
                "expected_one_mean": result.expected_one_stats.mean,
                "expected_one_std": result.expected_one_stats.std,
                "expected_one_min": result.expected_one_stats.min,
                "expected_one_max": result.expected_one_stats.max,
                "expected_one_mae": result.expected_one_stats.mae,
                "expected_one_max_abs_error": result.expected_one_stats.max_abs_error,
                "expected_zero_mean": result.expected_zero_stats.mean,
                "expected_zero_std": result.expected_zero_stats.std,
                "expected_zero_min": result.expected_zero_stats.min,
                "expected_zero_max": result.expected_zero_stats.max,
                "expected_zero_mae": result.expected_zero_stats.mae,
                "expected_zero_max_abs_error": result.expected_zero_stats.max_abs_error,
            }
        )
        print(
            f"run_id={run_id} delta*={result.delta_star} "
            f"accuracy={result.test_metrics.accuracy:.4f} macro_f1={result.test_metrics.macro_f1:.4f} "
            f"unmatched_rate={result.test_metrics.unmatched_rate:.4f} "
            f"mae={result.combined_mae:.3e} max_err={result.combined_max_abs_error:.3e} "
            f"elapsed={elapsed_seconds:.1f}s rate={records_per_second:.2f} rec/s"
        )

    runs_df = pd.DataFrame(run_rows)
    runs_df.insert(0, "data_scope", args.data_scope)
    runs_df.insert(1, "is_real_lendingclub", args.data_scope == "real_lendingclub")

    def _mean_std(col: str) -> dict:
        return {f"{col}_mean": statistics.fmean(runs_df[col]), f"{col}_std": statistics.pstdev(runs_df[col])}

    summary_row = {
        "data_scope": args.data_scope,
        "is_real_lendingclub": args.data_scope == "real_lendingclub",
        "n_runs": args.n_runs,
        "alpha1": args.alpha1,
        "synthetic_seed": args.seed,
        "dataset_sha256": args.dataset_sha256,
        "git_commit": git_commit,
        "validation_n": int(runs_df["validation_n"].iloc[0]),
        "test_n": int(runs_df["test_n"].iloc[0]),
        "total_elapsed_seconds": float(runs_df["elapsed_seconds"].sum()),
        **_mean_std("delta_star"),
        **_mean_std("accuracy"),
        **_mean_std("macro_f1"),
        **_mean_std("unmatched_rate"),
        **_mean_std("combined_mae"),
        **_mean_std("combined_max_abs_error"),
        **_mean_std("records_per_second"),
    }
    summary_df = pd.DataFrame([summary_row])

    threshold_doc = stamp_data_scope(
        {
            "delta_star_selection_method": DELTA_STAR_SELECTION_METHOD,
            "delta_star_grid": list(DELTA_STAR_GRID),
            "n_runs": args.n_runs,
            "alpha1": args.alpha1,
            "synthetic_seed": args.seed,
            "dataset_sha256": args.dataset_sha256,
            "git_commit": git_commit,
            "validation_n": int(runs_df["validation_n"].iloc[0]),
            "test_n": int(runs_df["test_n"].iloc[0]),
            "ckks_config": ckks_config,
            "delta_star_values_across_runs": runs_df["delta_star"].tolist(),
            "delta_star_mean": summary_row["delta_star_mean"],
            "delta_star_std": summary_row["delta_star_std"],
        },
        args.data_scope,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    runs_path = output_dir / "matching_fidelity_runs.csv"
    summary_path = output_dir / "matching_fidelity_summary.csv"
    threshold_path = output_dir / "matching_threshold.json"
    runs_df.to_csv(runs_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    save_json(threshold_doc, threshold_path)

    print(f"\nAcross {args.n_runs} runs: accuracy={summary_row['accuracy_mean']:.4f}+/-{summary_row['accuracy_std']:.4f} "
          f"macro_f1={summary_row['macro_f1_mean']:.4f}+/-{summary_row['macro_f1_std']:.4f} "
          f"unmatched_rate={summary_row['unmatched_rate_mean']:.4f}+/-{summary_row['unmatched_rate_std']:.4f} "
          f"delta*={summary_row['delta_star_mean']:.4f}+/-{summary_row['delta_star_std']:.4f}")
    print(f"Wrote {runs_path}")
    print(f"Wrote {summary_path}")
    print(f"Wrote {threshold_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
