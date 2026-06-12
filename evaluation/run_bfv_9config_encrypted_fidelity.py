#!/usr/bin/env python3
"""Phase 3A: the pre-declared 9-configuration encrypted-fidelity subset,
executed under the ACTIVE BFV direct-addition architecture
(reviewer2_phase3a_bfv_realdata_validation_report.md).

Runs alpha1 in {0.0, 0.7, 1.3} x seed in {0, 5, 9} = 9 configurations,
logistic_regression only (per the pre-declared subset in
docs/MANUSCRIPT_EVIDENCE_STATUS.md's "Proposed encrypted-fidelity subset"
section), via ``evaluation/run_primary_policy_encrypted_audit_bfv.py``
(the ACTIVE-BFV per-configuration runner) -- NEVER via the historical
CKKS+compSim script, which remains completely untouched.

STOP-BEFORE-START GUARD (task item 4): before touching any credential,
model, or encryption call, this script verifies that the raw LendingClub
CSV this codebase's tracked provenance metadata
(``results/metadata/dataset_manifest.json``) describes is ACTUALLY
present at the expected path and has the ACTUALLY EXPECTED SHA-256. If
it is absent or does not match, this script prints the precise blocker
and exits non-zero WITHOUT running any configuration, retraining
anything, or substituting a different dataset. This is not a
convenience check -- it is the mechanism by which this script honours
the task constraint "do not substitute a different LendingClub download
silently."

This script does NOT retrain, retune, reselect tau, or otherwise touch
the frozen ML protocol -- it reads the SAME frozen ``model_predictions.
parquet``/threshold-policy/tau ``evaluation/build_primary_policy_results.py``'s
own real-data run already established (Phase 9 in
docs/MANUSCRIPT_EVIDENCE_STATUS.md), and regenerates ONLY the
synthetic-gender labels per (alpha1, seed) pair via the frozen
``evaluation/generate_synthetic_gender.py`` script (exactly as
``evaluation/run_alpha1_seed_sensitivity.py`` already does for its own,
PLAINTEXT-only, sensitivity sweep) -- never a new model fit.

Usage:
    python evaluation/run_bfv_9config_encrypted_fidelity.py \\
        --raw-csv data/raw/accepted_2007_to_2018Q4.csv \\
        --predictions results/evaluation/model_predictions.parquet \\
        --split-dir data/processed/ \\
        --tau 0.80 --threshold-policy validation_balanced_accuracy_max \\
        --output-dir results/evaluation
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "results" / "metadata" / "dataset_manifest.json"
DEFAULT_RAW_PATH = REPO_ROOT / "data" / "raw" / "accepted_2007_to_2018Q4.csv"

ALPHA1_VALUES = (0.0, 0.7, 1.3)
SEEDS = (0, 5, 9)
MODEL_NAME = "logistic_regression"  # pre-declared subset: LR only


def _load_script(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _sha256_of_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return None


def _git_dirty() -> Optional[bool]:
    try:
        status = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout
        return len(status.strip()) > 0
    except Exception:
        return None


def verify_raw_dataset_provenance(raw_path: Path, manifest_path: Path) -> Optional[str]:
    """Returns None if the raw dataset is present and matches the tracked
    manifest's SHA-256/row count. Otherwise returns a precise, human-
    readable description of the blocker -- never raises, never guesses,
    never substitutes an alternative file."""
    if not manifest_path.exists():
        return (
            f"BLOCKED: no tracked dataset manifest found at {manifest_path}. "
            "Cannot verify raw-data provenance without it; refusing to guess "
            "an expected SHA-256/row count."
        )
    manifest = json.loads(manifest_path.read_text())
    expected_sha256 = manifest.get("sha256")
    expected_raw_row_count = manifest.get("raw_row_count")
    expected_path_hint = manifest.get("input_path")

    if not raw_path.exists():
        return (
            f"BLOCKED: raw LendingClub CSV not found at {raw_path}. "
            f"The tracked manifest ({manifest_path}) expects the file at "
            f"'{expected_path_hint}' with SHA-256 {expected_sha256} "
            f"({expected_raw_row_count} raw rows). This checkpoint's own "
            "data/README.md already documents that no LendingClub file has "
            "been located in this environment. Per task constraints, this "
            "script does NOT download or substitute an alternative file -- "
            "obtain the exact dataset described in data/README.md and place "
            "it at the expected path before re-running this script."
        )

    actual_sha256 = _sha256_of_file(raw_path)
    if actual_sha256 != expected_sha256:
        return (
            f"BLOCKED: raw file at {raw_path} has SHA-256 {actual_sha256}, "
            f"which does NOT match the tracked manifest's expected SHA-256 "
            f"{expected_sha256} ({manifest_path}). Refusing to run the "
            "real-data encrypted-fidelity subset against an unverified or "
            "different dataset release -- this would silently substitute a "
            "different LendingClub download, which this script must not do."
        )

    return None  # verified: present and matches


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-csv", default=str(DEFAULT_RAW_PATH))
    parser.add_argument("--predictions", default="results/evaluation/model_predictions.parquet")
    parser.add_argument("--split-dir", default="data/processed/")
    parser.add_argument("--tau", type=float, default=0.80)
    parser.add_argument("--threshold-policy", default="validation_balanced_accuracy_max")
    parser.add_argument("--dataset-sha256", default=None, help="Defaults to the tracked manifest's SHA-256.")
    parser.add_argument("--output-dir", default="results/evaluation")
    parser.add_argument("--config", default=str(REPO_ROOT / "configs" / "evaluation.yaml"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    raw_path = Path(args.raw_csv)
    blocker = verify_raw_dataset_provenance(raw_path, MANIFEST_PATH)
    if blocker is not None:
        print(blocker)
        print("STOPPING before any configuration is run. No credential, model, or encryption call was made.")
        return 3
    print(f"Raw dataset verified: {raw_path} matches tracked manifest ({MANIFEST_PATH}).")

    manifest = json.loads(MANIFEST_PATH.read_text())
    dataset_sha256 = args.dataset_sha256 or manifest["sha256"]

    gender_script = _load_script("_p3_gender", "evaluation/generate_synthetic_gender.py")
    bfv_runner = _load_script("_p3_bfv_runner", "evaluation/run_primary_policy_encrypted_audit_bfv.py")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    run_rows: List[dict] = []
    git_commit = _git_commit()
    git_dirty = _git_dirty()

    for alpha1 in ALPHA1_VALUES:
        for seed in SEEDS:
            print(f"\n=== Configuration alpha1={alpha1} seed={seed} model={MODEL_NAME} ===")
            gender_path = output_dir / f"bfv_synthetic_gender_alpha1_{alpha1}_seed_{seed}.parquet"
            old_argv = sys.argv
            sys.argv = [
                "g", "--input", str(Path(args.split_dir).parent / "loan_with_outcome.parquet"),
                "--split-dir", args.split_dir, "--alpha1", str(alpha1), "--seed", str(seed),
                "--output", str(gender_path), "--data-scope", "real_lendingclub", "--config", args.config,
            ]
            try:
                assert gender_script.main() == 0
            finally:
                sys.argv = old_argv

            audit_path = output_dir / f"bfv_lr_alpha{alpha1}_seed{seed}_encrypted_audit.json"
            fairness_path = output_dir / f"bfv_lr_alpha{alpha1}_seed{seed}_fairness_reconstruction.json"
            predictions_path = output_dir / f"bfv_lr_alpha{alpha1}_seed{seed}_predictions.parquet"

            old_argv = sys.argv
            sys.argv = [
                "r",
                "--predictions", args.predictions,
                "--synthetic-gender", str(gender_path),
                "--split-dir", args.split_dir,
                "--data-scope", "real_lendingclub",
                "--model", MODEL_NAME,
                "--threshold-policy", args.threshold_policy,
                "--tau", str(args.tau),
                "--alpha1", str(alpha1), "--seed", str(seed),
                "--dataset-sha256", dataset_sha256,
                "--output-predictions", str(predictions_path),
                "--output-audit", str(audit_path),
                "--output-fairness", str(fairness_path),
            ]
            try:
                rc = bfv_runner.main()
            finally:
                sys.argv = old_argv
            if rc != 0:
                print(f"STOP: configuration alpha1={alpha1} seed={seed} did not complete cleanly (exit {rc}).")
                return rc

            audit = json.loads(audit_path.read_text())
            fairness = json.loads(fairness_path.read_text())
            run_rows.append({
                "alpha1": alpha1, "seed": seed, "model": MODEL_NAME,
                "test_population_n": audit["test_population_n"],
                "resolved_test_n": audit["resolved_test_n"],
                "unresolved_test_n": audit["unresolved_test_n"],
                "eo_coverage_fraction": audit["eo_coverage_fraction"],
                "all_rounded_counts_match_plaintext": audit["all_rounded_counts_match_plaintext"],
                "max_absolute_error": audit["max_absolute_error"],
                "mean_absolute_error": audit["mean_absolute_error"],
                "DP_plain": fairness["DP_plain"], "DP_encrypted": fairness["DP_encrypted"], "e_DP": fairness["e_DP"],
                "EO_plain": fairness["EO_plain"], "EO_encrypted": fairness["EO_encrypted"], "e_EO": fairness["e_EO"],
                "runtime_seconds": audit["runtime_seconds"],
                "packet_sha256": audit["packet_sha256"],
                "bfv_safe_bound": audit["bfv_safe_bound"], "bfv_safety_factor": audit["bfv_safety_factor"],
            })

    runs_df = pd.DataFrame(run_rows)
    runs_path = output_dir / "bfv_encrypted_fidelity_9config_runs.csv"
    runs_df.to_csv(runs_path, index=False)

    all_stats = []
    for alpha1 in ALPHA1_VALUES:
        for seed in SEEDS:
            audit_path = output_dir / f"bfv_lr_alpha{alpha1}_seed{seed}_encrypted_audit.json"
            audit = json.loads(audit_path.read_text())
            for key, v in audit["statistics"].items():
                all_stats.append({"alpha1": alpha1, "seed": seed, "statistic": key, **v})
    stats_df = pd.DataFrame(all_stats)
    n_comparisons = len(stats_df)
    n_exact = int((stats_df["absolute_error"] == 0).sum())

    summary = {
        "n_configurations": len(run_rows),
        "n_count_comparisons": n_comparisons,
        "n_exact_matches": n_exact,
        "max_absolute_count_error": float(stats_df["absolute_error"].max()) if n_comparisons else None,
        "mean_absolute_count_error": float(stats_df["absolute_error"].mean()) if n_comparisons else None,
        "max_dp_reconstruction_difference": float(runs_df["e_DP"].max()) if len(runs_df) else None,
        "max_eo_reconstruction_difference": float(runs_df["e_EO"].max()) if len(runs_df) else None,
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "dataset_sha256": dataset_sha256,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    summary_path = output_dir / "bfv_encrypted_fidelity_9config_summary.csv"
    pd.DataFrame([summary]).to_csv(summary_path, index=False)

    combined_json_path = output_dir / "bfv_encrypted_fidelity_9config.json"
    with open(combined_json_path, "w", encoding="utf-8") as fh:
        json.dump({"runs": run_rows, "summary": summary}, fh, indent=2, sort_keys=True, default=str)

    run_meta_path = output_dir / "bfv_encrypted_fidelity_9config_run_meta.json"
    with open(run_meta_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True, default=str)

    print(f"\nWrote {runs_path}, {summary_path}, {combined_json_path}, {run_meta_path}")
    print(f"n_count_comparisons={n_comparisons} n_exact_matches={n_exact} "
          f"max_abs_count_error={summary['max_absolute_count_error']} "
          f"max_DP_diff={summary['max_dp_reconstruction_difference']} max_EO_diff={summary['max_eo_reconstruction_difference']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
