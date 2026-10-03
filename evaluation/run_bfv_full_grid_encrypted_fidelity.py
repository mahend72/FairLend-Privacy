#!/usr/bin/env python3
"""Restartable BFV encrypted-fidelity run over the FULL alpha1 x seed grid
specified in manuscript Section 6.1.1 (5 alpha1 values x 10 seeds = 50
configurations), logistic regression only.

This is a thin driver around exactly the same per-configuration steps
``run_bfv_9config_encrypted_fidelity.py`` uses (same gender-label
generator, same ACTIVE-BFV runner, same frozen predictions/tau/threshold
policy). It changes NO scientific setting. It only (i) enumerates the full
grid, (ii) safely SKIPS configurations whose result files already exist and
verify as complete and correctly-labelled, and (iii) once all 50 exist,
aggregates them.

Usage:
    run_bfv_full_grid_encrypted_fidelity.py --run [--shard I/N]   # compute missing configs
    run_bfv_full_grid_encrypted_fidelity.py --aggregate           # validate + summarise all 50
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
ALPHA1_GRID = (0.0, 0.4, 0.7, 1.0, 1.3)
SEEDS = tuple(range(10))
MODEL = "logistic_regression"
TAU = 0.80


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def paths(out: Path, a: float, s: int):
    stem = f"bfv_lr_alpha{a}_seed{s}"
    return {
        "gender": out / f"bfv_synthetic_gender_alpha1_{a}_seed_{s}.parquet",
        "audit": out / f"{stem}_encrypted_audit.json",
        "fair": out / f"{stem}_fairness_reconstruction.json",
        "pred": out / f"{stem}_predictions.parquet",
    }


def is_complete(out: Path, a: float, s: int, sha: str) -> bool:
    p = paths(out, a, s)
    if not (p["audit"].exists() and p["fair"].exists() and p["pred"].exists()):
        return False
    try:
        au = json.loads(p["audit"].read_text())
    except Exception:
        return False
    return (
        au.get("status") == "completed" and au.get("alpha1") == a and au.get("synthetic_seed") == s
        and au.get("model") == MODEL and au.get("tau") == TAU and au.get("test_population_n") == 177489
        and len(au.get("statistics", {})) == 12 and au.get("dataset_sha256") == sha
        and au.get("any_per_record_decryption_occurred") is False
    )


def run(args, out: Path, sha: str) -> int:
    orch = _load("_fg_orch", "evaluation/run_bfv_9config_encrypted_fidelity.py")
    blocker = orch.verify_raw_dataset_provenance(Path(args.raw_csv), orch.MANIFEST_PATH)
    if blocker:
        print(blocker); return 3
    print("Raw dataset SHA-256 verified against the tracked manifest.")
    gender = _load("_fg_gender", "evaluation/generate_synthetic_gender.py")
    runner = _load("_fg_runner", "evaluation/run_primary_policy_encrypted_audit_bfv.py")
    grid = [(a, s) for a in ALPHA1_GRID for s in SEEDS]
    if args.shard:
        i, n = map(int, args.shard.split("/"))
        pending = [c for c in grid if not is_complete(out, *c, sha)]
        grid = pending[i::n]
    for a, s in grid:
        if is_complete(out, a, s, sha):
            print(f"SKIP alpha1={a} seed={s} (complete)"); continue
        print(f"\n=== alpha1={a} seed={s} model={MODEL} ===", flush=True)
        p = paths(out, a, s)
        argv0 = sys.argv
        sys.argv = ["g", "--input", str(Path(args.split_dir) / "loan_with_outcome.parquet"),
                    "--split-dir", args.split_dir, "--alpha1", str(a), "--seed", str(s),
                    "--output", str(p["gender"]), "--data-scope", "real_lendingclub", "--config", args.config]
        try:
            assert gender.main() == 0
        finally:
            sys.argv = argv0
        sys.argv = ["r", "--predictions", args.predictions, "--synthetic-gender", str(p["gender"]),
                    "--split-dir", args.split_dir, "--data-scope", "real_lendingclub", "--model", MODEL,
                    "--threshold-policy", args.threshold_policy, "--tau", str(TAU),
                    "--alpha1", str(a), "--seed", str(s), "--dataset-sha256", sha,
                    "--output-predictions", str(p["pred"]), "--output-audit", str(p["audit"]),
                    "--output-fairness", str(p["fair"])]
        try:
            rc = runner.main()
        finally:
            sys.argv = argv0
        if rc != 0:
            print(f"STOP: alpha1={a} seed={s} failed (exit {rc})"); return rc
    return 0


def aggregate(out: Path, sha: str) -> int:
    expected = [(a, s) for a in ALPHA1_GRID for s in SEEDS]
    missing = [c for c in expected if not is_complete(out, *c, sha)]
    if missing:
        print(f"INCOMPLETE: {len(missing)} of 50 missing/invalid: {missing}"); return 2
    runs, stats = [], []
    for a, s in expected:
        p = paths(out, a, s)
        au, fr = json.loads(p["audit"].read_text()), json.loads(p["fair"].read_text())
        runs.append({"alpha1": a, "seed": s, "model": MODEL, "test_population_n": au["test_population_n"],
                     "resolved_test_n": au["resolved_test_n"], "unresolved_test_n": au["unresolved_test_n"],
                     "all_rounded_counts_match_plaintext": au["all_rounded_counts_match_plaintext"],
                     "max_absolute_error": au["max_absolute_error"], "mean_absolute_error": au["mean_absolute_error"],
                     "DP_plain": fr["DP_plain"], "DP_encrypted": fr["DP_encrypted"], "e_DP": fr["e_DP"],
                     "EO_plain": fr["EO_plain"], "EO_encrypted": fr["EO_encrypted"], "e_EO": fr["e_EO"],
                     "runtime_seconds": au["runtime_seconds"], "packet_sha256": au["packet_sha256"],
                     "bfv_safety_factor": au["bfv_safety_factor"]})
        for k, v in au["statistics"].items():
            stats.append({"alpha1": a, "seed": s, "statistic": k, **v})
    r, st = pd.DataFrame(runs), pd.DataFrame(stats)
    assert len(r) == 50 and not r.duplicated(["alpha1", "seed"]).any()
    # independent plaintext cross-check (separately produced sensitivity sweep, LR rows)
    sens = pd.read_csv(REPO_ROOT / "results/evaluation/alpha1_seed_sensitivity_runs.csv")
    sens = sens[sens.model == MODEL][["alpha1", "seed", "DP", "EO"]]
    m = r.merge(sens, on=["alpha1", "seed"], how="left")
    xdp = float((m.DP - m.DP_plain).abs().max()); xeo = float((m.EO - m.EO_plain).abs().max())
    exact = int((st.absolute_error == 0).sum())
    summary = {
        "n_configurations": len(r), "n_count_comparisons": len(st), "n_exact_matches": exact,
        "exact_match_percent": 100.0 * exact / len(st),
        "max_absolute_count_error": float(st.absolute_error.max()), "mean_absolute_count_error": float(st.absolute_error.mean()),
        "max_e_DP": float(r.e_DP.max()), "max_e_EO": float(r.e_EO.max()),
        "max_abs_diff_vs_plaintext_sweep_DP": xdp, "max_abs_diff_vs_plaintext_sweep_EO": xeo,
        "dataset_sha256": sha,
    }
    by = []
    for a, d in r.groupby("alpha1"):
        sd = st[st.alpha1 == a]
        by.append({"alpha1": a, "n_seeds": len(d), "seeds": ",".join(map(str, sorted(d.seed))),
                   "count_comparisons": len(sd), "exact_matches": int((sd.absolute_error == 0).sum()),
                   "max_abs_count_error": float(sd.absolute_error.max()), "max_e_DP": float(d.e_DP.max()),
                   "max_e_EO": float(d.e_EO.max()),
                   "DP_mean": d.DP_plain.mean(), "DP_std": d.DP_plain.std(), "EO_mean": d.EO_plain.mean(), "EO_std": d.EO_plain.std(),
                   "runtime_mean_s": d.runtime_seconds.mean(), "runtime_std_s": d.runtime_seconds.std()})
    r.to_csv(out / "bfv_encrypted_fidelity_50config_runs.csv", index=False)
    st.to_csv(out / "bfv_encrypted_fidelity_50config_counts.csv", index=False)
    pd.DataFrame(by).to_csv(out / "bfv_encrypted_fidelity_50config_by_alpha1.csv", index=False)
    pd.DataFrame([summary]).to_csv(out / "bfv_encrypted_fidelity_50config_summary.csv", index=False)
    (out / "bfv_encrypted_fidelity_50config.json").write_text(json.dumps({"summary": summary, "by_alpha1": by}, indent=2, default=str))
    print(json.dumps(summary, indent=2)); print(pd.DataFrame(by).to_string())
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", action="store_true"); ap.add_argument("--aggregate", action="store_true")
    ap.add_argument("--shard", default=None, help="I/N: process every N-th pending config starting at I")
    ap.add_argument("--raw-csv", default=str(REPO_ROOT / "data/raw/accepted_2007_to_2018Q4.csv"))
    ap.add_argument("--predictions", default="results/evaluation/model_predictions.parquet")
    ap.add_argument("--split-dir", default="data/processed/")
    ap.add_argument("--threshold-policy", default="validation_balanced_accuracy_max")
    ap.add_argument("--output-dir", default="results/evaluation")
    ap.add_argument("--config", default=str(REPO_ROOT / "configs/evaluation.yaml"))
    args = ap.parse_args()
    out = Path(args.output_dir)
    sha = json.loads((REPO_ROOT / "results/metadata/dataset_manifest.json").read_text())["sha256"]
    if args.run:
        rc = run(args, out, sha)
        if rc:
            return rc
    if args.aggregate:
        return aggregate(out, sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
