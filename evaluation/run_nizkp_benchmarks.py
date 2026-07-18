#!/usr/bin/env python3
"""Phase 3B: NIZKP (R_acc, Groth16) reproducible benchmarking
(reviewer2_phase3b_nizkp_instantiation_report.md, task items 9-11, 17).

Measures, with repeated runs and peak-memory capture where available:

  - circuit compile-time constraint/wire counts (parsed from circom's own
    stdout, never manually estimated);
  - Setup (Powers-of-Tau + Groth16 key generation) -- N=1, since this is
    a one-time cost, stated explicitly rather than hidden;
  - witness generation time (isolated from proving);
  - proving time (isolated from witness generation);
  - verification time;
  - proof size, proving-key size, verification-key size (measured bytes);
  - peak prover/verifier memory via `/usr/bin/time -v` (Linux; if
    unavailable, this script says so rather than estimating).

Writes NEW artifacts under results/nizkp/ (never overwriting any
historical CKKS/BFV result):

    results/nizkp/nizkp_benchmark_raw.csv
    results/nizkp/nizkp_benchmark_summary.csv
    results/nizkp/nizkp_constraint_summary.json
    results/nizkp/nizkp_environment.json

Usage:
    python evaluation/run_nizkp_benchmarks.py
"""
from __future__ import annotations

import json
import re
import shutil
import statistics
import subprocess
import time
from pathlib import Path
from typing import List, Optional

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results" / "nizkp"


def _timed_subprocess_with_memory(cmd: List[str], cwd: Path) -> dict:
    """Runs ``cmd`` under ``/usr/bin/time -v`` if available (captures
    peak RSS); falls back to a plain timed subprocess (memory reported
    as None, never estimated) if ``/usr/bin/time`` is absent."""
    has_time_v = shutil.which("/usr/bin/time") is not None
    if has_time_v:
        full_cmd = ["/usr/bin/time", "-v"] + cmd
    else:
        full_cmd = cmd
    start = time.perf_counter_ns()
    result = subprocess.run(full_cmd, capture_output=True, text=True, cwd=cwd)
    end = time.perf_counter_ns()
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
    peak_kb: Optional[int] = None
    if has_time_v:
        match = re.search(r"Maximum resident set size \(kbytes\): (\d+)", result.stderr)
        if match:
            peak_kb = int(match.group(1))
    return {"elapsed_ns": end - start, "peak_rss_kb": peak_kb}


def main() -> int:
    from fairlend.nizkp import r_acc
    from fairlend.nizkp.groth16_toolchain import circuit_paths, compile_circuit, parse_compile_stats
    from fairlend.benchmarks.environment import collect_environment_metadata

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    paths = circuit_paths("r_acc")
    if not paths.vkey_path.exists():
        print("R_acc circuit not yet set up -- running fairlend.nizkp.r_acc.setup() first (several minutes)...")
        r_acc.setup(ptau_power=13)

    # --- Constraint statistics: recompile to capture fresh circom stdout. ---
    print("Recompiling r_acc.circom to capture constraint statistics...")
    t0 = time.perf_counter()
    compile_circuit("r_acc")
    compile_seconds = time.perf_counter() - t0
    from fairlend.nizkp.groth16_toolchain import _last_compile_stdout
    stats = parse_compile_stats(_last_compile_stdout)
    print("constraint stats:", stats)

    circom_version_out = subprocess.run(
        [shutil.which("circom") or str(Path.home() / ".local" / "bin" / "circom"), "--version"],
        capture_output=True, text=True,
    ).stdout.strip()
    snarkjs_version_out = subprocess.run(["npx", "snarkjs", "--version"], capture_output=True, text=True, cwd=paths.circom_source.parent).stdout.strip()

    constraint_summary = {
        **stats,
        "circuit": "r_acc",
        "circom_version": circom_version_out,
        "circom_compile_seconds": compile_seconds,
        "curve": "bn128 (alt_bn128 / BN254)",
        "proof_system": "groth16",
    }
    with open(RESULTS_DIR / "nizkp_constraint_summary.json", "w", encoding="utf-8") as fh:
        json.dump(constraint_summary, fh, indent=2, sort_keys=True)
    print(f"Wrote {RESULTS_DIR / 'nizkp_constraint_summary.json'}")

    # --- Serialized artifact sizes (measured, not estimated). ---
    sizes = {
        "proving_key_zkey_bytes": paths.zkey_final_path.stat().st_size,
        "verification_key_json_bytes": paths.vkey_path.stat().st_size,
    }

    # --- Repeated timing/memory measurements. ---
    bank_key = r_acc.generate_bank_signing_key()
    instance = r_acc.issue_r_acc_instance(bank_key, uid=r_acc.encode_to_field(b"nizkp-benchmark-uid"), acc=r_acc.encode_to_field(b"nizkp-benchmark-acc"))
    input_json = {**instance.statement.as_circuit_input(), **instance.witness.as_circuit_input()}

    N_REPEATS = 10
    raw_rows = []

    proof_size_bytes = None
    for i in range(N_REPEATS):
        work_dir = RESULTS_DIR / "_scratch" / f"run_{i}"
        work_dir.mkdir(parents=True, exist_ok=True)
        input_path = work_dir / "input.json"
        witness_path = work_dir / "witness.wtns"
        proof_path = work_dir / "proof.json"
        public_path = work_dir / "public.json"
        input_path.write_text(json.dumps(input_json))

        witness_result = _timed_subprocess_with_memory(
            ["node", str(paths.witness_gen_js), str(paths.wasm_path), str(input_path), str(witness_path)],
            cwd=paths.circom_source.parent,
        )
        raw_rows.append({"operation": "witness_generation", "run": i, "elapsed_ns": witness_result["elapsed_ns"], "peak_rss_kb": witness_result["peak_rss_kb"]})

        prove_result = _timed_subprocess_with_memory(
            ["npx", "snarkjs", "groth16", "prove", str(paths.zkey_final_path), str(witness_path), str(proof_path), str(public_path)],
            cwd=paths.circom_source.parent,
        )
        raw_rows.append({"operation": "proving", "run": i, "elapsed_ns": prove_result["elapsed_ns"], "peak_rss_kb": prove_result["peak_rss_kb"]})
        if proof_size_bytes is None:
            proof_size_bytes = proof_path.stat().st_size

        verify_result = _timed_subprocess_with_memory(
            ["npx", "snarkjs", "groth16", "verify", str(paths.vkey_path), str(public_path), str(proof_path)],
            cwd=paths.circom_source.parent,
        )
        raw_rows.append({"operation": "verification", "run": i, "elapsed_ns": verify_result["elapsed_ns"], "peak_rss_kb": verify_result["peak_rss_kb"]})
        print(f"  run {i+1}/{N_REPEATS}: witness={witness_result['elapsed_ns']/1e9:.3f}s "
              f"prove={prove_result['elapsed_ns']/1e9:.3f}s verify={verify_result['elapsed_ns']/1e9:.3f}s")

        shutil.rmtree(work_dir)

    raw_df = pd.DataFrame(raw_rows)
    raw_path = RESULTS_DIR / "nizkp_benchmark_raw.csv"
    raw_df.to_csv(raw_path, index=False)

    summary_rows = []
    for op in ("witness_generation", "proving", "verification"):
        sub = raw_df[raw_df["operation"] == op]
        elapsed_s = sub["elapsed_ns"] / 1e9
        rss = sub["peak_rss_kb"].dropna()
        summary_rows.append({
            "operation": op, "n": len(sub),
            "mean_seconds": elapsed_s.mean(), "std_seconds": elapsed_s.std(ddof=0),
            "median_seconds": elapsed_s.median(), "min_seconds": elapsed_s.min(), "max_seconds": elapsed_s.max(),
            "mean_peak_rss_kb": rss.mean() if len(rss) else None,
            "max_peak_rss_kb": rss.max() if len(rss) else None,
        })
    # Setup is N=1 -- a one-time cost, reported explicitly as such (not repeated).
    summary_rows.append({
        "operation": "setup_one_time_only", "n": 1,
        "mean_seconds": None, "std_seconds": None, "median_seconds": None, "min_seconds": None, "max_seconds": None,
        "mean_peak_rss_kb": None, "max_peak_rss_kb": None,
        "note": "Setup (Powers-of-Tau + Groth16 keygen) runs ONCE per circuit, not per proof; "
                "see reviewer2_phase3b_nizkp_instantiation_report.md for the one observed setup timing.",
    })
    summary_df = pd.DataFrame(summary_rows)
    summary_path = RESULTS_DIR / "nizkp_benchmark_summary.csv"
    summary_df.to_csv(summary_path, index=False)
    print(f"Wrote {raw_path}, {summary_path}")

    sizes["proof_json_bytes"] = proof_size_bytes
    with open(RESULTS_DIR / "nizkp_sizes.json", "w", encoding="utf-8") as fh:
        json.dump(sizes, fh, indent=2, sort_keys=True)
    print(f"Wrote {RESULTS_DIR / 'nizkp_sizes.json'}:", sizes)

    # --- Environment / provenance. ---
    env = collect_environment_metadata({
        "proof_system": "groth16", "circuit": "r_acc",
        "circom_version": circom_version_out, "snarkjs_version": snarkjs_version_out,
        "curve": "bn128 (alt_bn128 / BN254)",
        "setup_method": "local single-contribution Powers-of-Tau + Groth16 phase-2, NOT a production ceremony",
        "n_repeats": N_REPEATS,
        "memory_measurement_tool": "/usr/bin/time -v" if shutil.which("/usr/bin/time") else "UNAVAILABLE",
    })
    env_path = RESULTS_DIR / "nizkp_environment.json"
    with open(env_path, "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=2, sort_keys=True, default=str)
    print(f"Wrote {env_path}")
    if env.get("git_dirty"):
        print("NOTE: git tree is dirty -- treat this run's numbers as PROVISIONAL, not manuscript-ready.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
