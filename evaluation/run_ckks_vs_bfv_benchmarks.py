#!/usr/bin/env python3
"""Phase 2 (CKKS -> BFV migration) runtime and serialization benchmarks
(reviewer2_phase2_bfv_migration_report.md, task items 11-12, 17).

Benchmarks ONLY the validated DIRECT-ADDITION variants:

    CKKS direct aggregation (Phase 1 baseline, compute_encrypted_audit_ckks_direct)
    vs
    BFV direct aggregation  (Phase 2 ACTIVE,   compute_encrypted_audit)

The legacy compSim path's own numbers already exist in
``results/benchmarks/runtime_summary.csv`` (produced by
``evaluation/run_benchmarks.py``, unmodified) and are NOT re-measured
here -- this script reads that file only to quote its compSim numbers in
a three-way appendix table, never as the primary CKKS-vs-BFV baseline.

Writes NEW, separately-named artifacts -- no existing CSV is overwritten:

    results/benchmarks/ckks_vs_bfv_runtime_raw.csv
    results/benchmarks/ckks_vs_bfv_runtime_summary.csv
    results/benchmarks/serialization_bfv_measured.csv
    results/benchmarks/serialization_ckks_direct_vs_bfv.csv
    results/metadata/ckks_vs_bfv_benchmark_environment.json

Usage:
    python evaluation/run_ckks_vs_bfv_benchmarks.py
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import List

import pandas as pd

from fairlend.audit.aggregation import (
    EncryptedTestRecord,
    build_encrypted_aggregate_packet,
    build_encrypted_aggregate_packet_ckks_direct,
    compute_encrypted_audit,
    compute_encrypted_audit_ckks_direct,
    decrypt_audit_packet_for_diagnostics,
    decrypt_audit_packet_for_diagnostics_ckks_direct,
)
from fairlend.benchmarks.environment import collect_environment_metadata
from fairlend.benchmarks.timing import TimingResult, time_repeated
from fairlend.core.config import BFVConfig, CKKSConfig
from fairlend.crypto.bfv import build_fla_context as bfv_build_fla_context, derive_lpu_context as bfv_derive_lpu_context
from fairlend.crypto.ckks import build_fla_context as ckks_build_fla_context, derive_lpu_context as ckks_derive_lpu_context
from fairlend.roles.identity_provider import IdentityProvider, IdentityProviderBFV

REPO_ROOT = Path(__file__).resolve().parents[1]
BATCH_SIZES = (1, 10, 50, 100, 500, 1000)


def _make_records(ip, n: int, prefix: str) -> List[EncryptedTestRecord]:
    records = []
    for i in range(n):
        group = "male" if i % 2 == 0 else "female"
        credential = ip.issue_credential(f"{prefix}-{i}", group)
        records.append(EncryptedTestRecord(row_index=i, credential=credential, y_pred=int(i % 3 != 0), y_true=int(i % 4 != 0)))
    return records


def main() -> int:
    results: List[TimingResult] = []
    serialization_rows = []

    # --- A: context/key generation ---
    ckks_fla = None

    def _build_ckks_fla():
        nonlocal ckks_fla
        ckks_fla = ckks_build_fla_context()

    def _build_bfv_fla():
        nonlocal bfv_fla
        bfv_fla = bfv_build_fla_context()

    bfv_fla = None
    results.append(time_repeated(_build_ckks_fla, component="A_context_setup", operation="ckks_fla_context_build", n_repeats=10, n_warmup=2))
    results.append(time_repeated(_build_bfv_fla, component="A_context_setup", operation="bfv_fla_context_build", n_repeats=10, n_warmup=2))

    ckks_fla = ckks_build_fla_context()
    ckks_lpu = ckks_derive_lpu_context(ckks_fla)
    bfv_fla = bfv_build_fla_context()
    bfv_lpu = bfv_derive_lpu_context(bfv_fla)

    results.append(time_repeated(lambda: ckks_derive_lpu_context(ckks_fla), component="A_context_setup", operation="ckks_lpu_context_derive", n_repeats=10, n_warmup=2))
    results.append(time_repeated(lambda: bfv_derive_lpu_context(bfv_fla), component="A_context_setup", operation="bfv_lpu_context_derive", n_repeats=10, n_warmup=2))

    ckks_ip = IdentityProvider(ckks_lpu)
    bfv_ip = IdentityProviderBFV(bfv_lpu)

    # --- B: credential operation (protected-vector encryption) ---
    results.append(time_repeated(lambda: ckks_ip.issue_credential("bench", "male"), component="B_credential_issuance", operation="ckks_protected_attribute_credential", n_repeats=30, n_warmup=3))
    results.append(time_repeated(lambda: bfv_ip.issue_credential("bench", "male"), component="B_credential_issuance", operation="bfv_protected_attribute_credential", n_repeats=30, n_warmup=3))

    ckks_credential = ckks_ip.issue_credential("size-sample", "male")
    bfv_credential = bfv_ip.issue_credential("size-sample", "male")
    serialization_rows.append({"object": "protected_attribute_ciphertext", "scheme": "ckks_direct", "measured_bytes": len(ckks_credential.ciphertext_bytes)})
    serialization_rows.append({"object": "protected_attribute_ciphertext", "scheme": "bfv", "measured_bytes": len(bfv_credential.ciphertext_bytes)})

    # --- Context serialization sizes ---
    ckks_lpu_bytes = ckks_lpu.serialize(save_secret_key=False)
    bfv_lpu_bytes = bfv_lpu.serialize(save_secret_key=False, save_galois_keys=False, save_relin_keys=False)
    ckks_fla_bytes_len = len(ckks_fla.serialize(save_secret_key=True))
    bfv_fla_bytes_len = len(bfv_fla.serialize(save_secret_key=True, save_galois_keys=False, save_relin_keys=False))
    serialization_rows.append({"object": "lpu_public_context", "scheme": "ckks_direct", "measured_bytes": len(ckks_lpu_bytes)})
    serialization_rows.append({"object": "lpu_public_context", "scheme": "bfv", "measured_bytes": len(bfv_lpu_bytes)})
    serialization_rows.append({"object": "fla_private_context_LENGTH_ONLY", "scheme": "ckks_direct", "measured_bytes": ckks_fla_bytes_len})
    serialization_rows.append({"object": "fla_private_context_LENGTH_ONLY", "scheme": "bfv", "measured_bytes": bfv_fla_bytes_len})

    # --- C: aggregation at various batch sizes ---
    for n in BATCH_SIZES:
        ckks_records = _make_records(ckks_ip, n, "ckks")
        bfv_records = _make_records(bfv_ip, n, "bfv")

        ckks_result_holder = {}
        bfv_result_holder = {}

        def _ckks_agg(records=ckks_records):
            ckks_result_holder["r"] = compute_encrypted_audit_ckks_direct(records, ckks_ip.public_key, ckks_lpu, model_name="bench")

        def _bfv_agg(records=bfv_records):
            bfv_result_holder["r"] = compute_encrypted_audit(records, bfv_ip.public_key, bfv_lpu, model_name="bench")

        n_repeats = 10 if n <= 100 else 3
        results.append(time_repeated(_ckks_agg, component="C_aggregation", operation="ckks_direct_aggregation", batch_size=n, n_repeats=n_repeats, n_warmup=1))
        results.append(time_repeated(_bfv_agg, component="C_aggregation", operation="bfv_aggregation", batch_size=n, n_repeats=n_repeats, n_warmup=1))

        if n == max(BATCH_SIZES):
            ckks_packet_for_size = build_encrypted_aggregate_packet_ckks_direct(ckks_result_holder["r"])
            bfv_packet_for_size = build_encrypted_aggregate_packet(bfv_result_holder["r"])
            ckks_packet_bytes = sum(len(getattr(ckks_packet_for_size, s)) for s in ("C", "A", "P", "TP", "N", "FP"))
            bfv_packet_bytes = sum(len(getattr(bfv_packet_for_size, s)) for s in ("C", "A", "P", "TP", "N", "FP"))
            serialization_rows.append({"object": "complete_six_ciphertext_audit_packet", "scheme": "ckks_direct", "measured_bytes": ckks_packet_bytes})
            serialization_rows.append({"object": "complete_six_ciphertext_audit_packet", "scheme": "bfv", "measured_bytes": bfv_packet_bytes})

    # --- D: audit (decryption + total cost) ---
    ckks_records_100 = _make_records(ckks_ip, 100, "ckks-audit")
    bfv_records_100 = _make_records(bfv_ip, 100, "bfv-audit")
    ckks_result_100 = compute_encrypted_audit_ckks_direct(ckks_records_100, ckks_ip.public_key, ckks_lpu, model_name="bench")
    bfv_result_100 = compute_encrypted_audit(bfv_records_100, bfv_ip.public_key, bfv_lpu, model_name="bench")
    ckks_packet_100 = build_encrypted_aggregate_packet_ckks_direct(ckks_result_100)
    bfv_packet_100 = build_encrypted_aggregate_packet(bfv_result_100)

    results.append(time_repeated(lambda: decrypt_audit_packet_for_diagnostics_ckks_direct(ckks_packet_100, ckks_fla), component="D_audit_decryption", operation="ckks_direct_packet_decrypt", n_repeats=20, n_warmup=3))
    results.append(time_repeated(lambda: decrypt_audit_packet_for_diagnostics(bfv_packet_100, bfv_fla), component="D_audit_decryption", operation="bfv_packet_decrypt", n_repeats=20, n_warmup=3))

    def _ckks_total_audit():
        r = compute_encrypted_audit_ckks_direct(ckks_records_100, ckks_ip.public_key, ckks_lpu, model_name="bench")
        p = build_encrypted_aggregate_packet_ckks_direct(r)
        decrypt_audit_packet_for_diagnostics_ckks_direct(p, ckks_fla)

    def _bfv_total_audit():
        r = compute_encrypted_audit(bfv_records_100, bfv_ip.public_key, bfv_lpu, model_name="bench")
        p = build_encrypted_aggregate_packet(r)
        decrypt_audit_packet_for_diagnostics(p, bfv_fla)

    results.append(time_repeated(_ckks_total_audit, component="D_audit_total", operation="ckks_direct_total_audit_n100", batch_size=100, n_repeats=5, n_warmup=1))
    results.append(time_repeated(_bfv_total_audit, component="D_audit_total", operation="bfv_total_audit_n100", batch_size=100, n_repeats=5, n_warmup=1))

    # --- Write runtime CSVs ---
    raw_rows = []
    summary_rows = []
    for r in results:
        for ns in r.raw_ns:
            raw_rows.append({"component": r.component, "operation": r.operation, "batch_size": r.batch_size, "raw_ns": ns})
        summary_rows.append({
            "component": r.component, "operation": r.operation, "batch_size": r.batch_size, "n": r.n,
            "mean_ns": r.mean_ns, "std_ns": r.std_ns, "median_ns": r.median_ns, "min_ns": r.min_ns,
            "max_ns": r.max_ns, "p95_ns": r.p95_ns, "mean_ms_per_record": r.mean_ms_per_record,
            "records_per_second": r.records_per_second,
        })

    raw_path = REPO_ROOT / "results" / "benchmarks" / "ckks_vs_bfv_runtime_raw.csv"
    summary_path = REPO_ROOT / "results" / "benchmarks" / "ckks_vs_bfv_runtime_summary.csv"
    pd.DataFrame(raw_rows).to_csv(raw_path, index=False)
    pd.DataFrame(summary_rows).to_csv(summary_path, index=False)
    print(f"Wrote {raw_path} ({len(raw_rows)} rows), {summary_path} ({len(summary_rows)} rows)")

    # --- Write serialization CSVs ---
    bfv_measured_path = REPO_ROOT / "results" / "benchmarks" / "serialization_bfv_measured.csv"
    pd.DataFrame([r for r in serialization_rows if r["scheme"] == "bfv"]).to_csv(bfv_measured_path, index=False)

    comparison_rows = []
    by_object = {}
    for row in serialization_rows:
        by_object.setdefault(row["object"], {})[row["scheme"]] = row["measured_bytes"]
    for obj, by_scheme in by_object.items():
        ckks_bytes = by_scheme.get("ckks_direct")
        bfv_bytes = by_scheme.get("bfv")
        comparison_rows.append({
            "object": obj,
            "ckks_direct_bytes": ckks_bytes,
            "bfv_bytes": bfv_bytes,
            "bfv_minus_ckks_bytes": (bfv_bytes - ckks_bytes) if (ckks_bytes is not None and bfv_bytes is not None) else None,
            "bfv_relative_change_pct": (
                (bfv_bytes - ckks_bytes) / ckks_bytes * 100.0 if (ckks_bytes is not None and bfv_bytes is not None and ckks_bytes > 0) else None
            ),
        })
    comparison_path = REPO_ROOT / "results" / "benchmarks" / "serialization_ckks_direct_vs_bfv.csv"
    pd.DataFrame(comparison_rows).to_csv(comparison_path, index=False)
    print(f"Wrote {bfv_measured_path}, {comparison_path}")

    # --- Provenance ---
    ckks_cfg = dataclasses.asdict(CKKSConfig())
    bfv_cfg = dataclasses.asdict(BFVConfig())
    bfv_cfg["max_safe_count"] = BFVConfig().max_safe_count
    env = collect_environment_metadata({"ckks_config": ckks_cfg, "bfv_config": bfv_cfg})
    env_path = REPO_ROOT / "results" / "metadata" / "ckks_vs_bfv_benchmark_environment.json"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    with open(env_path, "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=2, sort_keys=True, default=str)
    print(f"Wrote {env_path}")
    if env.get("git_dirty"):
        print("NOTE: git tree is dirty -- treat this run's numbers as PROVISIONAL, not manuscript-ready.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
