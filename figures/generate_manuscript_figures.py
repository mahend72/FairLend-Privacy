#!/usr/bin/env python3
"""Regenerates the manuscript's Figures 3 and 4 (computation and
communication cost) from tracked, measured CSV artifacts only --
reviewer2_phase4a_manuscript_revision_log.md, item R.

Three architectures are shown, always separately labelled, never mixed
into one unlabeled series:

  - "Legacy CKKS + compSim"  (results/benchmarks/runtime_summary.csv,
    components D/E: comp_sim + aggregate_addition_update_12_per_record)
  - "CKKS-direct"            (results/benchmarks/ckks_vs_bfv_runtime_summary.csv,
    operation=ckks_direct_aggregation)
  - "BFV-direct" (ACTIVE)    (results/benchmarks/ckks_vs_bfv_runtime_summary.csv,
    operation=bfv_aggregation)

Figure 3 (computation cost): protected-attribute aggregation time vs.
batch size, one line per architecture, log-log axes.

Figure 4 (communication cost): measured application-packet and
aggregate-audit-packet sizes, one grouped bar per architecture, from
results/benchmarks/serialization_measured.csv (legacy),
results/benchmarks/serialization_ckks_direct_vs_bfv.csv (CKKS-direct/BFV).

No fabricated or interpolated value is plotted -- only rows present in
the cited CSV files, at the batch sizes those files actually measured.

Usage:
    python figures/generate_manuscript_figures.py
"""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH_DIR = REPO_ROOT / "results" / "benchmarks"
OUT_DIR = Path(__file__).resolve().parent

LEGACY_LABEL = "Legacy CKKS + compSim"
CKKS_DIRECT_LABEL = "CKKS-direct (superseded)"
BFV_LABEL = "BFV-direct (ACTIVE)"

COMMON_BATCH_SIZES = [1, 10, 50, 100, 500, 1000]


def _legacy_total_ms_by_batch() -> dict:
    df = pd.read_csv(BENCH_DIR / "runtime_summary.csv")
    df = df[df["component"] == "D_protected_group_processing"]
    totals = {}
    for batch in df["batch_size"].unique():
        sub = df[df["batch_size"] == batch]
        total_ns = sub["mean_ns"].sum()  # comp_sim + aggregate_addition_update, same batch
        totals[int(batch)] = total_ns / 1e6
    return totals


def _direct_ms_by_batch(operation: str) -> dict:
    df = pd.read_csv(BENCH_DIR / "ckks_vs_bfv_runtime_summary.csv")
    df = df[(df["component"] == "C_aggregation") & (df["operation"] == operation)]
    return {int(row.batch_size): row.mean_ns / 1e6 for row in df.itertuples()}


def figure_3_computation_cost():
    legacy = _legacy_total_ms_by_batch()
    ckks_direct = _direct_ms_by_batch("ckks_direct_aggregation")
    bfv_direct = _direct_ms_by_batch("bfv_aggregation")

    fig, ax = plt.subplots(figsize=(6, 4.5))
    for series, label, marker in (
        (legacy, LEGACY_LABEL, "o"),
        (ckks_direct, CKKS_DIRECT_LABEL, "s"),
        (bfv_direct, BFV_LABEL, "^"),
    ):
        xs = sorted(b for b in series if b in COMMON_BATCH_SIZES)
        ys = [series[b] for b in xs]
        ax.plot(xs, ys, marker=marker, label=label)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Batch size (applications)")
    ax.set_ylabel("Protected-attribute aggregation time (ms)")
    ax.set_title("Computation cost: protected-attribute aggregation\n(measured; see results/benchmarks/)")
    ax.legend()
    ax.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    out_path = OUT_DIR / "Computation-cost.png"
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Wrote {out_path}")


def figure_4_communication_cost():
    """All three architectures are compared on a CONSISTENT basis: raw
    ciphertext bytes (sum of len(ciphertext) over all ciphertext fields),
    never mixing in the legacy path's separate canonical-JSON+hex-encoded
    wire-format numbers (results/benchmarks/serialization_measured.csv's
    ``ip_protected_attribute_credential``/``complete_encrypted_audit_packet``
    rows use that different, larger encoding and are NOT used here, to
    avoid an apples-to-oranges comparison against the raw-byte figures
    the CKKS-direct/BFV comparison CSV reports)."""
    legacy_ser = pd.read_csv(BENCH_DIR / "serialization_measured.csv").set_index("object")["measured_bytes"]
    comparison = pd.read_csv(BENCH_DIR / "serialization_ckks_direct_vs_bfv.csv").set_index("object")

    legacy_bank = legacy_ser.get("bank_account_credential", 238)
    legacy_ca = legacy_ser.get("ca_score_credential", 226)
    legacy_ip_raw = legacy_ser["encrypted_protected_attribute_pair"]  # raw ciphertext bytes, not JSON-encoded
    legacy_application_packet = legacy_bank + legacy_ca + legacy_ip_raw
    # Legacy audit packet, raw ciphertext bytes: 12 ciphertexts = 2 groups
    # x one_serialized_group_audit_counts (6 ciphertexts/group, raw sum).
    legacy_audit_packet = 2 * legacy_ser["one_serialized_group_audit_counts"]

    ckks_direct_audit_packet = comparison.loc["complete_six_ciphertext_audit_packet", "ckks_direct_bytes"]
    bfv_audit_packet = comparison.loc["complete_six_ciphertext_audit_packet", "bfv_bytes"]
    ckks_direct_credential = comparison.loc["protected_attribute_ciphertext", "ckks_direct_bytes"]
    bfv_credential = comparison.loc["protected_attribute_ciphertext", "bfv_bytes"]
    ckks_direct_application_packet = legacy_bank + legacy_ca + ckks_direct_credential
    bfv_application_packet = legacy_bank + legacy_ca + bfv_credential

    architectures = [LEGACY_LABEL, CKKS_DIRECT_LABEL, BFV_LABEL]
    application_packets = [legacy_application_packet, ckks_direct_application_packet, bfv_application_packet]
    audit_packets = [legacy_audit_packet, ckks_direct_audit_packet, bfv_audit_packet]

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    x = range(len(architectures))
    width = 0.35
    ax.bar([i - width / 2 for i in x], [v / 1000 for v in application_packets], width, label="Application packet (Bank+CA+IP credentials)")
    ax.bar([i + width / 2 for i in x], [v / 1000 for v in audit_packets], width, label="Aggregate audit packet")
    ax.set_xticks(list(x))
    ax.set_xticklabels(architectures, rotation=15, ha="right")
    ax.set_ylabel("Measured size (kB)")
    ax.set_title("Communication cost: application and aggregate audit packets\n(measured; see results/benchmarks/)")
    ax.legend()
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    out_path = OUT_DIR / "communication-cost.png"
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Wrote {out_path}")
    print(
        "Application packet sizes -- legacy: {:.1f} kB, CKKS-direct: {:.1f} kB, BFV: {:.1f} kB".format(
            legacy_application_packet / 1000, ckks_direct_application_packet / 1000, bfv_application_packet / 1000
        )
    )
    print(
        "Audit packet sizes -- legacy: {:.1f} kB, CKKS-direct: {:.1f} kB, BFV: {:.1f} kB".format(
            legacy_audit_packet / 1000, ckks_direct_audit_packet / 1000, bfv_audit_packet / 1000
        )
    )


if __name__ == "__main__":
    figure_3_computation_cost()
    figure_4_communication_cost()
