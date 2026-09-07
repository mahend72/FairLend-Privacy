#!/usr/bin/env python3
"""Encrypted fairness audit (manuscript Sec. 4.6-4.7, Algorithm 5): compute
encrypted C/A/P/TP/N/FP per protected-attribute group, per model, from the
SAME frozen TEST predictions Phase 2's plaintext audit used, via a real
IP-issued/LPU-verified protected-attribute credential and real compSim --
never a plaintext shortcut.

This script does NOT fit, retrain, or re-threshold any model, and does
not recompute y_pred -- see ``fairlend.data.loader``/
``evaluation.train_credit_models`` (Phase 1). It reuses
``fairlend.audit.aggregation.build_audit_frame`` (Phase 2) purely to
validate row identity/train-validation-leakage and to look up which
plaintext label the evaluation harness should ask the Identity Provider
to encrypt for each TEST row -- exactly the "harness may know the
plaintext synthetic label before IP issuance" boundary described in
``fairlend.roles.identity_provider.IdentityProvider.issue_credential``'s
docstring. Nothing downstream of credential issuance (compSim, the
encrypted aggregation itself) ever sees that plaintext label again.

Phase 5 scope: this script reports raw decrypted aggregate values, their
rounded integer form, and their absolute error against the Phase 2
plaintext audit (the "oracle") -- it does NOT compute DP/EO (a later,
separate phase).

PROVENANCE (added after a Phase 6 review found two runs of the encrypted
pipeline -- this script and evaluation/run_fairness_reconstruction.py --
reporting different raw aggregate errors and asked for an exact
explanation): every invocation of this script builds a BRAND-NEW CKKS
context (``build_fla_context()``), brand-new encrypted references, and
issues BRAND-NEW, independently-randomised CKKS ciphertexts for every
TEST row's protected-attribute credential. CKKS encryption is
non-deterministic by design (Sec. 4.6), so raw decrypted aggregate values
-- and therefore their absolute error against the plaintext oracle --
WILL differ, in their last few significant digits, between any two runs
of this script, or between this script and
``run_fairness_reconstruction.py`` (which independently re-runs the same
pipeline rather than consuming this script's output). The ROUNDED counts
(and therefore DP/EO) are expected to be stable across runs; the RAW
error magnitude is not, and reporting one run's raw error as if it
"carried forward" to another run's independent realisation is incorrect.
To make this traceable rather than surprising, each report below records
a ``run_id`` (random per invocation), ``run_timestamp_utc``, the exact
CKKS configuration used, and a ``packet_sha256`` fingerprint of that
model's serialized encrypted aggregate packet -- two runs' fingerprints
will differ even when their rounded counts (and DP/EO) agree exactly.

Usage (fixture):
    python evaluation/run_encrypted_audit.py \\
        --predictions results/fixture_validation/evaluation/model_predictions.parquet \\
        --plaintext-audit results/fixture_validation/evaluation/plaintext_audit.csv \\
        --synthetic-gender data/processed/fixture_validation/synthetic_gender_alpha1_0.7_seed_0.parquet \\
        --split-dir data/processed/fixture_validation/ \\
        --data-scope synthetic_fixture \\
        --output results/fixture_validation/evaluation/encrypted_audit_diagnostic.json
"""
from __future__ import annotations

import argparse
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pandas as pd

from fairlend.audit.aggregation import (
    EncryptedAuditPacket,
    EncryptedTestRecord,
    build_audit_frame,
    build_encrypted_aggregate_packet,
    compute_encrypted_audit,
    decrypt_audit_packet_for_diagnostics,
)
from fairlend.core.config import CKKSConfig
from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
from fairlend.crypto.hashing import sha256_hex
from fairlend.audit.similarity import generate_encrypted_references, load_reference_vectors
from fairlend.data.loader import VALID_DATA_SCOPES, save_json, stamp_data_scope
from fairlend.models.credit_models import MODEL_NAMES
from fairlend.roles.identity_provider import IdentityProvider

REPO_ROOT = Path(__file__).resolve().parents[1]
GROUP_LABEL = {"male": "male", "female": "female"}
STAT_NAMES = ("C", "A", "P", "TP", "N", "FP")


def _packet_sha256(packet: EncryptedAuditPacket) -> str:
    """A fingerprint of one model's serialized encrypted aggregate
    packet, for distinguishing independent CKKS-encryption realisations
    across runs (see this module's PROVENANCE note) -- NOT a
    cryptographic commitment/authentication mechanism, just a
    reproducibility/debugging aid. Concatenates all 12 ciphertexts'
    serialized bytes in a fixed field order via the same SHA-256 helper
    used elsewhere in this codebase (fairlend.crypto.hashing)."""
    ordered = (
        packet.male.C, packet.male.A, packet.male.P, packet.male.TP, packet.male.N, packet.male.FP,
        packet.female.C, packet.female.A, packet.female.P, packet.female.TP, packet.female.N, packet.female.FP,
    )
    return sha256_hex(b"".join(ordered))


def _ckks_config_dict(config: CKKSConfig) -> dict:
    return {
        "poly_modulus_degree": config.poly_modulus_degree,
        "coeff_mod_bit_sizes": list(config.coeff_mod_bit_sizes),
        "global_scale_power": config.global_scale_power,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", required=True, help="Frozen model_predictions.parquet.")
    parser.add_argument(
        "--plaintext-audit",
        required=True,
        help="Phase 2's plaintext_audit.csv -- used as the oracle for numerical comparison.",
    )
    parser.add_argument("--synthetic-gender", required=True)
    parser.add_argument("--split-dir", required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--output", required=True, help="Output JSON path for the diagnostic report.")
    return parser.parse_args()


def _read_index(path: Path) -> pd.Index:
    return pd.Index(pd.read_parquet(path)["index"])


def _issue_records_for_model(
    model_predictions: pd.DataFrame,
    synthetic_gender: pd.DataFrame,
    test_dp_index: pd.Index,
    test_eo_index: pd.Index,
    train_index: pd.Index,
    validation_index: pd.Index,
    ip: IdentityProvider,
) -> List[EncryptedTestRecord]:
    """Validates identity/leakage exactly as Phase 2's plaintext audit
    does (via build_audit_frame), then -- and ONLY here, at the harness
    level -- reads each row's plaintext synthetic label to ask the
    Identity Provider to issue a real credential for it. The returned
    records carry the CREDENTIAL, never the label itself."""
    audit_frame = build_audit_frame(
        model_predictions,
        synthetic_gender,
        test_dp_index=test_dp_index,
        test_eo_index=test_eo_index,
        train_index=train_index,
        validation_index=validation_index,
    )
    records: List[EncryptedTestRecord] = []
    for row in audit_frame.itertuples(index=False):
        credential = ip.issue_credential(str(row.id) if hasattr(row, "id") else str(row.row_index), row.group)
        y_true = None if pd.isna(row.y_true) else int(row.y_true)
        records.append(
            EncryptedTestRecord(
                row_index=int(row.row_index), credential=credential, y_pred=int(row.y_pred), y_true=y_true
            )
        )
    return records


def main() -> int:
    args = parse_args()

    predictions = pd.read_parquet(args.predictions)
    synthetic_gender = pd.read_parquet(args.synthetic_gender)
    plaintext_audit = pd.read_csv(args.plaintext_audit).set_index("model")

    split_dir = Path(args.split_dir)
    train_index = _read_index(split_dir / "train_index.parquet")
    validation_index = _read_index(split_dir / "validation_index.parquet")
    test_dp_index = _read_index(split_dir / "test_index.parquet")
    test_eo_index = _read_index(split_dir / "test_eo_index.parquet")

    run_id = uuid.uuid4().hex
    run_timestamp_utc = datetime.now(timezone.utc).isoformat()
    ckks_config = _ckks_config_dict(CKKSConfig())

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)
    references = load_reference_vectors(generate_encrypted_references(fla_context), lpu_context)

    reports = []
    for model_name in MODEL_NAMES:
        model_predictions = predictions[predictions["model"] == model_name]
        records = _issue_records_for_model(
            model_predictions,
            synthetic_gender,
            test_dp_index,
            test_eo_index,
            train_index,
            validation_index,
            ip,
        )

        start = time.perf_counter()
        result = compute_encrypted_audit(records, ip.public_key, references, lpu_context, model_name=model_name)
        aggregation_seconds = time.perf_counter() - start

        packet = build_encrypted_aggregate_packet(result)
        decrypted = decrypt_audit_packet_for_diagnostics(packet, fla_context)

        oracle = plaintext_audit.loc[model_name]
        per_stat = {}
        max_abs_error = 0.0
        errors = []
        for group, decrypted_group in (("m", decrypted.male), ("f", decrypted.female)):
            for stat in STAT_NAMES:
                raw_value = getattr(decrypted_group, stat)
                rounded_value = round(raw_value)
                expected = int(oracle[f"{stat}_{group}"])
                error = abs(raw_value - expected)
                errors.append(error)
                max_abs_error = max(max_abs_error, error)
                per_stat[f"{stat}_{group}"] = {
                    "plaintext_count": expected,
                    "raw_decrypted_value": raw_value,
                    "rounded_value": rounded_value,
                    "matches_plaintext": rounded_value == expected,
                    "absolute_error": error,
                }

        report = stamp_data_scope(
            {
                "run_id": run_id,
                "run_timestamp_utc": run_timestamp_utc,
                "ckks_config": ckks_config,
                "packet_sha256": _packet_sha256(packet),
                "model": model_name,
                "test_population_n": decrypted.test_population_n,
                "resolved_test_n": decrypted.resolved_test_n,
                "unresolved_test_n": decrypted.unresolved_test_n,
                "packet_protocol_version": packet.protocol_version,
                "aggregation_seconds": aggregation_seconds,
                "aggregation_seconds_per_record": aggregation_seconds / max(len(records), 1),
                "max_absolute_error": max_abs_error,
                "mean_absolute_error": sum(errors) / len(errors),
                "all_rounded_counts_match_plaintext": all(v["matches_plaintext"] for v in per_stat.values()),
                "statistics": per_stat,
            },
            args.data_scope,
        )
        reports.append(report)

        print(
            f"model={model_name} run_id={run_id} packet_sha256={report['packet_sha256'][:16]}... "
            f"n_records={len(records)} aggregation_seconds={aggregation_seconds:.4f} "
            f"max_abs_error={max_abs_error:.6e} mean_abs_error={report['mean_absolute_error']:.6e} "
            f"all_match={report['all_rounded_counts_match_plaintext']}"
        )

    output_path = Path(args.output)
    save_json({"reports": reports}, output_path)
    print(f"Wrote encrypted audit diagnostic report to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
