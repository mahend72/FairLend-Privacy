#!/usr/bin/env python3
"""Plaintext-vs-encrypted fairness reconstruction (Phase 6): proves that
FairLend's encrypted aggregate audit reconstructs the SAME DP/EO as the
Phase 2 plaintext audit when both use identical held-out decisions.

This script does NOT implement any fairness formula itself -- it produces
a real ``EncryptedAuditPacket`` via the UNMODIFIED Phase 5 pipeline
(``fairlend.audit.aggregation.compute_encrypted_audit`` /
``build_encrypted_aggregate_packet`` / ``decrypt_audit_packet_for_
diagnostics``, using the SAME functions ``evaluation/run_encrypted_audit.py``
calls), then hands the plaintext oracle row and the decrypted packet to
``fairlend.audit.reconstruction`` for the actual comparison. See that
module for the DP/EO/rounding/raw-CKKS-diagnostic logic -- none of it is
duplicated here.

IMPORTANT -- this is a FRESH, INDEPENDENT run of that pipeline, NOT a
reuse of any packet ``run_encrypted_audit.py`` (or a prior run of this
script) produced: this script calls ``build_fla_context()``,
``generate_encrypted_references()``, and ``IdentityProvider.issue_
credential()`` itself, all of which are randomised/produce fresh CKKS
ciphertexts every invocation (Sec. 4.6). Consequently, the RAW decrypted
aggregate values -- and their absolute error against the plaintext oracle
-- from this script will differ, in their last few significant digits,
from any other invocation's, including ``run_encrypted_audit.py``'s. Only
the ROUNDED counts (and therefore DP/EO) are expected to be stable across
independent runs; do not describe one run's raw error as "carried
forward" from another's. See ``run_id``/``run_timestamp_utc``/
``packet_sha256`` in this script's JSON output for distinguishing
realisations, and ``evaluation/run_encrypted_audit.py``'s module
docstring for the same note in more detail.

Does NOT fit, retrain, or re-threshold any model, and does not access any
borrower-level TEST record beyond what Phase 5's own credential-issuance
step (``build_audit_frame`` + ``IdentityProvider.issue_credential``,
identical to ``run_encrypted_audit.py``) already required to build the
real encrypted aggregates in the first place -- the RECONSTRUCTION step
itself (``fairlend.audit.reconstruction``) is aggregate-only.

Usage (fixture):
    python evaluation/run_fairness_reconstruction.py \\
        --predictions results/fixture_validation/evaluation/model_predictions.parquet \\
        --plaintext-audit results/fixture_validation/evaluation/plaintext_audit.csv \\
        --synthetic-gender data/processed/fixture_validation/synthetic_gender_alpha1_0.7_seed_0.parquet \\
        --split-dir data/processed/fixture_validation/ \\
        --data-scope synthetic_fixture \\
        --output results/fixture_validation/evaluation/fairness_reconstruction.csv
"""
from __future__ import annotations

import argparse
import dataclasses
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
from fairlend.audit.reconstruction import compute_aggregate_reconstruction, compute_fairness_reconstruction
from fairlend.core.config import CKKSConfig, load_evaluation_config
from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
from fairlend.crypto.hashing import sha256_hex
from fairlend.audit.similarity import generate_encrypted_references, load_reference_vectors
from fairlend.data.loader import VALID_DATA_SCOPES, save_json, stamp_data_scope
from fairlend.models.credit_models import MODEL_NAMES
from fairlend.roles.identity_provider import IdentityProvider

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"


def _packet_sha256(packet: EncryptedAuditPacket) -> str:
    """See evaluation/run_encrypted_audit.py's identical helper -- a
    reproducibility/debugging fingerprint, not a security mechanism."""
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
    parser.add_argument("--plaintext-audit", required=True, help="Phase 2's plaintext_audit.csv (the oracle).")
    parser.add_argument("--synthetic-gender", required=True)
    parser.add_argument("--split-dir", required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument(
        "--minimum-cell-size",
        type=int,
        default=None,
        help="Overrides configs/evaluation.yaml's fairness.minimum_cell_size "
        "(default: null/unconfigured).",
    )
    parser.add_argument("--output", required=True, help="Output CSV path.")
    parser.add_argument("--output-json", default=None)
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
    """Identical orchestration to evaluation/run_encrypted_audit.py's own
    helper of the same name -- validates identity/leakage via
    build_audit_frame, then issues one real IP credential per TEST row.
    Kept as a second, independent instance here (rather than importing
    the sibling script as a module) since these are two separate CLI
    entry points; the FORMULAS these feed (fairness computation) are
    never duplicated -- only this shared plumbing is."""
    audit_frame = build_audit_frame(
        model_predictions, synthetic_gender, test_dp_index, test_eo_index, train_index, validation_index
    )
    records: List[EncryptedTestRecord] = []
    for row in audit_frame.itertuples(index=False):
        credential = ip.issue_credential(str(row.id), row.group)
        y_true = None if pd.isna(row.y_true) else int(row.y_true)
        records.append(
            EncryptedTestRecord(row_index=int(row.row_index), credential=credential, y_pred=int(row.y_pred), y_true=y_true)
        )
    return records


def _rate_dict(rate) -> dict:
    return {"value": rate.value, "available": rate.available, "reason": rate.reason}


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)
    minimum_cell_size = (
        args.minimum_cell_size if args.minimum_cell_size is not None else config.fairness.minimum_cell_size
    )

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

    flat_rows = []
    detail_rows = []
    for model_name in MODEL_NAMES:
        model_predictions = predictions[predictions["model"] == model_name]
        records = _issue_records_for_model(
            model_predictions, synthetic_gender, test_dp_index, test_eo_index, train_index, validation_index, ip
        )

        # --- Real Phase 5 pipeline, unmodified ---
        result = compute_encrypted_audit(records, ip.public_key, references, lpu_context, model_name=model_name)
        packet = build_encrypted_aggregate_packet(result)
        decrypted = decrypt_audit_packet_for_diagnostics(packet, fla_context)

        oracle_row = plaintext_audit.loc[model_name]
        agg = compute_aggregate_reconstruction(oracle_row, decrypted, model_name)
        fairness = compute_fairness_reconstruction(oracle_row, decrypted, model_name, minimum_cell_size)

        packet_fingerprint = _packet_sha256(packet)
        flat_rows.append(
            {
                "run_id": run_id,
                "run_timestamp_utc": run_timestamp_utc,
                "packet_sha256": packet_fingerprint,
                "model": model_name,
                "data_scope": args.data_scope,
                "is_real_lendingclub": args.data_scope == "real_lendingclub",
                "DP_plain": fairness.dp_plain.value,
                "DP_encrypted": fairness.dp_encrypted.value,
                "DP_reconstruction_error": fairness.dp_reconstruction_error,
                "EO_plain": fairness.eo_plain.value,
                "EO_encrypted": fairness.eo_encrypted.value,
                "EO_reconstruction_error": fairness.eo_reconstruction_error,
                "approval_rate_m_plain": fairness.approval_rate_m_plain.value,
                "approval_rate_f_plain": fairness.approval_rate_f_plain.value,
                "approval_rate_m_encrypted": fairness.approval_rate_m_encrypted.value,
                "approval_rate_f_encrypted": fairness.approval_rate_f_encrypted.value,
                "TPR_m_plain": fairness.tpr_m_plain.value,
                "TPR_f_plain": fairness.tpr_f_plain.value,
                "TPR_m_encrypted": fairness.tpr_m_encrypted.value,
                "TPR_f_encrypted": fairness.tpr_f_encrypted.value,
                "FPR_m_plain": fairness.fpr_m_plain.value,
                "FPR_f_plain": fairness.fpr_f_plain.value,
                "FPR_m_encrypted": fairness.fpr_m_encrypted.value,
                "FPR_f_encrypted": fairness.fpr_f_encrypted.value,
                "minimum_cell_size": minimum_cell_size,
                "DP_release_status_plain": fairness.dp_release_status_plain,
                "DP_release_status_encrypted": fairness.dp_release_status_encrypted,
                "EO_release_status_plain": fairness.eo_release_status_plain,
                "EO_release_status_encrypted": fairness.eo_release_status_encrypted,
                "DP_raw_ckks": fairness.dp_raw_ckks.value if fairness.dp_raw_ckks else None,
                "EO_raw_ckks": fairness.eo_raw_ckks.value if fairness.eo_raw_ckks else None,
                "DP_raw_ckks_error": fairness.dp_raw_ckks_error,
                "EO_raw_ckks_error": fairness.eo_raw_ckks_error,
                "aggregate_max_abs_error": agg.max_absolute_error,
                "aggregate_mean_abs_error": agg.mean_absolute_error,
                "all_aggregate_rounded_counts_match_plaintext": agg.all_rounded_match_plaintext,
            }
        )
        detail_rows.append(
            stamp_data_scope(
                {
                    "run_id": run_id,
                    "run_timestamp_utc": run_timestamp_utc,
                    "ckks_config": ckks_config,
                    "packet_sha256": packet_fingerprint,
                    "model": model_name,
                    "aggregate": dataclasses.asdict(agg),
                    "fairness": {
                        "dp_plain": _rate_dict(fairness.dp_plain),
                        "dp_encrypted": _rate_dict(fairness.dp_encrypted),
                        "dp_reconstruction_error": fairness.dp_reconstruction_error,
                        "eo_plain": _rate_dict(fairness.eo_plain),
                        "eo_encrypted": _rate_dict(fairness.eo_encrypted),
                        "eo_reconstruction_error": fairness.eo_reconstruction_error,
                        "dp_raw_ckks": _rate_dict(fairness.dp_raw_ckks) if fairness.dp_raw_ckks else None,
                        "eo_raw_ckks": _rate_dict(fairness.eo_raw_ckks) if fairness.eo_raw_ckks else None,
                        "dp_raw_ckks_error": fairness.dp_raw_ckks_error,
                        "eo_raw_ckks_error": fairness.eo_raw_ckks_error,
                    },
                },
                args.data_scope,
            )
        )

        print(
            f"model={model_name} run_id={run_id} packet_sha256={packet_fingerprint[:16]}... "
            f"DP_plain={fairness.dp_plain.value} DP_encrypted={fairness.dp_encrypted.value} "
            f"e_DP={fairness.dp_reconstruction_error} EO_plain={fairness.eo_plain.value} "
            f"EO_encrypted={fairness.eo_encrypted.value} e_EO={fairness.eo_reconstruction_error} "
            f"max_agg_err={agg.max_absolute_error:.3e} mean_agg_err={agg.mean_absolute_error:.3e}"
        )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(flat_rows).to_csv(output_path, index=False)
    print(f"Wrote fairness reconstruction CSV to {output_path}")

    if args.output_json:
        json_path = Path(args.output_json)
        save_json({"reports": detail_rows}, json_path)
        print(f"Wrote fairness reconstruction JSON to {json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
