#!/usr/bin/env python3
"""BFV (ACTIVE protocol) primary-policy encrypted aggregation + fairness
reconstruction for ONE model under ONE frozen, already validation-selected
decision threshold (tau) -- Phase 3A
(reviewer2_phase3a_bfv_realdata_validation_report.md).

This is a MECHANICAL migration of
``evaluation/run_primary_policy_encrypted_audit.py`` (the historical,
LEGACY CKKS+compSim script, left completely UNTOUCHED -- see that
script's own PHASE 1 NOTE for why) to the ACTIVE BFV direct-addition
path. Per reviewer2_phase3a_bfv_realdata_validation_report.md's audit of
that script, the mechanical changes are:

  - CKKS context construction (``fairlend.crypto.ckks``) -> BFV
    (``fairlend.crypto.bfv``).
  - ``IdentityProvider`` (CKKS) -> ``IdentityProviderBFV``.
  - Encrypted reference vectors (``generate_encrypted_references``,
    ``load_reference_vectors``) -> REMOVED ENTIRELY. The direct-addition
    architecture (Phase 1) has no reference-vector concept in either
    CKKS or BFV form; the legacy script's ``reference_fingerprint``
    provenance field has no BFV counterpart and is replaced by an
    explicit ``"scheme": "bfv"`` field plus the BFV parameter set itself.
  - ``compute_encrypted_audit``/``build_encrypted_aggregate_packet``/
    ``decrypt_audit_packet_for_diagnostics`` (legacy 12-ciphertext,
    male/female-nested) -> the canonical (Phase 2, BFV) 6-ciphertext,
    flat-field versions.
  - ``CKKSConfig`` -> ``BFVConfig``, plus an EXPLICIT modular-overflow
    check (``assert_population_within_bfv_safe_bound``) run and logged
    BEFORE the long encrypted-aggregation loop starts (in addition to
    the SAME guard ``compute_encrypted_audit`` itself already enforces
    internally -- belt and suspenders, so a too-large population is
    refused with a clear message before any credential is even issued,
    not partway through a multi-hour run).

Everything else is UNCHANGED from the legacy script, because it was
already scheme-agnostic (verified during the Phase 3A audit, not
assumed): frozen predictions/tau handling, plaintext oracle computation
(``fairlend.audit.aggregation.build_audit_frame``/
``compute_plaintext_audit``, ``fairlend.audit.fairness``), and DP/EO
reconstruction (``fairlend.audit.reconstruction.compute_aggregate_
reconstruction``/``compute_fairness_reconstruction``, which operate only
on the scheme-agnostic ``DecryptedAuditPacket``/``DecryptedGroupAuditCounts``
shape both CKKS and BFV produce identically). This script does NOT
retrain, retune, or reselect tau/threshold-policy/split/preprocessing --
every one of those is read from the SAME frozen artifacts the legacy
script reads.

NAMING QUIRK, DOCUMENTED RATHER THAN HIDDEN: ``fairlend.audit.
reconstruction``'s output fields are named ``DP_raw_ckks``/``EO_raw_ckks``
for historical (CKKS-era) reasons, even though this script feeds them
BFV-decrypted values. For BFV these fields are NOT a "raw vs. rounded"
distinction the way they are for CKKS (which has real approximation
noise): BFV decryption is already exact, so the "raw" and "rounded"
paths coincide exactly here (verified in Phase 2 and re-verified per-run
below). Field names were NOT changed in the shared ``reconstruction.py``
module for this phase, since that module is shared with the (unchanged)
CKKS scripts and renaming it is out of this phase's scope.

STOP CONDITION (unchanged from the legacy script): if any of the 12
rounded decrypted aggregates does not exactly equal its plaintext
counterpart, this script writes the aggregate report (clearly flagging
the mismatch), does NOT compute or write the fairness-reconstruction
artifact, and exits non-zero. For BFV, "rounded" and "raw" are the same
exact integer, so this condition is equivalent to "any BFV count
disagrees with plaintext at all" -- no tolerance is introduced.

This script does NOT check raw-data availability/provenance itself --
see ``evaluation/run_bfv_9config_encrypted_fidelity.py``, which performs
that check ONCE before invoking this script for each of the 9
configurations, and refuses to proceed (per reviewer2_phase3a's task
constraints) if the raw dataset is absent or does not match the tracked
manifest.

Usage:
    python evaluation/run_primary_policy_encrypted_audit_bfv.py \\
        --predictions results/evaluation/model_predictions.parquet \\
        --synthetic-gender data/processed/synthetic_gender_alpha1_0.7_seed_0.parquet \\
        --split-dir data/processed/ \\
        --data-scope real_lendingclub \\
        --model logistic_regression \\
        --threshold-policy validation_balanced_accuracy_max \\
        --tau 0.80 \\
        --alpha1 0.7 --seed 0 \\
        --dataset-sha256 <sha256> \\
        --output-predictions results/evaluation/bfv_lr_alpha0.7_seed0_predictions.parquet \\
        --output-audit results/evaluation/bfv_lr_alpha0.7_seed0_encrypted_audit.json \\
        --output-fairness results/evaluation/bfv_lr_alpha0.7_seed0_fairness_reconstruction.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

import pandas as pd

from fairlend.audit.aggregation import (
    EncryptedTestRecord,
    assert_population_within_bfv_safe_bound,
    build_audit_frame,
    build_encrypted_aggregate_packet,
    compute_encrypted_audit,
    compute_plaintext_audit,
    decrypt_audit_packet_for_diagnostics,
)
from fairlend.audit.fairness import compute_demographic_parity, compute_equalised_odds
from fairlend.audit.reconstruction import compute_aggregate_reconstruction, compute_fairness_reconstruction
from fairlend.core.config import BFVConfig
from fairlend.core.exceptions import BFVOverflowError
from fairlend.crypto.bfv import build_fla_context, context_can_decrypt, derive_lpu_context
from fairlend.crypto.hashing import sha256_hex
from fairlend.data.loader import VALID_DATA_SCOPES, stamp_data_scope
from fairlend.models.credit_models import MODEL_NAMES
from fairlend.roles.identity_provider import IdentityProviderBFV

REPO_ROOT = Path(__file__).resolve().parents[1]
STAT_NAMES = ("C", "A", "P", "TP", "N", "FP")
GROUP_SUFFIXES = ("m", "f")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", required=True, help="Frozen model_predictions.parquet.")
    parser.add_argument("--synthetic-gender", required=True)
    parser.add_argument("--split-dir", required=True)
    parser.add_argument("--data-scope", required=True, choices=VALID_DATA_SCOPES)
    parser.add_argument("--model", required=True, choices=MODEL_NAMES)
    parser.add_argument(
        "--threshold-policy",
        required=True,
        help="Label only (e.g. validation_balanced_accuracy_max) -- provenance/labelling, "
        "does not affect computation. tau is taken solely from --tau.",
    )
    parser.add_argument("--tau", type=float, required=True, help="Frozen, already validation-selected decision threshold.")
    parser.add_argument("--alpha1", type=float, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--dataset-sha256", default=None)
    parser.add_argument("--output-predictions", required=True)
    parser.add_argument("--output-audit", required=True)
    parser.add_argument("--output-fairness", required=True)
    parser.add_argument("--progress-every", type=int, default=5000)
    return parser.parse_args()


def _read_index(path: Path) -> pd.Index:
    return pd.Index(pd.read_parquet(path)["index"])


def _git_commit() -> Optional[str]:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return None


def _git_dirty() -> Optional[bool]:
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout
        return len(status.strip()) > 0
    except Exception:
        return None


def _bfv_config_dict(config: BFVConfig) -> dict:
    return {
        "poly_modulus_degree": config.poly_modulus_degree,
        "plain_modulus": config.plain_modulus,
        "coeff_mod_bit_sizes": list(config.coeff_mod_bit_sizes),
        "max_safe_count": config.max_safe_count,
    }


def _atomic_write_json(data: dict, path: Path) -> None:
    """Write-then-rename: a reader never observes a partially-written
    file, and a crash mid-write never corrupts a prior successful
    artifact at ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, default=str)
    os.replace(tmp_path, path)


def _atomic_write_parquet(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    df.to_parquet(tmp_path, index=False)
    os.replace(tmp_path, path)


class _LazyEncryptedRecordsBFV:
    """BFV counterpart of ``run_primary_policy_encrypted_audit.py``'s
    ``_LazyEncryptedRecords`` -- kept as a second, independent instance
    here (rather than importing the sibling script as a module) since
    these are two separate CLI entry points, exactly the same precedent
    ``evaluation/run_fairness_reconstruction.py`` already follows for its
    own ``_issue_records_for_model`` helper. Issues each IP credential
    only at iteration time, one at a time -- never materializing every
    TEST row's credential simultaneously; a real BFV credential
    ciphertext is on the order of a few hundred KB (measured: ~432 KB in
    Phase 2), so eagerly building the list for the full real TEST
    population (~177k rows) would still risk the same OOM failure this
    streaming design was originally built to fix.

    Memory footprint while consumed by ``compute_encrypted_audit`` is
    bounded by: the fixed-size 6-ciphertext running aggregate state (half
    the legacy path's 12, since BFV/direct-addition packs both groups
    into each statistic's single ciphertext) plus whichever single
    credential is currently alive -- never O(TEST population size)
    ciphertext objects.
    """

    def __init__(
        self,
        audit_frame: pd.DataFrame,
        ip: IdentityProviderBFV,
        progress_every: int = 5000,
        run_meta_path: Optional[Path] = None,
        run_meta_base: Optional[dict] = None,
    ):
        self._audit_frame = audit_frame
        self._ip = ip
        self._progress_every = max(1, progress_every)
        self._run_meta_path = run_meta_path
        self._run_meta_base = run_meta_base or {}

    def __len__(self) -> int:
        return len(self._audit_frame)

    def __iter__(self) -> Iterator[EncryptedTestRecord]:
        total = len(self._audit_frame)
        start = time.perf_counter()
        for i, row in enumerate(self._audit_frame.itertuples(index=False), start=1):
            credential = self._ip.issue_credential(str(row.id), row.group)
            y_true = None if pd.isna(row.y_true) else int(row.y_true)
            yield EncryptedTestRecord(
                row_index=int(row.row_index), credential=credential, y_pred=int(row.y_pred), y_true=y_true
            )
            if i % self._progress_every == 0 or i == total:
                elapsed = time.perf_counter() - start
                rate = i / elapsed if elapsed > 0 else float("inf")
                eta = (total - i) / rate if rate > 0 else float("inf")
                print(
                    f"  progress: {i}/{total} ({100 * i / total:.1f}%) "
                    f"elapsed={elapsed:.1f}s rate={rate:.2f} rec/s eta={eta:.0f}s",
                    flush=True,
                )
                if self._run_meta_path is not None:
                    _atomic_write_json(
                        {
                            **self._run_meta_base,
                            "status": "running",
                            "records_processed": i,
                            "records_total": total,
                            "elapsed_seconds": elapsed,
                            "records_per_second": rate,
                            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
                        },
                        self._run_meta_path,
                    )


def main() -> int:
    args = parse_args()

    predictions = pd.read_parquet(args.predictions)
    synthetic_gender = pd.read_parquet(args.synthetic_gender)

    split_dir = Path(args.split_dir)
    train_index = _read_index(split_dir / "train_index.parquet")
    validation_index = _read_index(split_dir / "validation_index.parquet")
    test_dp_index = _read_index(split_dir / "test_index.parquet")
    test_eo_index = _read_index(split_dir / "test_eo_index.parquet")

    model_predictions = predictions[predictions["model"] == args.model].copy()
    if model_predictions.empty:
        raise ValueError(f"No predictions found for model={args.model!r}.")

    # --- Step 1: primary-policy frozen decisions (tau applied to frozen
    # y_proba; y_proba itself is untouched, model is never refit). ---
    model_predictions["y_pred"] = (model_predictions["y_proba"] >= args.tau).astype(int)
    model_predictions["threshold_policy"] = args.threshold_policy
    model_predictions["tau"] = args.tau

    n_test = int(len(model_predictions))
    n_approved = int(model_predictions["y_pred"].sum())
    approval_rate = n_approved / n_test
    print(
        f"model={args.model} threshold_policy={args.threshold_policy} tau={args.tau} "
        f"TEST approval count={n_approved}/{n_test} rate={approval_rate:.6f} (before any encryption)"
    )

    # --- Modular-overflow guard (task item 10): check and log BEFORE
    # starting the long encrypted-aggregation loop, in addition to the
    # SAME guard compute_encrypted_audit enforces internally. ---
    bfv_config = BFVConfig()
    safe_bound = bfv_config.max_safe_count
    safety_factor = safe_bound / n_test if n_test > 0 else float("inf")
    print(f"BFV overflow guard: population={n_test} safe_bound={safe_bound} safety_factor={safety_factor:.2f}x")
    try:
        assert_population_within_bfv_safe_bound(n_test, bfv_config)
    except BFVOverflowError as exc:
        print(f"STOP: {exc}")
        return 2

    predictions_output_path = Path(args.output_predictions)
    _atomic_write_parquet(
        model_predictions[["row_index", "id", "model", "y_true", "y_proba", "y_pred", "threshold_policy", "tau"]],
        predictions_output_path,
    )
    print(f"Wrote primary-policy prediction artifact to {predictions_output_path}")

    # --- Step 2: plaintext primary-policy oracle. ---
    audit_frame = build_audit_frame(
        model_predictions[["row_index", "id", "y_true", "y_pred"]],
        synthetic_gender,
        test_dp_index=test_dp_index,
        test_eo_index=test_eo_index,
        train_index=train_index,
        validation_index=validation_index,
    )
    plaintext_result = compute_plaintext_audit(audit_frame, model_name=args.model)
    dp_plain = compute_demographic_parity(plaintext_result)
    eo_plain = compute_equalised_odds(plaintext_result)
    m, f = plaintext_result.male(), plaintext_result.female()

    oracle_row = {
        "C_m": m.C, "C_f": f.C,
        "A_m": m.A, "A_f": f.A,
        "P_m": m.P, "P_f": f.P,
        "TP_m": m.TP, "TP_f": f.TP,
        "N_m": m.N, "N_f": f.N,
        "FP_m": m.FP, "FP_f": f.FP,
        "test_population_n": plaintext_result.full_test_n,
        "resolved_test_n": plaintext_result.resolved_test_n,
        "unresolved_test_n": plaintext_result.unresolved_test_n,
    }
    print(
        f"PLAINTEXT ORACLE (tau={args.tau}): "
        f"C_m={m.C} C_f={f.C} A_m={m.A} A_f={f.A} P_m={m.P} P_f={f.P} "
        f"TP_m={m.TP} TP_f={f.TP} N_m={m.N} N_f={f.N} FP_m={m.FP} FP_f={f.FP} "
        f"DP_plain={dp_plain.dp_gap.value} EO_plain={eo_plain.eo_gap.value}"
    )

    # --- Provenance / run metadata (written now, before the long
    # encrypted-aggregation loop -- see _LazyEncryptedRecordsBFV). ---
    run_id = uuid.uuid4().hex
    run_timestamp_utc = datetime.now(timezone.utc).isoformat()
    git_commit = _git_commit()
    git_dirty = _git_dirty()
    bfv_config_dict = _bfv_config_dict(bfv_config)

    run_meta_base = {
        "scheme": "bfv",
        "run_id": run_id,
        "run_timestamp_utc": run_timestamp_utc,
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "dataset_sha256": args.dataset_sha256,
        "model": args.model,
        "threshold_policy": args.threshold_policy,
        "tau": args.tau,
        "alpha1": args.alpha1,
        "synthetic_seed": args.seed,
        "bfv_config": bfv_config_dict,
        "bfv_safe_bound": safe_bound,
        "bfv_safety_factor": safety_factor,
        "data_scope": args.data_scope,
    }
    audit_output_path = Path(args.output_audit)
    run_meta_path = audit_output_path.with_name(audit_output_path.stem + "_run_meta.json")
    _atomic_write_json(
        {**run_meta_base, "status": "running", "records_processed": 0, "records_total": n_test},
        run_meta_path,
    )
    print(f"Wrote run metadata to {run_meta_path}")

    # --- Step 3/4: real encrypted aggregation, streamed/lazy (memory
    # model: fixed aggregate state + current record only). ---
    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    lpu_holds_secret_key = context_can_decrypt(lpu_context)
    ip = IdentityProviderBFV(lpu_context)

    lazy_records = _LazyEncryptedRecordsBFV(
        audit_frame, ip, progress_every=args.progress_every, run_meta_path=run_meta_path, run_meta_base=run_meta_base
    )

    print(f"Starting BFV encrypted aggregation over {n_test} TEST records...")
    start = time.perf_counter()
    result = compute_encrypted_audit(lazy_records, ip.public_key, lpu_context, model_name=args.model, bfv_config=bfv_config)
    elapsed_seconds = time.perf_counter() - start
    records_per_second = n_test / elapsed_seconds if elapsed_seconds > 0 else float("inf")
    print(f"Encrypted aggregation finished in {elapsed_seconds:.1f}s ({records_per_second:.2f} rec/s).")

    packet = build_encrypted_aggregate_packet(result)
    ordered_ciphertexts = (packet.C, packet.A, packet.P, packet.TP, packet.N, packet.FP)
    packet_sha256 = sha256_hex(b"".join(ordered_ciphertexts))

    # --- Step 6: FLA decryption (aggregate-only packet in; per-group
    # decrypted floats out -- no per-record decryption ever occurs). BFV
    # decryption is EXACT: no rounding is needed to recover the integer
    # count, verified per-statistic below rather than assumed. ---
    decrypted = decrypt_audit_packet_for_diagnostics(packet, fla_context)
    agg = compute_aggregate_reconstruction(oracle_row, decrypted, args.model)

    per_stat = {}
    for group_suffix in GROUP_SUFFIXES:
        for stat in STAT_NAMES:
            key = f"{stat}_{group_suffix}"
            per_stat[key] = {
                "plaintext_count": agg.plaintext[key],
                "raw_decrypted_count": agg.raw_decrypted[key],
                "rounded_encrypted_count": agg.rounded[key],
                "absolute_error": agg.absolute_error[key],
                "matches_plaintext": agg.rounded[key] == agg.plaintext[key],
            }
            if agg.raw_decrypted[key] != agg.rounded[key]:
                raise AssertionError(
                    f"BFV decryption for {key} was not exact ({agg.raw_decrypted[key]!r} != "
                    f"{agg.rounded[key]!r}) -- this must never happen and indicates a bug, not an "
                    "approximation to tolerate."
                )
            print(
                f"  {key}: plaintext={per_stat[key]['plaintext_count']} "
                f"bfv_exact={per_stat[key]['raw_decrypted_count']:.1f} "
                f"abs_err={per_stat[key]['absolute_error']:.3e} "
                f"match={per_stat[key]['matches_plaintext']}"
            )

    all_match = agg.all_rounded_match_plaintext
    audit_report = stamp_data_scope(
        {
            **run_meta_base,
            "status": "completed" if all_match else "stopped_mismatch",
            "packet_sha256": packet_sha256,
            "packet_protocol_version": packet.protocol_version,
            "test_population_n": decrypted.test_population_n,
            "resolved_test_n": decrypted.resolved_test_n,
            "unresolved_test_n": decrypted.unresolved_test_n,
            "eo_coverage_fraction": decrypted.resolved_test_n / decrypted.test_population_n if decrypted.test_population_n else None,
            "test_approval_count": n_approved,
            "test_approval_rate": approval_rate,
            "runtime_seconds": elapsed_seconds,
            "records_per_second": records_per_second,
            "max_absolute_error": agg.max_absolute_error,
            "mean_absolute_error": agg.mean_absolute_error,
            "all_rounded_counts_match_plaintext": all_match,
            "lpu_ever_held_secret_key": lpu_holds_secret_key,
            "any_per_record_decryption_occurred": False,
            "statistics": per_stat,
        },
        args.data_scope,
    )
    _atomic_write_json(audit_report, audit_output_path)
    print(f"Wrote encrypted audit report to {audit_output_path}")
    _atomic_write_json({**run_meta_base, "status": audit_report["status"], "records_processed": n_test, "records_total": n_test}, run_meta_path)

    if not all_match:
        mismatched = [k for k, v in per_stat.items() if not v["matches_plaintext"]]
        print(f"STOP: BFV count != plaintext count for: {mismatched}. Not computing fairness reconstruction.")
        return 1

    # --- Step 7: real fairness reconstruction (production path; for BFV
    # the "raw" and "rounded" paths are identical -- see this script's
    # module docstring's "NAMING QUIRK" note). ---
    fairness = compute_fairness_reconstruction(oracle_row, decrypted, args.model, minimum_cell_size=None)
    e_dp = fairness.dp_reconstruction_error
    e_eo = fairness.eo_reconstruction_error
    if e_dp not in (0, 0.0) or e_eo not in (0, 0.0):
        raise AssertionError(
            f"BFV fairness reconstruction was not exact (e_DP={e_dp}, e_EO={e_eo}) -- this must never "
            "happen for an exact integer scheme and indicates a bug, not an approximation to tolerate."
        )
    print(
        f"DP_plain={fairness.dp_plain.value} DP_encrypted={fairness.dp_encrypted.value} e_DP={e_dp} "
        f"EO_plain={fairness.eo_plain.value} EO_encrypted={fairness.eo_encrypted.value} e_EO={e_eo}"
    )

    fairness_report = stamp_data_scope(
        {
            **run_meta_base,
            "packet_sha256": packet_sha256,
            "DP_plain": fairness.dp_plain.value,
            "DP_encrypted": fairness.dp_encrypted.value,
            "e_DP": e_dp,
            "EO_plain": fairness.eo_plain.value,
            "EO_encrypted": fairness.eo_encrypted.value,
            "e_EO": e_eo,
            "approval_rate_m_plain": fairness.approval_rate_m_plain.value,
            "approval_rate_f_plain": fairness.approval_rate_f_plain.value,
            "approval_rate_m_encrypted": fairness.approval_rate_m_encrypted.value,
            "approval_rate_f_encrypted": fairness.approval_rate_f_encrypted.value,
            "minimum_cell_size": fairness.minimum_cell_size,
            "DP_release_status_plain": fairness.dp_release_status_plain,
            "DP_release_status_encrypted": fairness.dp_release_status_encrypted,
            "EO_release_status_plain": fairness.eo_release_status_plain,
            "EO_release_status_encrypted": fairness.eo_release_status_encrypted,
        },
        args.data_scope,
    )
    _atomic_write_json(fairness_report, Path(args.output_fairness))
    print(f"Wrote fairness reconstruction report to {args.output_fairness}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
