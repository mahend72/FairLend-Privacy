#!/usr/bin/env python3
"""Phase 2 (CKKS -> BFV migration) differential comparison
(reviewer2_phase2_bfv_migration_report.md, task item 9).

Runs the SAME fixed reproducible fixture (tests/fixtures/lendingclub_sample.csv)
through three paths, for BOTH logistic_regression and random_forest:

  A. CKKS direct-additive aggregation (Phase 1 baseline,
     ``compute_encrypted_audit_ckks_direct``)
  B. BFV direct-additive aggregation (Phase 2 ACTIVE,
     ``compute_encrypted_audit``)
  C. plaintext aggregation (``compute_plaintext_audit``, the oracle)

For every group and statistic, reports: plaintext, CKKS raw (unrounded),
CKKS rounded, BFV exact, BFV-minus-plaintext, CKKS-rounded-minus-plaintext.
Also reports DP/EO for both models under all three paths.

CKKS and BFV each issue their OWN credentials from the SAME plaintext
gender labels (the two schemes cannot share a ciphertext), so this
compares the AGGREGATION RESULT on the same underlying data, not
byte-identical ciphertexts -- unlike the Phase 1 equivalence check, which
could reuse one credential set because both paths there were CKKS.

Does NOT run the expensive 9-configuration real-data sensitivity
experiment (out of Phase 2 scope).

Usage:
    python evaluation/run_ckks_vs_bfv_equivalence_check.py \\
        --output results/fixture_validation/evaluation/ckks_vs_bfv_equivalence.csv \\
        --output-summary results/fixture_validation/evaluation/ckks_vs_bfv_equivalence_summary.json
"""
from __future__ import annotations

import argparse
import importlib.util
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pandas as pd
import tenseal as ts

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "lendingclub_sample.csv"
CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"
STAT_NAMES = ("C", "A", "P", "TP", "N", "FP")


def _load_script(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _run(module, argv: List[str]) -> None:
    old_argv = sys.argv
    sys.argv = argv
    try:
        assert module.main() == 0
    finally:
        sys.argv = old_argv


def _build_fixture_pipeline(tmp_dir: Path) -> dict:
    prepare = _load_script("_dc_prepare", "evaluation/prepare_lendingclub.py")
    split = _load_script("_dc_split", "evaluation/split_dataset.py")
    gender = _load_script("_dc_gender", "evaluation/generate_synthetic_gender.py")
    train = _load_script("_dc_train", "evaluation/train_credit_models.py")
    plaintext_audit = _load_script("_dc_plaintext_audit", "evaluation/run_plaintext_audit.py")

    fake_repo_root = tmp_dir / "repo_root"
    fake_repo_root.mkdir()
    for module in (prepare, split, gender, train, plaintext_audit):
        module.REPO_ROOT = fake_repo_root

    data_dir = tmp_dir / "data"
    data_dir.mkdir()

    loan_path = data_dir / "loan_with_outcome.parquet"
    _run(prepare, ["p", "--input", str(FIXTURE_PATH), "--output", str(data_dir),
                   "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)])
    _run(split, ["s", "--input", str(loan_path), "--output", str(data_dir),
                 "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)])
    gender_path = data_dir / "synthetic_gender_alpha1_0.7_seed_0.parquet"
    _run(gender, ["g", "--input", str(loan_path), "--split-dir", str(data_dir),
                  "--alpha1", "0.7", "--seed", "0", "--output", str(gender_path),
                  "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)])
    _run(train, ["t", "--input", str(loan_path), "--split-dir", str(data_dir),
                 "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)])
    predictions_path = train.results_subdir(fake_repo_root, "synthetic_fixture", "evaluation") / "model_predictions.parquet"
    plaintext_audit_path = tmp_dir / "plaintext_audit.csv"
    _run(plaintext_audit, ["pa", "--predictions", str(predictions_path), "--prepared-data", str(loan_path),
                           "--synthetic-gender", str(gender_path), "--split-dir", str(data_dir),
                           "--alpha1", "0.7", "--seed", "0", "--data-scope", "synthetic_fixture",
                           "--config", str(CONFIG_PATH), "--output", str(plaintext_audit_path)])
    return {
        "predictions_path": predictions_path,
        "gender_path": gender_path,
        "data_dir": data_dir,
        "plaintext_audit_path": plaintext_audit_path,
    }


def _git_commit() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return None


def _git_dirty() -> bool | None:
    try:
        status = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout
        return len(status.strip()) > 0
    except Exception:
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--output-summary", required=True)
    return parser.parse_args()


def main() -> int:
    import tempfile

    from fairlend.audit.aggregation import (
        EncryptedTestRecord,
        build_audit_frame,
        build_encrypted_aggregate_packet,
        build_encrypted_aggregate_packet_ckks_direct,
        compute_encrypted_audit,
        compute_encrypted_audit_ckks_direct,
        compute_plaintext_audit,
        decrypt_audit_packet_for_diagnostics,
        decrypt_audit_packet_for_diagnostics_ckks_direct,
    )
    from fairlend.audit.fairness import compute_demographic_parity, compute_equalised_odds
    from fairlend.audit.reconstruction import encrypted_result_from_rounded_packet
    from fairlend.crypto.bfv import build_fla_context as bfv_build_fla_context, derive_lpu_context as bfv_derive_lpu_context
    from fairlend.crypto.ckks import build_fla_context as ckks_build_fla_context, derive_lpu_context as ckks_derive_lpu_context
    from fairlend.models.credit_models import MODEL_NAMES
    from fairlend.roles.identity_provider import IdentityProvider, IdentityProviderBFV

    args = parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        paths = _build_fixture_pipeline(Path(tmp))

        predictions = pd.read_parquet(paths["predictions_path"])
        synthetic_gender = pd.read_parquet(paths["gender_path"])
        plaintext_audit = pd.read_csv(paths["plaintext_audit_path"]).set_index("model")

        train_index = pd.Index(pd.read_parquet(paths["data_dir"] / "train_index.parquet")["index"])
        validation_index = pd.Index(pd.read_parquet(paths["data_dir"] / "validation_index.parquet")["index"])
        test_dp_index = pd.Index(pd.read_parquet(paths["data_dir"] / "test_index.parquet")["index"])
        test_eo_index = pd.Index(pd.read_parquet(paths["data_dir"] / "test_eo_index.parquet")["index"])

        ckks_fla = ckks_build_fla_context()
        ckks_lpu = ckks_derive_lpu_context(ckks_fla)
        ckks_ip = IdentityProvider(ckks_lpu)

        bfv_fla = bfv_build_fla_context()
        bfv_lpu = bfv_derive_lpu_context(bfv_fla)
        bfv_ip = IdentityProviderBFV(bfv_lpu)

        rows = []
        summary = []
        for model_name in MODEL_NAMES:
            model_predictions = predictions[predictions["model"] == model_name]
            audit_frame = build_audit_frame(
                model_predictions, synthetic_gender, test_dp_index, test_eo_index, train_index, validation_index
            )
            plaintext_result = compute_plaintext_audit(audit_frame, model_name=model_name)

            ckks_records: List[EncryptedTestRecord] = []
            bfv_records: List[EncryptedTestRecord] = []
            for row in audit_frame.itertuples(index=False):
                y_true = None if pd.isna(row.y_true) else int(row.y_true)
                ckks_records.append(EncryptedTestRecord(
                    row_index=int(row.row_index), credential=ckks_ip.issue_credential(str(row.id), row.group),
                    y_pred=int(row.y_pred), y_true=y_true,
                ))
                bfv_records.append(EncryptedTestRecord(
                    row_index=int(row.row_index), credential=bfv_ip.issue_credential(str(row.id), row.group),
                    y_pred=int(row.y_pred), y_true=y_true,
                ))

            ckks_result = compute_encrypted_audit_ckks_direct(ckks_records, ckks_ip.public_key, ckks_lpu, model_name=model_name)
            ckks_packet = build_encrypted_aggregate_packet_ckks_direct(ckks_result)
            ckks_decrypted = decrypt_audit_packet_for_diagnostics_ckks_direct(ckks_packet, ckks_fla)

            bfv_result = compute_encrypted_audit(bfv_records, bfv_ip.public_key, bfv_lpu, model_name=model_name)
            bfv_packet = build_encrypted_aggregate_packet(bfv_result)
            bfv_decrypted = decrypt_audit_packet_for_diagnostics(bfv_packet, bfv_fla)

            oracle = plaintext_audit.loc[model_name]
            for group, suffix in (("male", "m"), ("female", "f")):
                ckks_group = getattr(ckks_decrypted, group)
                bfv_group = getattr(bfv_decrypted, group)
                for stat in STAT_NAMES:
                    expected = int(oracle[f"{stat}_{suffix}"])
                    ckks_raw = getattr(ckks_group, stat)
                    ckks_rounded = round(ckks_raw)
                    bfv_exact = getattr(bfv_group, stat)
                    rows.append({
                        "model": model_name,
                        "group": group,
                        "statistic": stat,
                        "plaintext": expected,
                        "ckks_raw": ckks_raw,
                        "ckks_rounded": ckks_rounded,
                        "bfv_exact": bfv_exact,
                        "bfv_minus_plaintext": bfv_exact - expected,
                        "ckks_rounded_minus_plaintext": ckks_rounded - expected,
                    })

            dp_plain = compute_demographic_parity(plaintext_result)
            eo_plain = compute_equalised_odds(plaintext_result)
            ckks_plaintext_shaped = encrypted_result_from_rounded_packet(ckks_decrypted)
            bfv_plaintext_shaped = encrypted_result_from_rounded_packet(bfv_decrypted)
            dp_ckks = compute_demographic_parity(ckks_plaintext_shaped)
            eo_ckks = compute_equalised_odds(ckks_plaintext_shaped)
            dp_bfv = compute_demographic_parity(bfv_plaintext_shaped)
            eo_bfv = compute_equalised_odds(bfv_plaintext_shaped)

            model_summary = {
                "model": model_name,
                "n_records": len(ckks_records),
                "DP_plain": dp_plain.dp_gap.value,
                "DP_ckks_direct": dp_ckks.dp_gap.value,
                "DP_bfv_direct": dp_bfv.dp_gap.value,
                "EO_plain": eo_plain.eo_gap.value,
                "EO_ckks_direct": eo_ckks.eo_gap.value,
                "EO_bfv_direct": eo_bfv.eo_gap.value,
                "DP_bfv_matches_plain_exactly": dp_bfv.dp_gap.value == dp_plain.dp_gap.value,
                "EO_bfv_matches_plain_exactly": eo_bfv.eo_gap.value == eo_plain.eo_gap.value,
            }
            summary.append(model_summary)
            print(
                f"model={model_name} n_records={len(ckks_records)} "
                f"DP_plain={dp_plain.dp_gap.value} DP_ckks={dp_ckks.dp_gap.value} DP_bfv={dp_bfv.dp_gap.value} "
                f"EO_plain={eo_plain.eo_gap.value} EO_ckks={eo_ckks.eo_gap.value} EO_bfv={eo_bfv.eo_gap.value}"
            )

        df = pd.DataFrame(rows)
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"Wrote CKKS-vs-BFV per-statistic comparison to {output_path}")

        assert (df["bfv_minus_plaintext"] == 0).all(), "BFV disagrees with the plaintext oracle on a count!"

        provenance = {
            "git_commit": _git_commit(),
            "git_dirty": _git_dirty(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "python_version": sys.version,
            "tenseal_version": ts.__version__,
            "platform": platform.platform(),
        }

        import json

        summary_path = Path(args.output_summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump({"per_model": summary, "provenance": provenance}, fh, indent=2, sort_keys=True)
        print(f"Wrote DP/EO comparison summary to {summary_path}")
        if provenance["git_dirty"]:
            print("NOTE: git tree is dirty -- treat this run's numbers as PROVISIONAL, not manuscript-ready.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
