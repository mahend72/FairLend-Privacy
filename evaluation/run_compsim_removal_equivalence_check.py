#!/usr/bin/env python3
"""Phase 1 (compSim removal) equivalence check
(reviewer2_phase1_compsim_removal_report.md, item 7).

Runs BOTH the LEGACY compSim-based encrypted-audit-aggregation path
(``fairlend.audit.aggregation.compute_encrypted_audit_legacy_compsim``)
and the NEW direct encrypted-additive-aggregation path
(``fairlend.audit.aggregation.compute_encrypted_audit``) over the
IDENTICAL set of already-issued protected-attribute credentials (the same
``EncryptedTestRecord`` list is fed into both aggregation calls, so the
comparison isolates the AGGREGATION METHOD, not a fresh independent CKKS
realisation per path), on the small hermetic fixture pipeline
(tests/fixtures/lendingclub_sample.csv, the same fixture the scientific
test suite uses) -- for BOTH logistic_regression and random_forest.

Reports, for every (model, group, statistic) triple: the plaintext oracle
count, the legacy path's raw/rounded decrypted value and absolute error,
the new path's raw/rounded decrypted value and absolute error, and their
difference. Also reports DP/EO gaps computed from each path's rounded
counts.

This is a SMALL, FAST, fixture-scale sanity check. It does NOT run the
expensive 9-configuration real-data sensitivity experiment (out of Phase
1 scope) and does NOT touch any already-committed real-data result
artifact.

Usage:
    python evaluation/run_compsim_removal_equivalence_check.py \\
        --output results/fixture_validation/evaluation/compsim_removal_equivalence.csv \\
        --output-summary results/fixture_validation/evaluation/compsim_removal_equivalence_summary.json
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "lendingclub_sample.csv"
CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"
STAT_NAMES = ("C", "A", "P", "TP", "N", "FP")
GROUPS = ("male", "female")


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


def _build_fixture_pipeline(tmp_dir: Path) -> Dict[str, Path]:
    """Builds the small hermetic fixture pipeline via the ACTUAL CLI
    scripts (not a re-implementation of their logic), exactly as
    tests/integration/test_run_encrypted_audit_script.py does -- so this
    script's inputs are produced by the same code a real evaluation run
    would use, not a shortcut."""
    prepare = _load_script("_eq_prepare", "evaluation/prepare_lendingclub.py")
    split = _load_script("_eq_split", "evaluation/split_dataset.py")
    gender = _load_script("_eq_gender", "evaluation/generate_synthetic_gender.py")
    train = _load_script("_eq_train", "evaluation/train_credit_models.py")
    plaintext_audit = _load_script("_eq_plaintext_audit", "evaluation/run_plaintext_audit.py")

    fake_repo_root = tmp_dir / "repo_root"
    fake_repo_root.mkdir()
    for module in (prepare, split, gender, train, plaintext_audit):
        module.REPO_ROOT = fake_repo_root

    data_dir = tmp_dir / "data"
    data_dir.mkdir()

    loan_path = data_dir / "loan_with_outcome.parquet"
    _run(
        prepare,
        ["p", "--input", str(FIXTURE_PATH), "--output", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)],
    )
    _run(
        split,
        ["s", "--input", str(loan_path), "--output", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)],
    )
    gender_path = data_dir / "synthetic_gender_alpha1_0.7_seed_0.parquet"
    _run(
        gender,
        [
            "g", "--input", str(loan_path), "--split-dir", str(data_dir), "--alpha1", "0.7", "--seed", "0",
            "--output", str(gender_path), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH),
        ],
    )
    _run(
        train,
        ["t", "--input", str(loan_path), "--split-dir", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)],
    )
    predictions_path = train.results_subdir(fake_repo_root, "synthetic_fixture", "evaluation") / "model_predictions.parquet"
    plaintext_audit_path = tmp_dir / "plaintext_audit.csv"
    _run(
        plaintext_audit,
        [
            "pa", "--predictions", str(predictions_path), "--prepared-data", str(loan_path),
            "--synthetic-gender", str(gender_path), "--split-dir", str(data_dir),
            "--alpha1", "0.7", "--seed", "0", "--data-scope", "synthetic_fixture",
            "--config", str(CONFIG_PATH), "--output", str(plaintext_audit_path),
        ],
    )
    return {
        "predictions_path": predictions_path,
        "gender_path": gender_path,
        "data_dir": data_dir,
        "plaintext_audit_path": plaintext_audit_path,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="Output CSV path for the per-statistic comparison.")
    parser.add_argument("--output-summary", required=True, help="Output JSON path for the DP/EO comparison summary.")
    return parser.parse_args()


def main() -> int:
    import tempfile

    # NOTE (Phase 2): this script compares the LEGACY compSim path against
    # the Phase 1 CKKS-DIRECT baseline specifically -- it explicitly
    # imports the *_ckks_direct names (not the bare canonical names,
    # which as of Phase 2 refer to the BFV active path) so this Phase 1
    # comparison remains exactly what it always was, unaffected by BFV's
    # introduction. See evaluation/run_ckks_vs_bfv_equivalence_check.py
    # for the Phase 2 (CKKS-direct vs BFV-direct) comparison.
    from fairlend.audit.aggregation import (
        EncryptedTestRecord,
        build_audit_frame,
        build_encrypted_aggregate_packet_ckks_direct as build_encrypted_aggregate_packet,
        build_encrypted_aggregate_packet_legacy_compsim,
        compute_encrypted_audit_ckks_direct as compute_encrypted_audit,
        compute_encrypted_audit_legacy_compsim,
        compute_plaintext_audit,
        decrypt_audit_packet_for_diagnostics_ckks_direct as decrypt_audit_packet_for_diagnostics,
        decrypt_audit_packet_for_diagnostics_legacy_compsim,
    )
    from fairlend.audit.fairness import compute_demographic_parity, compute_equalised_odds
    from fairlend.audit.similarity import generate_encrypted_references, load_reference_vectors
    from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
    from fairlend.models.credit_models import MODEL_NAMES
    from fairlend.roles.identity_provider import IdentityProvider

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

        fla_context = build_fla_context()
        lpu_context = derive_lpu_context(fla_context)
        ip = IdentityProvider(lpu_context)
        references = load_reference_vectors(generate_encrypted_references(fla_context), lpu_context)

        rows = []
        summary = []
        for model_name in MODEL_NAMES:
            model_predictions = predictions[predictions["model"] == model_name]
            audit_frame = build_audit_frame(
                model_predictions, synthetic_gender, test_dp_index, test_eo_index, train_index, validation_index
            )
            plaintext_result = compute_plaintext_audit(audit_frame, model_name=model_name)

            records: List[EncryptedTestRecord] = []
            for row in audit_frame.itertuples(index=False):
                credential = ip.issue_credential(str(row.id), row.group)
                y_true = None if pd.isna(row.y_true) else int(row.y_true)
                records.append(
                    EncryptedTestRecord(row_index=int(row.row_index), credential=credential, y_pred=int(row.y_pred), y_true=y_true)
                )

            # LEGACY (compSim-based) path, reusing the IDENTICAL records.
            legacy_result = compute_encrypted_audit_legacy_compsim(
                records, ip.public_key, references, lpu_context, model_name=model_name
            )
            legacy_packet = build_encrypted_aggregate_packet_legacy_compsim(legacy_result)
            legacy_decrypted = decrypt_audit_packet_for_diagnostics_legacy_compsim(legacy_packet, fla_context)

            # NEW (direct-addition) path, reusing the SAME records again.
            new_result = compute_encrypted_audit(records, ip.public_key, lpu_context, model_name=model_name)
            new_packet = build_encrypted_aggregate_packet(new_result)
            new_decrypted = decrypt_audit_packet_for_diagnostics(new_packet, fla_context)

            oracle = plaintext_audit.loc[model_name]
            for group, suffix in (("male", "m"), ("female", "f")):
                legacy_group = getattr(legacy_decrypted, group)
                new_group = getattr(new_decrypted, group)
                for stat in STAT_NAMES:
                    expected = int(oracle[f"{stat}_{suffix}"])
                    legacy_raw = getattr(legacy_group, stat)
                    new_raw = getattr(new_group, stat)
                    legacy_rounded = round(legacy_raw)
                    new_rounded = round(new_raw)
                    rows.append(
                        {
                            "model": model_name,
                            "group": group,
                            "statistic": stat,
                            "plaintext_count": expected,
                            "old_raw_decrypted": legacy_raw,
                            "old_rounded": legacy_rounded,
                            "old_absolute_error": abs(legacy_raw - expected),
                            "new_raw_decrypted": new_raw,
                            "new_rounded": new_rounded,
                            "new_absolute_error": abs(new_raw - expected),
                            "old_minus_new_rounded": legacy_rounded - new_rounded,
                        }
                    )

            dp_plain = compute_demographic_parity(plaintext_result)
            eo_plain = compute_equalised_odds(plaintext_result)

            from fairlend.audit.reconstruction import encrypted_result_from_rounded_packet

            legacy_plaintext_shaped = encrypted_result_from_rounded_packet(legacy_decrypted)
            new_plaintext_shaped = encrypted_result_from_rounded_packet(new_decrypted)
            dp_legacy = compute_demographic_parity(legacy_plaintext_shaped)
            eo_legacy = compute_equalised_odds(legacy_plaintext_shaped)
            dp_new = compute_demographic_parity(new_plaintext_shaped)
            eo_new = compute_equalised_odds(new_plaintext_shaped)

            model_summary = {
                "model": model_name,
                "n_records": len(records),
                "DP_plain": dp_plain.dp_gap.value,
                "DP_legacy_compsim": dp_legacy.dp_gap.value,
                "DP_direct": dp_new.dp_gap.value,
                "EO_plain": eo_plain.eo_gap.value,
                "EO_legacy_compsim": eo_legacy.eo_gap.value,
                "EO_direct": eo_new.eo_gap.value,
                "DP_legacy_matches_plain": dp_legacy.dp_gap.value == dp_plain.dp_gap.value,
                "DP_direct_matches_plain": dp_new.dp_gap.value == dp_plain.dp_gap.value,
                "EO_legacy_matches_plain": eo_legacy.eo_gap.value == eo_plain.eo_gap.value,
                "EO_direct_matches_plain": eo_new.eo_gap.value == eo_plain.eo_gap.value,
            }
            summary.append(model_summary)
            print(
                f"model={model_name} n_records={len(records)} "
                f"DP_plain={dp_plain.dp_gap.value} DP_legacy={dp_legacy.dp_gap.value} DP_direct={dp_new.dp_gap.value} "
                f"EO_plain={eo_plain.eo_gap.value} EO_legacy={eo_legacy.eo_gap.value} EO_direct={eo_new.eo_gap.value}"
            )

        df = pd.DataFrame(rows)
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"Wrote per-statistic equivalence comparison to {output_path}")

        assert (df["old_minus_new_rounded"] == 0).all(), "Legacy and direct paths disagree on a rounded count!"

        import json

        summary_path = Path(args.output_summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump({"per_model": summary}, fh, indent=2, sort_keys=True)
        print(f"Wrote DP/EO comparison summary to {summary_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
