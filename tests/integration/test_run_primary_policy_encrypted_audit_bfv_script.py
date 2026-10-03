"""Phase 3A regression tests
(reviewer2_phase3a_bfv_realdata_validation_report.md, task item 13) for
the new BFV real-data evaluation scripts:

  - ``evaluation/run_primary_policy_encrypted_audit_bfv.py`` (per-config runner)
  - ``evaluation/run_bfv_9config_encrypted_fidelity.py`` (9-config orchestrator + data-provenance guard)

Uses the same self-contained fixture pipeline pattern as
``tests/integration/test_run_encrypted_audit_script.py``
(tests/fixtures/lendingclub_sample.csv, isolated under tmp_path) -- this
is a FIXTURE-SCALE rehearsal proving the BFV real-data scripts' mechanics
are correct; it is NOT the real 9-configuration LendingClub run (blocked
in this environment -- see the Phase 3A report's "raw dataset
unavailable" finding).
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import sys
from pathlib import Path

import pandas as pd
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "lendingclub_sample.csv"
CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"


def _load_script(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _run(module, argv):
    old_argv = sys.argv
    sys.argv = argv
    try:
        return module.main()
    finally:
        sys.argv = old_argv


# --- Structural: BFV runner cannot silently fall back to CKKS --------------


def test_bfv_runner_source_never_imports_ckks_or_legacy_names():
    """Checks the IMPORT statements specifically (not the whole file's
    prose, which legitimately discusses "fairlend.crypto.ckks" etc. when
    explaining what this script migrated FROM)."""
    import ast

    tree = ast.parse((REPO_ROOT / "evaluation" / "run_primary_policy_encrypted_audit_bfv.py").read_text(encoding="utf-8"))
    imported_modules = set()
    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
            for alias in node.names:
                imported_names.add(alias.name)

    assert "fairlend.crypto.ckks" not in imported_modules
    assert "fairlend.audit.similarity" not in imported_modules  # generate_encrypted_references/load_reference_vectors live here
    assert "IdentityProvider" not in imported_names  # only IdentityProviderBFV may be imported
    assert "CKKSConfig" not in imported_names

    assert "fairlend.crypto.bfv" in imported_modules
    assert "IdentityProviderBFV" in imported_names
    assert "BFVConfig" in imported_names


def test_legacy_ckks_script_still_points_to_its_historical_implementation():
    """Confirms evaluation/run_primary_policy_encrypted_audit.py (the
    HISTORICAL CKKS+compSim script) was NOT touched by Phase 3A -- it
    must still import the legacy compSim path under explicit aliasing,
    never the bare canonical (now-BFV) names."""
    source = (REPO_ROOT / "evaluation" / "run_primary_policy_encrypted_audit.py").read_text(encoding="utf-8")
    assert "compute_encrypted_audit_legacy_compsim as compute_encrypted_audit" in source
    assert "build_encrypted_aggregate_packet_legacy_compsim as build_encrypted_aggregate_packet" in source
    assert "decrypt_audit_packet_for_diagnostics_legacy_compsim as decrypt_audit_packet_for_diagnostics" in source
    assert "fairlend.crypto.ckks" in source
    assert "generate_encrypted_references" in source
    assert "IdentityProviderBFV" not in source


def test_orchestrator_never_calls_the_legacy_ckks_runner():
    source = (REPO_ROOT / "evaluation" / "run_bfv_9config_encrypted_fidelity.py").read_text(encoding="utf-8")
    assert "run_primary_policy_encrypted_audit.py" not in source
    assert "run_primary_policy_encrypted_audit_bfv.py" in source


# --- Stop-before-start data-provenance guard (task item 4) ------------------


def test_provenance_guard_blocks_when_raw_file_is_absent(tmp_path):
    orchestrator = _load_script("_bfv9_absent", "evaluation/run_bfv_9config_encrypted_fidelity.py")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "sha256": "deadbeef", "raw_row_count": 123, "input_path": "data/raw/does_not_exist.csv",
    }))
    missing_path = tmp_path / "does_not_exist.csv"
    blocker = orchestrator.verify_raw_dataset_provenance(missing_path, manifest_path)
    assert blocker is not None
    assert "BLOCKED" in blocker
    assert "not found" in blocker


def test_provenance_guard_blocks_on_sha256_mismatch(tmp_path):
    orchestrator = _load_script("_bfv9_mismatch", "evaluation/run_bfv_9config_encrypted_fidelity.py")
    raw_path = tmp_path / "raw.csv"
    raw_path.write_text("id,loan_status\n1,Fully Paid\n")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"sha256": "0000000000000000000000000000000000000000000000000000000000000000"[:64], "raw_row_count": 1}))
    blocker = orchestrator.verify_raw_dataset_provenance(raw_path, manifest_path)
    assert blocker is not None
    assert "does NOT match" in blocker


def test_provenance_guard_passes_when_file_and_hash_match(tmp_path):
    import hashlib

    orchestrator = _load_script("_bfv9_ok", "evaluation/run_bfv_9config_encrypted_fidelity.py")
    raw_path = tmp_path / "raw.csv"
    raw_path.write_text("id,loan_status\n1,Fully Paid\n")
    expected_sha256 = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"sha256": expected_sha256, "raw_row_count": 1}))
    blocker = orchestrator.verify_raw_dataset_provenance(raw_path, manifest_path)
    assert blocker is None


def test_orchestrator_actually_stops_against_this_repository_current_state():
    """The real, current repository state (not a fixture): data/raw/ is
    gitignored and empty in this checkout. This test proves the
    orchestrator's real entry point (parse_args + verify_raw_dataset_
    provenance, via main()) actually stops with a non-zero, distinct
    exit code and touches no credential/model/encryption call -- not
    merely that the helper function CAN detect absence in isolation."""
    orchestrator = _load_script("_bfv9_real", "evaluation/run_bfv_9config_encrypted_fidelity.py")
    rc = _run(orchestrator, ["o"])
    assert rc == 3  # this script's own documented "blocked" exit code


# --- Fixture-scale end-to-end: BFV metadata, exactness, key separation -----


@pytest.fixture(scope="module")
def bfv_pipeline_paths(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("bfv_p3a")
    prepare = _load_script("_p3a_prepare", "evaluation/prepare_lendingclub.py")
    split = _load_script("_p3a_split", "evaluation/split_dataset.py")
    gender = _load_script("_p3a_gender", "evaluation/generate_synthetic_gender.py")
    train = _load_script("_p3a_train", "evaluation/train_credit_models.py")
    bfv_runner = _load_script("_p3a_bfv_runner", "evaluation/run_primary_policy_encrypted_audit_bfv.py")

    fake_repo_root = tmp_path / "repo_root"
    fake_repo_root.mkdir()
    for module in (prepare, split, gender, train):
        module.REPO_ROOT = fake_repo_root

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    loan_path = data_dir / "loan_with_outcome.parquet"
    assert _run(prepare, ["p", "--input", str(FIXTURE_PATH), "--output", str(data_dir),
                          "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)]) == 0
    assert _run(split, ["s", "--input", str(loan_path), "--output", str(data_dir),
                        "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)]) == 0
    gender_path = data_dir / "synthetic_gender_alpha1_0.7_seed_0.parquet"
    assert _run(gender, ["g", "--input", str(loan_path), "--split-dir", str(data_dir),
                         "--alpha1", "0.7", "--seed", "0", "--output", str(gender_path),
                         "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)]) == 0
    assert _run(train, ["t", "--input", str(loan_path), "--split-dir", str(data_dir),
                        "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)]) == 0
    predictions_path = train.results_subdir(fake_repo_root, "synthetic_fixture", "evaluation") / "model_predictions.parquet"

    out_pred = tmp_path / "bfv_predictions.parquet"
    out_audit = tmp_path / "bfv_encrypted_audit.json"
    out_fair = tmp_path / "bfv_fairness_reconstruction.json"
    assert _run(bfv_runner, [
        "r", "--predictions", str(predictions_path), "--synthetic-gender", str(gender_path),
        "--split-dir", str(data_dir), "--data-scope", "synthetic_fixture", "--model", "logistic_regression",
        "--threshold-policy", "validation_f1_max", "--tau", "0.5",
        "--alpha1", "0.7", "--seed", "0", "--dataset-sha256", "fixture-test",
        "--output-predictions", str(out_pred), "--output-audit", str(out_audit), "--output-fairness", str(out_fair),
    ]) == 0

    return {"audit_path": out_audit, "fairness_path": out_fair}


def test_bfv_audit_report_identifies_scheme_correctly(bfv_pipeline_paths):
    audit = json.loads(bfv_pipeline_paths["audit_path"].read_text())
    assert audit["scheme"] == "bfv"
    assert "bfv_config" in audit
    assert audit["bfv_config"]["plain_modulus"] == 33832961
    assert "ckks_config" not in audit
    assert "reference_fingerprint" not in audit


def test_bfv_audit_no_secret_key_ever_held_by_lpu(bfv_pipeline_paths):
    audit = json.loads(bfv_pipeline_paths["audit_path"].read_text())
    assert audit["lpu_ever_held_secret_key"] is False
    assert audit["any_per_record_decryption_occurred"] is False


def test_bfv_audit_all_counts_match_plaintext_exactly(bfv_pipeline_paths):
    audit = json.loads(bfv_pipeline_paths["audit_path"].read_text())
    assert audit["all_rounded_counts_match_plaintext"] is True
    assert audit["max_absolute_error"] == 0.0
    assert audit["mean_absolute_error"] == 0.0
    for key, stat in audit["statistics"].items():
        assert stat["matches_plaintext"] is True
        assert stat["absolute_error"] == 0.0, key


def test_bfv_fairness_reconstruction_exact(bfv_pipeline_paths):
    fairness = json.loads(bfv_pipeline_paths["fairness_path"].read_text())
    assert fairness["e_DP"] == 0.0
    assert fairness["e_EO"] == 0.0


def test_bfv_overflow_guard_reported_in_audit(bfv_pipeline_paths):
    audit = json.loads(bfv_pipeline_paths["audit_path"].read_text())
    assert audit["bfv_safe_bound"] == 16916480
    assert audit["bfv_safety_factor"] > 1.0  # population is far below the safe bound
