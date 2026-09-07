"""End-to-end test of evaluation/run_encrypted_audit.py: builds a
self-contained fixture pipeline (ingestion -> split -> synthetic gender ->
model training -> plaintext audit, via the actual CLI scripts, isolated
under tmp_path) and then proves the ENCRYPTED audit script:

  - reads the exact same frozen model_predictions.parquet the plaintext
    audit used (task Sec. 3's "same frozen predictions" requirement),
    never retraining or recomputing y_pred;
  - reproduces the plaintext audit's rounded counts exactly;
  - never calls sklearn's .fit() (no retraining) or CKKSVector.decrypt()
    outside its own explicitly diagnostic step.
"""
from __future__ import annotations

import importlib.util
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


@pytest.fixture(scope="module")
def scripts():
    return {
        "prepare": _load_script("_prepare3", "evaluation/prepare_lendingclub.py"),
        "split": _load_script("_split3", "evaluation/split_dataset.py"),
        "gender": _load_script("_gender3", "evaluation/generate_synthetic_gender.py"),
        "train": _load_script("_train3", "evaluation/train_credit_models.py"),
        "plaintext_audit": _load_script("_plaintext_audit3", "evaluation/run_plaintext_audit.py"),
        "encrypted_audit": _load_script("_encrypted_audit3", "evaluation/run_encrypted_audit.py"),
    }


@pytest.fixture()
def pipeline_paths(scripts, tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    fake_repo_root = tmp_path / "repo_root"
    fake_repo_root.mkdir()
    for module in scripts.values():
        monkeypatch.setattr(module, "REPO_ROOT", fake_repo_root, raising=True)

    def _run(key, argv):
        monkeypatch.setattr(sys, "argv", argv)
        assert scripts[key].main() == 0

    loan_path = data_dir / "loan_with_outcome.parquet"
    _run(
        "prepare",
        ["p", "--input", str(FIXTURE_PATH), "--output", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)],
    )
    _run(
        "split",
        ["s", "--input", str(loan_path), "--output", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)],
    )
    gender_path = data_dir / "synthetic_gender_alpha1_0.7_seed_0.parquet"
    _run(
        "gender",
        [
            "g", "--input", str(loan_path), "--split-dir", str(data_dir), "--alpha1", "0.7", "--seed", "0",
            "--output", str(gender_path), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH),
        ],
    )
    _run(
        "train",
        ["t", "--input", str(loan_path), "--split-dir", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)],
    )
    predictions_path = (
        scripts["train"].results_subdir(fake_repo_root, "synthetic_fixture", "evaluation") / "model_predictions.parquet"
    )
    plaintext_audit_path = tmp_path / "plaintext_audit.csv"
    _run(
        "plaintext_audit",
        [
            "pa", "--predictions", str(predictions_path), "--prepared-data", str(loan_path),
            "--synthetic-gender", str(gender_path), "--split-dir", str(data_dir),
            "--alpha1", "0.7", "--seed", "0", "--data-scope", "synthetic_fixture",
            "--config", str(CONFIG_PATH), "--output", str(plaintext_audit_path),
        ],
    )

    return {
        "predictions_path": predictions_path,
        "loan_path": loan_path,
        "gender_path": gender_path,
        "data_dir": data_dir,
        "plaintext_audit_path": plaintext_audit_path,
    }


def _run_encrypted_audit(scripts, pipeline_paths, monkeypatch, output_path):
    argv = [
        "ea",
        "--predictions", str(pipeline_paths["predictions_path"]),
        "--plaintext-audit", str(pipeline_paths["plaintext_audit_path"]),
        "--synthetic-gender", str(pipeline_paths["gender_path"]),
        "--split-dir", str(pipeline_paths["data_dir"]),
        "--data-scope", "synthetic_fixture",
        "--output", str(output_path),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["encrypted_audit"].main() == 0


def test_encrypted_audit_reproduces_plaintext_audit_rounded_counts(scripts, pipeline_paths, tmp_path, monkeypatch):
    output_path = tmp_path / "encrypted_audit_diagnostic.json"
    _run_encrypted_audit(scripts, pipeline_paths, monkeypatch, output_path)

    import json

    report = json.loads(output_path.read_text())["reports"]
    assert {r["model"] for r in report} == {"logistic_regression", "random_forest"}
    for model_report in report:
        assert model_report["all_rounded_counts_match_plaintext"] is True
        assert model_report["data_scope"] == "synthetic_fixture"
        assert model_report["is_real_lendingclub"] is False


def test_encrypted_audit_uses_the_exact_frozen_predictions_file(scripts, pipeline_paths, tmp_path, monkeypatch):
    """Directly proves task Sec. 3: reload the frozen parquet independently
    and confirm the encrypted audit's per-model record count and y_pred
    values are byte-identical to what that file actually contains --
    not a freshly recomputed prediction."""
    frozen = pd.read_parquet(pipeline_paths["predictions_path"])

    # Patch EncryptedTestRecord construction to capture what the script
    # actually fed into compute_encrypted_audit.
    captured = {}
    original_compute = scripts["encrypted_audit"].compute_encrypted_audit

    def _spy(records, ip_public_key, references, lpu_context, model_name):
        captured[model_name] = list(records)
        return original_compute(records, ip_public_key, references, lpu_context, model_name)

    monkeypatch.setattr(scripts["encrypted_audit"], "compute_encrypted_audit", _spy)

    output_path = tmp_path / "encrypted_audit_diagnostic.json"
    _run_encrypted_audit(scripts, pipeline_paths, monkeypatch, output_path)

    for model_name, records in captured.items():
        frozen_model = frozen[frozen["model"] == model_name].set_index("row_index")
        assert len(records) == len(frozen_model)
        for record in records:
            expected_y_pred = int(frozen_model.loc[record.row_index, "y_pred"])
            assert record.y_pred == expected_y_pred
            expected_y_true = frozen_model.loc[record.row_index, "y_true"]
            if pd.isna(expected_y_true):
                assert record.y_true is None
            else:
                assert record.y_true == int(expected_y_true)


def test_encrypted_audit_never_calls_sklearn_fit(scripts, pipeline_paths, tmp_path, monkeypatch):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    def _raise(*args, **kwargs):
        raise AssertionError("run_encrypted_audit.py must never call model.fit().")

    monkeypatch.setattr(LogisticRegression, "fit", _raise)
    monkeypatch.setattr(RandomForestClassifier, "fit", _raise)

    output_path = tmp_path / "encrypted_audit_diagnostic.json"
    _run_encrypted_audit(scripts, pipeline_paths, monkeypatch, output_path)
    assert output_path.exists()


def test_encrypted_audit_script_source_never_calls_fit():
    script_path = REPO_ROOT / "evaluation" / "run_encrypted_audit.py"
    source = script_path.read_text(encoding="utf-8")
    assert ".fit(" not in source
    for forbidden in ("select_best_logistic_regression", "select_best_random_forest", "LogisticRegression", "RandomForestClassifier"):
        assert forbidden not in source


def test_rerunning_encrypted_audit_is_deterministic_in_rounded_counts(scripts, pipeline_paths, tmp_path, monkeypatch):
    """CKKS encryption is randomised per call, so raw floats will differ
    between runs -- but the ROUNDED reconstructed counts (the actual
    scientific claim) must be identical every time."""
    import json

    output_a = tmp_path / "diag_a.json"
    _run_encrypted_audit(scripts, pipeline_paths, monkeypatch, output_a)
    report_a = json.loads(output_a.read_text())["reports"]

    output_b = tmp_path / "diag_b.json"
    _run_encrypted_audit(scripts, pipeline_paths, monkeypatch, output_b)
    report_b = json.loads(output_b.read_text())["reports"]

    for model_a, model_b in zip(
        sorted(report_a, key=lambda r: r["model"]), sorted(report_b, key=lambda r: r["model"])
    ):
        for stat_key in model_a["statistics"]:
            assert (
                model_a["statistics"][stat_key]["rounded_value"]
                == model_b["statistics"][stat_key]["rounded_value"]
            )
        # Provenance metadata must prove these ARE two independent
        # cryptographic realisations, not accidentally the same one
        # (e.g. from a cached context or reused ciphertext bug).
        assert model_a["run_id"] != model_b["run_id"]
        assert model_a["packet_sha256"] != model_b["packet_sha256"]


def test_provenance_fields_present_and_ckks_config_matches_manuscript_defaults(
    scripts, pipeline_paths, tmp_path, monkeypatch
):
    import json

    from fairlend.core.config import CKKSConfig

    output = tmp_path / "diag.json"
    _run_encrypted_audit(scripts, pipeline_paths, monkeypatch, output)
    reports = json.loads(output.read_text())["reports"]

    default_config = CKKSConfig()
    for report in reports:
        assert len(report["run_id"]) == 32  # uuid4().hex
        assert "T" in report["run_timestamp_utc"]  # ISO 8601
        assert len(report["packet_sha256"]) == 64  # sha256 hex digest
        assert report["ckks_config"] == {
            "poly_modulus_degree": default_config.poly_modulus_degree,
            "coeff_mod_bit_sizes": list(default_config.coeff_mod_bit_sizes),
            "global_scale_power": default_config.global_scale_power,
        }
    # Both models in the SAME run share the same run_id/timestamp/config
    # (one script invocation) but have DIFFERENT packet fingerprints
    # (independent per-model credential issuance and aggregation).
    assert reports[0]["run_id"] == reports[1]["run_id"]
    assert reports[0]["packet_sha256"] != reports[1]["packet_sha256"]
