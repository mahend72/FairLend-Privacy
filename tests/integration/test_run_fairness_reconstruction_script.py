"""End-to-end test of evaluation/run_fairness_reconstruction.py: builds a
self-contained fixture pipeline (ingestion -> split -> synthetic gender ->
model training -> plaintext audit, via the actual CLI scripts, isolated
under tmp_path) and then:

  - runs the fairness reconstruction script and checks its CSV/JSON output;
  - independently re-derives DP/EO from the script's own reported rounded
    encrypted counts using plain Python (task Sec. 17), comparing
    digit-for-digit against the script's DP_encrypted/EO_encrypted;
  - proves no model retraining occurs.
"""
from __future__ import annotations

import importlib.util
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


@pytest.fixture(scope="module")
def scripts():
    return {
        "prepare": _load_script("_prepare4", "evaluation/prepare_lendingclub.py"),
        "split": _load_script("_split4", "evaluation/split_dataset.py"),
        "gender": _load_script("_gender4", "evaluation/generate_synthetic_gender.py"),
        "train": _load_script("_train4", "evaluation/train_credit_models.py"),
        "plaintext_audit": _load_script("_plaintext_audit4", "evaluation/run_plaintext_audit.py"),
        "reconstruction": _load_script("_reconstruction4", "evaluation/run_fairness_reconstruction.py"),
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
    _run("prepare", ["p", "--input", str(FIXTURE_PATH), "--output", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)])
    _run("split", ["s", "--input", str(loan_path), "--output", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)])
    gender_path = data_dir / "synthetic_gender_alpha1_0.7_seed_0.parquet"
    _run(
        "gender",
        ["g", "--input", str(loan_path), "--split-dir", str(data_dir), "--alpha1", "0.7", "--seed", "0",
         "--output", str(gender_path), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)],
    )
    _run("train", ["t", "--input", str(loan_path), "--split-dir", str(data_dir), "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH)])
    predictions_path = scripts["train"].results_subdir(fake_repo_root, "synthetic_fixture", "evaluation") / "model_predictions.parquet"
    plaintext_audit_path = tmp_path / "plaintext_audit.csv"
    _run(
        "plaintext_audit",
        ["pa", "--predictions", str(predictions_path), "--prepared-data", str(loan_path),
         "--synthetic-gender", str(gender_path), "--split-dir", str(data_dir),
         "--alpha1", "0.7", "--seed", "0", "--data-scope", "synthetic_fixture",
         "--config", str(CONFIG_PATH), "--output", str(plaintext_audit_path)],
    )
    return {
        "predictions_path": predictions_path, "gender_path": gender_path,
        "data_dir": data_dir, "plaintext_audit_path": plaintext_audit_path,
    }


def _run_reconstruction(scripts, pipeline_paths, monkeypatch, output_csv, output_json):
    argv = [
        "fr",
        "--predictions", str(pipeline_paths["predictions_path"]),
        "--plaintext-audit", str(pipeline_paths["plaintext_audit_path"]),
        "--synthetic-gender", str(pipeline_paths["gender_path"]),
        "--split-dir", str(pipeline_paths["data_dir"]),
        "--data-scope", "synthetic_fixture",
        "--output", str(output_csv),
        "--output-json", str(output_json),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["reconstruction"].main() == 0


def test_reconstruction_csv_has_zero_error_for_both_models(scripts, pipeline_paths, tmp_path, monkeypatch):
    output_csv = tmp_path / "fairness_reconstruction.csv"
    output_json = tmp_path / "fairness_reconstruction.json"
    _run_reconstruction(scripts, pipeline_paths, monkeypatch, output_csv, output_json)

    df = pd.read_csv(output_csv)
    assert set(df["model"]) == {"logistic_regression", "random_forest"}
    for _, row in df.iterrows():
        assert row["DP_reconstruction_error"] == 0.0
        assert row["EO_reconstruction_error"] == 0.0
        assert row["DP_plain"] == row["DP_encrypted"]
        assert row["EO_plain"] == row["EO_encrypted"]
        assert row["DP_release_status_plain"] == "minimum_cell_size_not_configured"
        assert row["DP_release_status_encrypted"] == "minimum_cell_size_not_configured"
        assert row["data_scope"] == "synthetic_fixture"
        assert row["is_real_lendingclub"] == False  # noqa: E712


def test_independent_rederivation_of_dp_eo_matches_script_output(scripts, pipeline_paths, tmp_path, monkeypatch):
    """Task Sec. 17: recompute DP/EO directly from the script's own
    reported ROUNDED encrypted counts, using plain Python arithmetic
    entirely independent of fairlend.audit.fairness, and compare
    digit-for-digit."""
    output_csv = tmp_path / "fairness_reconstruction.csv"
    output_json = tmp_path / "fairness_reconstruction.json"
    _run_reconstruction(scripts, pipeline_paths, monkeypatch, output_csv, output_json)

    csv_df = pd.read_csv(output_csv).set_index("model")
    detail = json.loads(output_json.read_text())["reports"]

    for report in detail:
        model = report["model"]
        rounded = report["aggregate"]["rounded"]
        C_m, C_f = rounded["C_m"], rounded["C_f"]
        A_m, A_f = rounded["A_m"], rounded["A_f"]
        P_m, P_f = rounded["P_m"], rounded["P_f"]
        TP_m, TP_f = rounded["TP_m"], rounded["TP_f"]
        N_m, N_f = rounded["N_m"], rounded["N_f"]
        FP_m, FP_f = rounded["FP_m"], rounded["FP_f"]

        independent_dp = abs((A_f / C_f) - (A_m / C_m))
        independent_tpr_m = TP_m / P_m
        independent_tpr_f = TP_f / P_f
        independent_fpr_m = FP_m / N_m
        independent_fpr_f = FP_f / N_f
        independent_eo = max(abs(independent_tpr_f - independent_tpr_m), abs(independent_fpr_f - independent_fpr_m))

        script_dp = csv_df.loc[model, "DP_encrypted"]
        script_eo = csv_df.loc[model, "EO_encrypted"]

        assert independent_dp == pytest.approx(script_dp, abs=1e-15)
        assert independent_eo == pytest.approx(script_eo, abs=1e-15)
        # And, per task Sec. 9, both must also equal the plaintext value.
        assert independent_dp == pytest.approx(csv_df.loc[model, "DP_plain"], abs=1e-15)
        assert independent_eo == pytest.approx(csv_df.loc[model, "EO_plain"], abs=1e-15)


def test_reconstruction_script_never_calls_sklearn_fit(scripts, pipeline_paths, tmp_path, monkeypatch):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    def _raise(*args, **kwargs):
        raise AssertionError("run_fairness_reconstruction.py must never call model.fit().")

    monkeypatch.setattr(LogisticRegression, "fit", _raise)
    monkeypatch.setattr(RandomForestClassifier, "fit", _raise)

    output_csv = tmp_path / "fairness_reconstruction.csv"
    output_json = tmp_path / "fairness_reconstruction.json"
    _run_reconstruction(scripts, pipeline_paths, monkeypatch, output_csv, output_json)
    assert output_csv.exists()


def test_reconstruction_script_source_never_calls_fit():
    script_path = REPO_ROOT / "evaluation" / "run_fairness_reconstruction.py"
    source = script_path.read_text(encoding="utf-8")
    assert ".fit(" not in source
    for forbidden in ("select_best_logistic_regression", "select_best_random_forest", "LogisticRegression", "RandomForestClassifier"):
        assert forbidden not in source


def test_output_csv_has_the_requested_columns(scripts, pipeline_paths, tmp_path, monkeypatch):
    output_csv = tmp_path / "fairness_reconstruction.csv"
    output_json = tmp_path / "fairness_reconstruction.json"
    _run_reconstruction(scripts, pipeline_paths, monkeypatch, output_csv, output_json)
    df = pd.read_csv(output_csv)
    expected_columns = {
        "model", "data_scope", "is_real_lendingclub",
        "DP_plain", "DP_encrypted", "DP_reconstruction_error",
        "EO_plain", "EO_encrypted", "EO_reconstruction_error",
        "approval_rate_m_plain", "approval_rate_f_plain", "approval_rate_m_encrypted", "approval_rate_f_encrypted",
        "TPR_m_plain", "TPR_f_plain", "TPR_m_encrypted", "TPR_f_encrypted",
        "FPR_m_plain", "FPR_f_plain", "FPR_m_encrypted", "FPR_f_encrypted",
        "minimum_cell_size", "DP_release_status_plain", "DP_release_status_encrypted",
        "EO_release_status_plain", "EO_release_status_encrypted",
        "aggregate_max_abs_error", "aggregate_mean_abs_error",
    }
    assert expected_columns.issubset(set(df.columns))


def test_two_runs_have_different_provenance_but_identical_reconstruction_result(
    scripts, pipeline_paths, tmp_path, monkeypatch
):
    """Reproduces, as a checked-in test, the exact investigation that
    found run_encrypted_audit.py and run_fairness_reconstruction.py
    report different raw aggregate errors: each is an independent CKKS
    realisation (different run_id, different packet_sha256), yet the
    ROUNDED reconstruction (DP/EO and their reconstruction error) is
    stable across runs regardless."""
    csv_a, json_a = tmp_path / "a.csv", tmp_path / "a.json"
    _run_reconstruction(scripts, pipeline_paths, monkeypatch, csv_a, json_a)
    csv_b, json_b = tmp_path / "b.csv", tmp_path / "b.json"
    _run_reconstruction(scripts, pipeline_paths, monkeypatch, csv_b, json_b)

    df_a = pd.read_csv(csv_a, float_precision="round_trip").set_index("model")
    df_b = pd.read_csv(csv_b, float_precision="round_trip").set_index("model")

    for model in df_a.index:
        assert df_a.loc[model, "run_id"] != df_b.loc[model, "run_id"]
        assert df_a.loc[model, "packet_sha256"] != df_b.loc[model, "packet_sha256"]
        # The raw aggregate error magnitude is NOT required to match --
        # only the rounded-count-derived DP/EO reconstruction is.
        assert df_a.loc[model, "DP_encrypted"] == df_b.loc[model, "DP_encrypted"]
        assert df_a.loc[model, "EO_encrypted"] == df_b.loc[model, "EO_encrypted"]
        assert df_a.loc[model, "DP_reconstruction_error"] == 0.0
        assert df_b.loc[model, "DP_reconstruction_error"] == 0.0
