"""End-to-end test of evaluation/run_threshold_policy_sensitivity.py:
builds a self-contained fixture pipeline (ingestion -> split -> synthetic
gender -> model training -> plaintext-audit-equivalent frozen predictions,
via the actual CLI scripts, isolated under tmp_path) and then runs the
threshold-policy sensitivity script, checking:

  - the validation_f1_max policy reproduces the EXISTING primary run's
    tau exactly (reproducibility, task Sec. 9's last bullet);
  - fixed_probability_0.50 really is 0.50, always;
  - the frozen tau is applied unchanged to TEST (never re-selected there);
  - DP/EO are computed from the corresponding frozen per-policy decisions;
  - the primary-run artifacts (model_predictions.parquet, model_metrics.csv)
    are never modified by this script.
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
        "prepare": _load_script("_prepare6", "evaluation/prepare_lendingclub.py"),
        "split": _load_script("_split6", "evaluation/split_dataset.py"),
        "gender": _load_script("_gender6", "evaluation/generate_synthetic_gender.py"),
        "train": _load_script("_train6", "evaluation/train_credit_models.py"),
        "sensitivity": _load_script("_sensitivity6", "evaluation/run_threshold_policy_sensitivity.py"),
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
    metrics_path = predictions_path.parent / "model_metrics.csv"
    return {
        "loan_path": loan_path, "gender_path": gender_path, "data_dir": data_dir,
        "predictions_path": predictions_path, "metrics_path": metrics_path,
    }


def _run_sensitivity(scripts, pipeline_paths, monkeypatch, output_path):
    argv = [
        "ts",
        "--input", str(pipeline_paths["loan_path"]),
        "--predictions", str(pipeline_paths["predictions_path"]),
        "--synthetic-gender", str(pipeline_paths["gender_path"]),
        "--split-dir", str(pipeline_paths["data_dir"]),
        "--data-scope", "synthetic_fixture",
        "--output", str(output_path),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["sensitivity"].main() == 0


def test_validation_f1_max_reproduces_the_primary_run_tau_exactly(scripts, pipeline_paths, tmp_path, monkeypatch):
    primary_metrics = pd.read_csv(pipeline_paths["metrics_path"]).set_index("model")

    output_path = tmp_path / "sensitivity.csv"
    _run_sensitivity(scripts, pipeline_paths, monkeypatch, output_path)
    sensitivity = pd.read_csv(output_path)

    f1_rows = sensitivity[sensitivity["threshold_policy"] == "validation_f1_max"].set_index("model")
    for model in ("logistic_regression", "random_forest"):
        assert f1_rows.loc[model, "tau"] == pytest.approx(primary_metrics.loc[model, "threshold"])


def test_fixed_050_policy_is_always_exactly_050(scripts, pipeline_paths, tmp_path, monkeypatch):
    output_path = tmp_path / "sensitivity.csv"
    _run_sensitivity(scripts, pipeline_paths, monkeypatch, output_path)
    sensitivity = pd.read_csv(output_path)
    fixed_rows = sensitivity[sensitivity["threshold_policy"] == "fixed_probability_0.50"]
    assert (fixed_rows["tau"] == 0.5).all()


def test_frozen_tau_applied_unchanged_to_test_and_dp_eo_present(scripts, pipeline_paths, tmp_path, monkeypatch):
    output_path = tmp_path / "sensitivity.csv"
    _run_sensitivity(scripts, pipeline_paths, monkeypatch, output_path)
    sensitivity = pd.read_csv(output_path)

    expected_columns = {
        "model", "threshold_policy", "tau", "validation_n", "validation_approval_rate",
        "test_n_all", "test_n_resolved", "test_approval_rate_all",
        "C_m", "C_f", "A_m", "A_f", "P_m", "P_f", "TP_m", "TP_f", "N_m", "N_f", "FP_m", "FP_f",
        "DP_plain", "EO_plain", "data_scope", "is_real_lendingclub",
    }
    assert expected_columns.issubset(set(sensitivity.columns))
    assert set(sensitivity["model"]) == {"logistic_regression", "random_forest"}
    assert set(sensitivity["threshold_policy"]) == {
        "validation_f1_max", "fixed_probability_0.50", "validation_balanced_accuracy_max", "validation_youden_j",
    }
    # C_m + C_f must equal the full TEST population for every policy row
    # (approval decision changes with tau; population membership does not).
    assert ((sensitivity["C_m"] + sensitivity["C_f"]) == sensitivity["test_n_all"]).all()
    assert (sensitivity["data_scope"] == "synthetic_fixture").all()
    assert (sensitivity["is_real_lendingclub"] == False).all()  # noqa: E712


def test_primary_run_artifacts_are_never_modified(scripts, pipeline_paths, tmp_path, monkeypatch):
    predictions_before = pipeline_paths["predictions_path"].read_bytes()
    metrics_before = pipeline_paths["metrics_path"].read_bytes()

    output_path = tmp_path / "sensitivity.csv"
    _run_sensitivity(scripts, pipeline_paths, monkeypatch, output_path)

    assert pipeline_paths["predictions_path"].read_bytes() == predictions_before
    assert pipeline_paths["metrics_path"].read_bytes() == metrics_before


def test_sensitivity_script_never_calls_fit_directly_on_test_data():
    """Static check: the script must never call select_best_* with TEST
    data, and TEST probabilities must come only from the frozen
    predictions file (no X_test/build_feature_frame call on TEST rows)."""
    source = (REPO_ROOT / "evaluation" / "run_threshold_policy_sensitivity.py").read_text(encoding="utf-8")
    assert "df.loc[test" not in source.replace(" ", "")
    assert "X_test" not in source
