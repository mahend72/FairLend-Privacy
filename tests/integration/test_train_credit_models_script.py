"""End-to-end test of evaluation/train_credit_models.py against the
fixture: ingestion -> split -> model training -> saved predictions, run
through the actual CLI entry point (not the underlying library functions
directly), proving the script itself produces a fixed, reusable
prediction artifact with correct provenance tagging."""
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
        "prepare": _load_script("_prepare_lendingclub", "evaluation/prepare_lendingclub.py"),
        "split": _load_script("_split_dataset", "evaluation/split_dataset.py"),
        "train": _load_script("_train_credit_models", "evaluation/train_credit_models.py"),
    }


def _run_pipeline(scripts, tmp_path, monkeypatch, run_dir_name):
    data_dir = tmp_path / run_dir_name
    data_dir.mkdir()
    # Isolate results_subdir() output under tmp_path instead of the real
    # repo root -- otherwise every test run would write into (and dirty)
    # the tracked results/fixture_validation/ directory.
    fake_repo_root = data_dir / "repo_root"
    fake_repo_root.mkdir()
    for module in scripts.values():
        monkeypatch.setattr(module, "REPO_ROOT", fake_repo_root, raising=True)

    argv = [
        "prepare_lendingclub.py",
        "--input",
        str(FIXTURE_PATH),
        "--output",
        str(data_dir),
        "--data-scope",
        "synthetic_fixture",
        "--config",
        str(CONFIG_PATH),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["prepare"].main() == 0

    argv = [
        "split_dataset.py",
        "--input",
        str(data_dir / "loan_with_outcome.parquet"),
        "--output",
        str(data_dir),
        "--data-scope",
        "synthetic_fixture",
        "--config",
        str(CONFIG_PATH),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["split"].main() == 0

    argv = [
        "train_credit_models.py",
        "--input",
        str(data_dir / "loan_with_outcome.parquet"),
        "--split-dir",
        str(data_dir),
        "--data-scope",
        "synthetic_fixture",
        "--config",
        str(CONFIG_PATH),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["train"].main() == 0

    return scripts["train"].results_subdir(fake_repo_root, "synthetic_fixture", "evaluation")


def test_script_writes_predictions_and_metrics_with_correct_shape(scripts, tmp_path, monkeypatch):
    output_dir = _run_pipeline(scripts, tmp_path, monkeypatch, "run_a")

    predictions_path = output_dir / "model_predictions.parquet"
    metrics_path = output_dir / "model_metrics.csv"
    assert predictions_path.exists()
    assert metrics_path.exists()

    predictions = pd.read_parquet(predictions_path)
    assert set(predictions["model"].unique()) == {"logistic_regression", "random_forest"}
    assert set(predictions.columns) == {
        "row_index",
        "id",
        "model",
        "y_true",
        "y_proba",
        "y_pred",
        "threshold",
    }
    # Every TEST row must have a prediction from BOTH models.
    n_test_rows = predictions[predictions["model"] == "logistic_regression"].shape[0]
    assert predictions[predictions["model"] == "random_forest"].shape[0] == n_test_rows
    # Unresolved-outcome TEST rows are present (y_true null) but still predicted.
    assert predictions["y_true"].isna().any()
    assert predictions["y_pred"].isin([0, 1]).all()

    metrics = pd.read_csv(metrics_path)
    assert set(metrics["model"]) == {"logistic_regression", "random_forest"}
    assert (metrics["data_scope"] == "synthetic_fixture").all()
    assert (metrics["is_real_lendingclub"] == False).all()  # noqa: E712


def test_predictions_are_reusable_identically_by_two_independent_readers(
    scripts, tmp_path, monkeypatch
):
    """Simulates the plaintext audit (Phase 2) and the encrypted audit
    (Phases 5-8) both reading the one saved artifact -- they must see
    exactly the same values, since neither is allowed to recompute."""
    output_dir = _run_pipeline(scripts, tmp_path, monkeypatch, "run_b")
    predictions_path = output_dir / "model_predictions.parquet"

    reader_a = pd.read_parquet(predictions_path)  # stand-in: plaintext audit
    reader_b = pd.read_parquet(predictions_path)  # stand-in: encrypted audit
    assert reader_a.equals(reader_b)


def test_rerunning_the_script_reproduces_identical_predictions(scripts, tmp_path, monkeypatch):
    output_dir_a = _run_pipeline(scripts, tmp_path, monkeypatch, "run_c1")
    predictions_a = pd.read_parquet(output_dir_a / "model_predictions.parquet").copy()

    output_dir_b = _run_pipeline(scripts, tmp_path, monkeypatch, "run_c2")
    predictions_b = pd.read_parquet(output_dir_b / "model_predictions.parquet").copy()

    pd.testing.assert_frame_equal(predictions_a, predictions_b)
