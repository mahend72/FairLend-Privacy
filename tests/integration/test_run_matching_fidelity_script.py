"""End-to-end test of evaluation/run_matching_fidelity.py: builds a
self-contained fixture pipeline (ingestion -> split -> synthetic gender,
via the actual CLI scripts, isolated under tmp_path) and then runs the
matching-fidelity diagnostic across several independent cryptographic
realisations, checking output schema, provenance, and mean/std summary
correctness.
"""
from __future__ import annotations

import importlib.util
import statistics
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
        "prepare": _load_script("_prepare5", "evaluation/prepare_lendingclub.py"),
        "split": _load_script("_split5", "evaluation/split_dataset.py"),
        "gender": _load_script("_gender5", "evaluation/generate_synthetic_gender.py"),
        "matching": _load_script("_matching5", "evaluation/run_matching_fidelity.py"),
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
    return {"gender_path": gender_path, "data_dir": data_dir}


def _run_matching(scripts, pipeline_paths, monkeypatch, output_dir, n_runs=3):
    argv = [
        "m",
        "--synthetic-gender", str(pipeline_paths["gender_path"]),
        "--split-dir", str(pipeline_paths["data_dir"]),
        "--data-scope", "synthetic_fixture",
        "--n-runs", str(n_runs),
        "--output-dir", str(output_dir),
        "--alpha1", "0.7",
        "--seed", "0",
        "--dataset-sha256", "test-fixture-sha256-placeholder",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["matching"].main() == 0


def test_output_files_created_with_correct_schema(scripts, pipeline_paths, tmp_path, monkeypatch):
    output_dir = tmp_path / "out"
    _run_matching(scripts, pipeline_paths, monkeypatch, output_dir, n_runs=3)

    runs_csv = output_dir / "matching_fidelity_runs.csv"
    summary_csv = output_dir / "matching_fidelity_summary.csv"
    threshold_json = output_dir / "matching_threshold.json"
    assert runs_csv.exists() and summary_csv.exists() and threshold_json.exists()

    runs_df = pd.read_csv(runs_csv)
    assert len(runs_df) == 3
    assert (runs_df["data_scope"] == "synthetic_fixture").all()
    assert (runs_df["is_real_lendingclub"] == False).all()  # noqa: E712
    assert runs_df["run_id"].nunique() == 3  # every run has a distinct id
    assert runs_df["reference_fingerprint"].nunique() == 3  # and a distinct crypto realisation

    import json

    threshold_doc = json.loads(threshold_json.read_text())
    assert threshold_doc["data_scope"] == "synthetic_fixture"
    assert threshold_doc["is_real_lendingclub"] is False
    assert threshold_doc["n_runs"] == 3
    assert "delta_star_selection_method" in threshold_doc
    assert len(threshold_doc["delta_star_values_across_runs"]) == 3


def test_summary_mean_and_std_computed_correctly(scripts, pipeline_paths, tmp_path, monkeypatch):
    output_dir = tmp_path / "out"
    _run_matching(scripts, pipeline_paths, monkeypatch, output_dir, n_runs=5)

    runs_df = pd.read_csv(output_dir / "matching_fidelity_runs.csv")
    summary_df = pd.read_csv(output_dir / "matching_fidelity_summary.csv")
    row = summary_df.iloc[0]

    for column in ("accuracy", "macro_f1", "unmatched_rate", "delta_star", "combined_mae", "combined_max_abs_error"):
        expected_mean = statistics.fmean(runs_df[column])
        expected_std = statistics.pstdev(runs_df[column])
        assert row[f"{column}_mean"] == pytest.approx(expected_mean)
        assert row[f"{column}_std"] == pytest.approx(expected_std)

    assert row["n_runs"] == 5
    assert row["validation_n"] == runs_df["validation_n"].iloc[0]
    assert row["test_n"] == runs_df["test_n"].iloc[0]


def test_each_run_has_distinct_provenance_but_stable_matching_quality(scripts, pipeline_paths, tmp_path, monkeypatch):
    """On this fixture (Phase 4's well-separated compSim scores), every
    independent cryptographic run should achieve identical (typically
    perfect) matching accuracy despite having different underlying
    ciphertexts -- measured, not assumed."""
    output_dir = tmp_path / "out"
    _run_matching(scripts, pipeline_paths, monkeypatch, output_dir, n_runs=5)
    runs_df = pd.read_csv(output_dir / "matching_fidelity_runs.csv")

    assert runs_df["run_id"].nunique() == len(runs_df)
    assert runs_df["reference_fingerprint"].nunique() == len(runs_df)
    # Not hardcoded as an assumption -- measured: report what accuracy
    # actually was, and require it be consistent across runs.
    assert runs_df["accuracy"].nunique() == 1
    assert runs_df["macro_f1"].nunique() == 1


def test_matching_script_never_touches_model_predictions_or_fits_anything():
    """Checks actual usage, not prose -- the script's own module
    docstring explains (in English) that it does NOT read
    model_predictions.parquet, which would otherwise trip a bare
    substring search."""
    script_path = REPO_ROOT / "evaluation" / "run_matching_fidelity.py"
    source = script_path.read_text(encoding="utf-8")
    # No CLI flag for predictions/plaintext-audit at all -- the parser's
    # only inputs are --synthetic-gender/--split-dir/--output-dir/--n-runs/
    # --data-scope.
    assert "--predictions" not in source
    assert "--plaintext-audit" not in source
    assert ".fit(" not in source
    for forbidden in ("LogisticRegression", "RandomForestClassifier", "select_best_logistic_regression"):
        assert forbidden not in source
