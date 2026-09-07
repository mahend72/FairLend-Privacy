"""End-to-end test of evaluation/run_plaintext_audit.py: builds a
self-contained fixture pipeline (ingestion -> split -> synthetic gender ->
model training, via the actual CLI scripts, isolated under tmp_path) and
then proves the AUDIT script itself never fits/retrains anything -- it
only reads the frozen model_predictions.parquet Phase 1 already wrote.

Building the pipeline here (including running train_credit_models.py once
to produce a self-contained prediction artifact under tmp_path) is test
setup, not the Phase 2 deliverable run -- the actual reported Phase 2
numbers come from running run_plaintext_audit.py against the real,
already-frozen results/fixture_validation/evaluation/model_predictions.parquet
(see the session's Phase 2 report), which this test does not touch or
overwrite.
"""
from __future__ import annotations

import importlib.util
import inspect
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
        "prepare": _load_script("_prepare_lendingclub2", "evaluation/prepare_lendingclub.py"),
        "split": _load_script("_split_dataset2", "evaluation/split_dataset.py"),
        "gender": _load_script("_generate_synthetic_gender2", "evaluation/generate_synthetic_gender.py"),
        "train": _load_script("_train_credit_models2", "evaluation/train_credit_models.py"),
        "audit": _load_script("_run_plaintext_audit2", "evaluation/run_plaintext_audit.py"),
    }


@pytest.fixture()
def audit_inputs(scripts, tmp_path, monkeypatch):
    """Builds one full, self-contained fixture pipeline under tmp_path and
    returns the paths run_plaintext_audit.py needs."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    fake_repo_root = tmp_path / "repo_root"
    fake_repo_root.mkdir()
    for module in scripts.values():
        monkeypatch.setattr(module, "REPO_ROOT", fake_repo_root, raising=True)

    def _run(module_key, argv):
        monkeypatch.setattr(sys, "argv", argv)
        assert scripts[module_key].main() == 0

    _run(
        "prepare",
        [
            "prepare_lendingclub.py", "--input", str(FIXTURE_PATH), "--output", str(data_dir),
            "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH),
        ],
    )
    loan_path = data_dir / "loan_with_outcome.parquet"
    _run(
        "split",
        [
            "split_dataset.py", "--input", str(loan_path), "--output", str(data_dir),
            "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH),
        ],
    )
    gender_path = data_dir / "synthetic_gender_alpha1_0.7_seed_0.parquet"
    _run(
        "gender",
        [
            "generate_synthetic_gender.py", "--input", str(loan_path), "--split-dir", str(data_dir),
            "--alpha1", "0.7", "--seed", "0", "--output", str(gender_path),
            "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH),
        ],
    )
    _run(
        "train",
        [
            "train_credit_models.py", "--input", str(loan_path), "--split-dir", str(data_dir),
            "--data-scope", "synthetic_fixture", "--config", str(CONFIG_PATH),
        ],
    )
    predictions_path = (
        scripts["train"].results_subdir(fake_repo_root, "synthetic_fixture", "evaluation")
        / "model_predictions.parquet"
    )
    output_path = tmp_path / "plaintext_audit.csv"
    return {
        "predictions": predictions_path,
        "prepared_data": loan_path,
        "synthetic_gender": gender_path,
        "split_dir": data_dir,
        "output": output_path,
    }


def test_script_source_never_calls_fit_or_imports_model_fitting_functions():
    """Static proof: the audit script's own source does not contain a
    fit-call pattern and does not import anything that fits a model."""
    script_path = REPO_ROOT / "evaluation" / "run_plaintext_audit.py"
    source = script_path.read_text(encoding="utf-8")
    assert ".fit(" not in source
    for forbidden in (
        "select_best_logistic_regression",
        "select_best_random_forest",
        "LogisticRegression",
        "RandomForestClassifier",
    ):
        assert forbidden not in source


def test_audit_script_runs_without_calling_sklearn_fit(scripts, audit_inputs, monkeypatch):
    """Runtime proof: even with sklearn's fit() patched to raise for both
    model classes, the audit script completes successfully -- if it ever
    retrained anything, this would fail loudly instead of silently
    passing."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    def _raise(*args, **kwargs):
        raise AssertionError("run_plaintext_audit.py must never call model.fit().")

    monkeypatch.setattr(LogisticRegression, "fit", _raise)
    monkeypatch.setattr(RandomForestClassifier, "fit", _raise)

    argv = [
        "run_plaintext_audit.py",
        "--predictions", str(audit_inputs["predictions"]),
        "--prepared-data", str(audit_inputs["prepared_data"]),
        "--synthetic-gender", str(audit_inputs["synthetic_gender"]),
        "--split-dir", str(audit_inputs["split_dir"]),
        "--alpha1", "0.7", "--seed", "0",
        "--data-scope", "synthetic_fixture",
        "--config", str(CONFIG_PATH),
        "--output", str(audit_inputs["output"]),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["audit"].main() == 0
    assert audit_inputs["output"].exists()


def test_audit_output_reuses_frozen_predictions_exactly(scripts, audit_inputs, monkeypatch):
    """The audit's C/A counts must be derivable purely from the frozen
    predictions file -- rerunning the audit against the SAME frozen file
    twice must give identical results (no hidden randomness/refitting)."""
    argv = [
        "run_plaintext_audit.py",
        "--predictions", str(audit_inputs["predictions"]),
        "--prepared-data", str(audit_inputs["prepared_data"]),
        "--synthetic-gender", str(audit_inputs["synthetic_gender"]),
        "--split-dir", str(audit_inputs["split_dir"]),
        "--alpha1", "0.7", "--seed", "0",
        "--data-scope", "synthetic_fixture",
        "--config", str(CONFIG_PATH),
        "--output", str(audit_inputs["output"]),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["audit"].main() == 0
    first = pd.read_csv(audit_inputs["output"])

    output_2 = audit_inputs["output"].parent / "plaintext_audit_2.csv"
    argv[-1] = str(output_2)
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["audit"].main() == 0
    second = pd.read_csv(output_2)

    pd.testing.assert_frame_equal(first, second)


def test_output_csv_has_the_requested_columns(scripts, audit_inputs, monkeypatch):
    argv = [
        "run_plaintext_audit.py",
        "--predictions", str(audit_inputs["predictions"]),
        "--prepared-data", str(audit_inputs["prepared_data"]),
        "--synthetic-gender", str(audit_inputs["synthetic_gender"]),
        "--split-dir", str(audit_inputs["split_dir"]),
        "--alpha1", "0.7", "--seed", "0",
        "--data-scope", "synthetic_fixture",
        "--config", str(CONFIG_PATH),
        "--output", str(audit_inputs["output"]),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert scripts["audit"].main() == 0
    df = pd.read_csv(audit_inputs["output"])
    expected_columns = {
        "model", "data_scope", "is_real_lendingclub", "alpha1", "seed",
        "test_population_n", "resolved_test_n", "unresolved_test_n",
        "C_m", "C_f", "A_m", "A_f", "P_m", "P_f", "TP_m", "TP_f", "N_m", "N_f", "FP_m", "FP_f",
        "approval_rate_m", "approval_rate_f", "TPR_m", "TPR_f", "FPR_m", "FPR_f",
        "DP_plain", "EO_plain", "minimum_cell_size", "DP_release_status", "EO_release_status",
    }
    assert expected_columns.issubset(set(df.columns))
    assert set(df["model"]) == {"logistic_regression", "random_forest"}
    assert (df["data_scope"] == "synthetic_fixture").all()
    assert (df["is_real_lendingclub"] == False).all()  # noqa: E712
    assert (df["minimum_cell_size"].isna()).all()  # k_min unconfigured by default config
    assert (df["DP_release_status"] == "minimum_cell_size_not_configured").all()
    assert (df["EO_release_status"] == "minimum_cell_size_not_configured").all()


def test_output_rejected_if_predictions_do_not_match_prepared_data(scripts, audit_inputs, monkeypatch, tmp_path):
    """Corrupting y_true in a copy of the frozen predictions must be
    caught by the cross-check against --prepared-data, not silently
    audited."""
    predictions = pd.read_parquet(audit_inputs["predictions"])
    predictions.loc[predictions.index[0], "y_true"] = (
        0.0 if predictions.loc[predictions.index[0], "y_true"] != 0.0 else 1.0
    )
    tampered_path = tmp_path / "tampered_predictions.parquet"
    predictions.to_parquet(tampered_path, index=False)

    argv = [
        "run_plaintext_audit.py",
        "--predictions", str(tampered_path),
        "--prepared-data", str(audit_inputs["prepared_data"]),
        "--synthetic-gender", str(audit_inputs["synthetic_gender"]),
        "--split-dir", str(audit_inputs["split_dir"]),
        "--alpha1", "0.7", "--seed", "0",
        "--data-scope", "synthetic_fixture",
        "--config", str(CONFIG_PATH),
        "--output", str(audit_inputs["output"]),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(ValueError, match="does not match"):
        scripts["audit"].main()
