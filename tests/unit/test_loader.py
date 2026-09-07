"""Unit tests for raw dataset loading, hashing, and manifest construction."""
from __future__ import annotations

from pathlib import Path

import pytest

from fairlend.data.loader import build_raw_manifest, compute_sha256, load_raw_lendingclub

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "lendingclub_sample.csv"


def test_load_raw_lendingclub_missing_file_raises_clear_error(tmp_path):
    missing = tmp_path / "does_not_exist.csv"
    with pytest.raises(FileNotFoundError):
        load_raw_lendingclub(missing)


def test_load_raw_lendingclub_reads_fixture():
    df = load_raw_lendingclub(FIXTURE_PATH)
    assert len(df) == 200
    for col in ("loan_status", "annual_inc", "emp_length", "dti", "home_ownership", "addr_state"):
        assert col in df.columns


def test_sha256_is_deterministic_for_same_file():
    a = compute_sha256(FIXTURE_PATH)
    b = compute_sha256(FIXTURE_PATH)
    assert a == b
    assert len(a) == 64  # hex-encoded SHA-256


def test_sha256_differs_for_different_content(tmp_path):
    f1 = tmp_path / "a.csv"
    f2 = tmp_path / "b.csv"
    f1.write_text("a,b\n1,2\n")
    f2.write_text("a,b\n1,3\n")
    assert compute_sha256(f1) != compute_sha256(f2)


def test_build_raw_manifest_reports_actual_counts_not_manuscript_figures():
    df = load_raw_lendingclub(FIXTURE_PATH)
    manifest = build_raw_manifest(FIXTURE_PATH, df)
    assert manifest.raw_row_count == 200  # actual fixture size, not ~890,000
    assert manifest.raw_column_count == df.shape[1]
    assert manifest.sha256 == compute_sha256(FIXTURE_PATH)
    assert "loan_status" in manifest.columns
