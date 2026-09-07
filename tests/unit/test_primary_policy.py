"""Unit tests for fairlend.audit.primary_policy (Stage 4's result-
consolidation layer): hand-built, artifact-shaped dicts only -- no CKKS,
no credentials, no file I/O. Mirrors tests/unit/test_reconstruction.py's
style."""
from __future__ import annotations

import pytest

from fairlend.audit.primary_policy import (
    AggregateReconstructionMismatchError,
    DataScopeMismatchError,
    ProvenanceMismatchError,
    STAT_KEYS,
    assert_distinct_realisations,
    build_primary_policy_row,
    verify_aggregate_reconstruction,
    verify_matching_dataset_hash,
    verify_provenance,
)

DATASET_SHA256 = "3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a"
POLICY = "validation_balanced_accuracy_max"


def _common_provenance(**overrides) -> dict:
    base = {
        "dataset_sha256": DATASET_SHA256,
        "alpha1": 0.7,
        "synthetic_seed": 0,
        "threshold_policy": POLICY,
        "tau": 0.80,
        "data_scope": "real_lendingclub",
        "test_population_n": 177489,
        "resolved_test_n": 165872,
        "unresolved_test_n": 11617,
    }
    base.update(overrides)
    return base


def _expected_kwargs(**overrides) -> dict:
    kwargs = dict(
        expected_dataset_sha256=DATASET_SHA256,
        expected_alpha1=0.7,
        expected_seed=0,
        expected_threshold_policy=POLICY,
        expected_tau=0.80,
        expected_data_scope="real_lendingclub",
        expected_test_population_n=177489,
        expected_resolved_test_n=165872,
        expected_unresolved_test_n=11617,
    )
    kwargs.update(overrides)
    return kwargs


def _stat_block(plaintext: int, raw: float, rounded: int) -> dict:
    return {
        "plaintext_count": plaintext,
        "raw_decrypted_count": raw,
        "rounded_encrypted_count": rounded,
        "absolute_error": abs(raw - plaintext),
        "matches_plaintext": rounded == plaintext,
    }


def _exact_statistics() -> dict:
    """All 12 stats, each rounding exactly to its plaintext count with a
    small nonzero raw CKKS error -- the normal, expected case."""
    values = {"C_m": 100, "C_f": 100, "A_m": 60, "A_f": 60, "P_m": 70, "P_f": 70,
              "TP_m": 45, "TP_f": 45, "N_m": 20, "N_f": 20, "FP_m": 8, "FP_f": 8}
    return {k: _stat_block(v, v + 0.01, v) for k, v in values.items()}


def _audit_report(**overrides) -> dict:
    report = {
        **_common_provenance(),
        "run_id": "run-lr-1",
        "packet_sha256": "packet-lr-1",
        "reference_fingerprint": "ref-lr-1",
        "test_approval_count": 60,
        "test_approval_rate": 0.6,
        "runtime_seconds": 100.0,
        "records_per_second": 10.0,
        "statistics": _exact_statistics(),
    }
    report.update(overrides)
    return report


def _fairness_report(**overrides) -> dict:
    report = {
        **_common_provenance(),
        "run_id": "run-lr-1",
        "packet_sha256": "packet-lr-1",
        "reference_fingerprint": "ref-lr-1",
        "DP_plain": 0.001,
        "DP_encrypted": 0.001,
        "e_DP": 0.0,
        "EO_plain": 0.002,
        "EO_encrypted": 0.002,
        "e_EO": 0.0,
        "DP_raw_ckks": 0.0010001,
        "EO_raw_ckks": 0.0020001,
    }
    # Fairness reports carry no population-size fields in the real artifacts.
    for key in ("test_population_n", "resolved_test_n", "unresolved_test_n"):
        report.pop(key, None)
    report.update(overrides)
    return report


# --- verify_provenance ------------------------------------------------


def test_verify_provenance_accepts_matching_artifact():
    verify_provenance(_audit_report(), **_expected_kwargs(), label="LR audit report")


def test_verify_provenance_rejects_dataset_hash_mismatch():
    bad = _audit_report(dataset_sha256="0" * 64)
    with pytest.raises(ProvenanceMismatchError):
        verify_provenance(bad, **_expected_kwargs(), label="LR audit report")


def test_verify_provenance_rejects_f1_max_artifact_when_balanced_accuracy_expected():
    """Guards against silently substituting a validation_f1_max artifact
    (tau=0.05, degenerate) for the primary validation_balanced_accuracy_max
    result."""
    f1_max_artifact = _audit_report(threshold_policy="validation_f1_max", tau=0.05)
    with pytest.raises(ProvenanceMismatchError):
        verify_provenance(f1_max_artifact, **_expected_kwargs(), label="LR audit report")


def test_verify_provenance_rejects_fixture_scope_when_real_expected():
    fixture_artifact = _audit_report(data_scope="synthetic_fixture")
    with pytest.raises(DataScopeMismatchError):
        verify_provenance(fixture_artifact, **_expected_kwargs(), label="LR audit report")


def test_verify_provenance_rejects_population_size_mismatch():
    bad = _audit_report(test_population_n=38)
    with pytest.raises(ProvenanceMismatchError):
        verify_provenance(bad, **_expected_kwargs(), label="LR audit report")


def test_verify_provenance_skips_population_checks_when_not_requested():
    """Fairness-reconstruction reports carry no population-size fields;
    the caller omits those expected_* kwargs rather than the check
    failing on a field that could never be present."""
    fairness = _fairness_report()
    kwargs = {
        k: v
        for k, v in _expected_kwargs().items()
        if k not in ("expected_test_population_n", "expected_resolved_test_n", "expected_unresolved_test_n")
    }
    verify_provenance(fairness, **kwargs, label="LR fairness report")


# --- verify_aggregate_reconstruction / build_primary_policy_row -------


def test_verify_aggregate_reconstruction_passes_and_recomputes_errors():
    errors = verify_aggregate_reconstruction(_audit_report(), "LR")
    assert set(errors) == set(STAT_KEYS)
    assert errors["C_m"] == pytest.approx(0.01)


def test_verify_aggregate_reconstruction_flags_any_of_24_mismatches():
    statistics = _exact_statistics()
    statistics["FP_f"] = _stat_block(plaintext=8, raw=8.6, rounded=9)  # rounds to the WRONG count
    bad_report = _audit_report(statistics=statistics)
    with pytest.raises(AggregateReconstructionMismatchError):
        verify_aggregate_reconstruction(bad_report, "LR")


def test_build_primary_policy_row_requires_matching_run_identity():
    audit = _audit_report()
    mismatched_fairness = _fairness_report(run_id="a-different-run")
    with pytest.raises(ProvenanceMismatchError):
        build_primary_policy_row(audit, mismatched_fairness, "logistic_regression")


def test_build_primary_policy_row_success():
    row = build_primary_policy_row(_audit_report(), _fairness_report(), "logistic_regression")
    assert row.model == "logistic_regression"
    assert row.approval_count == 60
    assert row.dp_reconstruction_error == 0.0
    assert row.eo_reconstruction_error == 0.0
    assert row.aggregate_max_abs_error == pytest.approx(0.01)
    assert row.rounding_safety_margin == pytest.approx(0.5 - 0.01)


# --- assert_distinct_realisations --------------------------------------


def test_assert_distinct_realisations_passes_for_independent_runs():
    lr_row = build_primary_policy_row(_audit_report(), _fairness_report(), "logistic_regression")
    rf_row = build_primary_policy_row(
        _audit_report(run_id="run-rf-1", packet_sha256="packet-rf-1", reference_fingerprint="ref-rf-1"),
        _fairness_report(run_id="run-rf-1", packet_sha256="packet-rf-1", reference_fingerprint="ref-rf-1"),
        "random_forest",
    )
    assert_distinct_realisations({"logistic_regression": lr_row, "random_forest": rf_row})


def test_assert_distinct_realisations_rejects_shared_run_id():
    """Two models must never share the same CKKS realisation -- catches
    an accidental artifact-copy bug (e.g. RF results ending up identical
    to LR's)."""
    lr_row = build_primary_policy_row(_audit_report(), _fairness_report(), "logistic_regression")
    rf_row = build_primary_policy_row(_audit_report(), _fairness_report(), "random_forest")  # same run_id as LR
    with pytest.raises(ProvenanceMismatchError):
        assert_distinct_realisations({"logistic_regression": lr_row, "random_forest": rf_row})


# --- verify_matching_dataset_hash ---------------------------------------


def test_verify_matching_dataset_hash_accepts_matching_artifact():
    threshold_doc = {"dataset_sha256": DATASET_SHA256, "data_scope": "real_lendingclub"}
    run_row = {"dataset_sha256": DATASET_SHA256}
    verify_matching_dataset_hash(
        threshold_doc, run_row, expected_dataset_sha256=DATASET_SHA256, expected_data_scope="real_lendingclub"
    )


def test_verify_matching_dataset_hash_rejects_hash_mismatch():
    threshold_doc = {"dataset_sha256": "0" * 64, "data_scope": "real_lendingclub"}
    run_row = {"dataset_sha256": DATASET_SHA256}
    with pytest.raises(ProvenanceMismatchError):
        verify_matching_dataset_hash(
            threshold_doc, run_row, expected_dataset_sha256=DATASET_SHA256, expected_data_scope="real_lendingclub"
        )


def test_verify_matching_dataset_hash_rejects_fixture_scope_mismatch():
    threshold_doc = {"dataset_sha256": DATASET_SHA256, "data_scope": "synthetic_fixture"}
    run_row = {"dataset_sha256": DATASET_SHA256}
    with pytest.raises(DataScopeMismatchError):
        verify_matching_dataset_hash(
            threshold_doc, run_row, expected_dataset_sha256=DATASET_SHA256, expected_data_scope="real_lendingclub"
        )
