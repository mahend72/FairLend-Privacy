"""Unit tests for fairlend.benchmarks (Phase 11): schema, positive
timings, serialization/analytical formula correctness, no-secret-material
discipline, and communication-projection arithmetic. No CKKS setup cost
is required for most of these -- only a couple of tests build a real
(tiny) CKKS context to prove the "length only, never persisted" pattern
against a genuine secret-bearing serialization."""
from __future__ import annotations

import importlib.util
import inspect
import sys
import time
from pathlib import Path

import pytest

from fairlend.benchmarks.communication import (
    ONE_TIME,
    PER_APPLICATION,
    PER_AUDIT_BATCH,
    CommunicationPathEntry,
    project_total_communication_bytes,
    total_bytes_by_category,
)
from fairlend.benchmarks.environment import collect_environment_metadata
from fairlend.benchmarks.serialization_estimate import analytical_ciphertext_bytes, percentage_difference
from fairlend.benchmarks.timing import TimingResult, time_repeated

REPO_ROOT = Path(__file__).resolve().parents[2]


# --- TimingResult / time_repeated schema (Phase 11 Sec. 4/18) -----------


def test_time_repeated_returns_expected_schema_and_positive_values():
    result = time_repeated(lambda: time.sleep(0.001), component="test", operation="sleep_1ms",
                            batch_size=1, n_repeats=10, n_warmup=2)
    assert isinstance(result, TimingResult)
    assert result.n == 10
    assert len(result.raw_ns) == 10  # every raw observation retained
    assert all(ns > 0 for ns in result.raw_ns)
    assert result.mean_ns > 0
    assert result.min_ns <= result.median_ns <= result.max_ns
    assert result.std_ns >= 0
    assert result.p95_ns >= result.median_ns


def test_time_repeated_records_per_second_scales_with_batch_size():
    result = time_repeated(lambda: time.sleep(0.001), component="test", operation="batch_sleep",
                            batch_size=10, n_repeats=5, n_warmup=1)
    assert result.mean_ms_per_record == pytest.approx(result.mean_ns / 1e6 / 10)
    assert result.records_per_second > 0


def test_time_repeated_never_uses_wall_clock_for_duration():
    """Structural guard against reintroducing datetime-based timing --
    checks actual usage (import/call sites), not incidental docstring
    prose that merely explains the rule."""
    import fairlend.benchmarks.timing as module

    source = inspect.getsource(module.time_repeated)
    body_only = source.split('"""', 2)[-1] if source.count('"""') >= 2 else source
    assert "datetime" not in body_only
    assert "perf_counter_ns" in body_only


# --- analytical CKKS estimate (Phase 11 Sec. 11) -------------------------


def test_analytical_ciphertext_bytes_known_case():
    estimate = analytical_ciphertext_bytes(poly_modulus_degree=8192, active_moduli_bit_sizes=[60, 40, 40, 60], num_polys=2)
    # bytes_per_coefficient = ceil(60/8)+ceil(40/8)+ceil(40/8)+ceil(60/8) = 8+5+5+8 = 26
    assert estimate.bytes_per_coefficient == 26
    assert estimate.analytical_estimate_bytes == 2 * 8192 * 26


def test_analytical_ciphertext_bytes_rejects_empty_chain():
    with pytest.raises(ValueError):
        analytical_ciphertext_bytes(poly_modulus_degree=8192, active_moduli_bit_sizes=[], num_polys=2)


def test_percentage_difference_correct_sign_and_magnitude():
    assert percentage_difference(measured_bytes=110, analytical_estimate_bytes=100) == pytest.approx(10.0)
    assert percentage_difference(measured_bytes=90, analytical_estimate_bytes=100) == pytest.approx(-10.0)


def test_percentage_difference_nan_for_zero_analytical_estimate():
    import math

    assert math.isnan(percentage_difference(measured_bytes=100, analytical_estimate_bytes=0))


def test_analytical_estimate_never_forced_to_match_measured():
    """Structural guard: analytical_ciphertext_bytes's OWN function body
    (not the module's explanatory docstrings) must never reference a
    measured value -- it takes only CKKS parameters."""
    from fairlend.benchmarks.serialization_estimate import analytical_ciphertext_bytes

    params = list(inspect.signature(analytical_ciphertext_bytes).parameters)
    assert params == ["poly_modulus_degree", "active_moduli_bit_sizes", "num_polys"]
    body_source = inspect.getsource(analytical_ciphertext_bytes)
    # Strip the function's own docstring before checking its executable body.
    body_only = body_source.split('"""', 2)[-1] if body_source.count('"""') >= 2 else body_source
    assert "measured" not in body_only.lower()


# --- communication classification / projection arithmetic (Sec. 12-14) --


def test_communication_path_entry_rejects_unknown_category():
    with pytest.raises(ValueError):
        CommunicationPathEntry("A -> B", "thing", 100, "sometimes")


def test_communication_path_entry_rejects_negative_bytes():
    with pytest.raises(ValueError):
        CommunicationPathEntry("A -> B", "thing", -1, ONE_TIME)


def test_total_bytes_by_category_separates_one_time_from_per_application():
    entries = [
        CommunicationPathEntry("setup", "keys", 1000, ONE_TIME),
        CommunicationPathEntry("app", "credential", 50, PER_APPLICATION),
        CommunicationPathEntry("app", "credential2", 30, PER_APPLICATION),
        CommunicationPathEntry("audit", "packet", 500, PER_AUDIT_BATCH),
    ]
    totals = total_bytes_by_category(entries)
    assert totals[ONE_TIME] == 1000
    assert totals[PER_APPLICATION] == 80
    assert totals[PER_AUDIT_BATCH] == 500


def test_project_total_communication_bytes_formula():
    total = project_total_communication_bytes(
        fixed_setup_bytes=1000, per_application_bytes=50, audit_packet_bytes=500, n_applications=10
    )
    assert total == 1000 + 10 * 50 + 500


def test_project_total_communication_bytes_does_not_multiply_setup_by_n():
    """Phase 11 Sec. 12: 'Do not add one-time key distribution into every
    application cost.' -- the fixed setup term must appear exactly once
    regardless of n."""
    small = project_total_communication_bytes(fixed_setup_bytes=1000, per_application_bytes=50, audit_packet_bytes=500, n_applications=1)
    large = project_total_communication_bytes(fixed_setup_bytes=1000, per_application_bytes=50, audit_packet_bytes=500, n_applications=1000)
    # The setup contribution to the difference must be exactly 0 (it cancels).
    assert (large - small) == (1000 - 1) * 50


def test_project_total_communication_bytes_rejects_negative_n():
    with pytest.raises(ValueError):
        project_total_communication_bytes(fixed_setup_bytes=0, per_application_bytes=0, audit_packet_bytes=0, n_applications=-1)


# --- no secret material persisted (Phase 11 Sec. 10) --------------------


def _load_benchmark_script():
    spec = importlib.util.spec_from_file_location("_run_benchmarks_test", REPO_ROOT / "evaluation" / "run_benchmarks.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["_run_benchmarks_test"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_measure_len_only_returns_int_not_bytes():
    """The private-context measurement helper must return an int (a
    length), never the actual secret-bearing byte string, so a caller
    cannot accidentally persist it."""
    script = _load_benchmark_script()
    result = script._measure_len_only(lambda: b"some secret bytes payload")
    assert isinstance(result, int)
    assert result == len(b"some secret bytes payload")


def test_measure_len_only_does_not_retain_a_reference_to_the_bytes():
    """After the call returns, nothing the function returns can be used
    to recover the original bytes -- only their length is observable."""
    script = _load_benchmark_script()
    produced = {"called": False}

    def _produce_secret():
        produced["called"] = True
        return b"\x00" * 12345  # stand-in for a private CKKS context blob

    length = script._measure_len_only(_produce_secret)
    assert produced["called"] is True
    assert length == 12345
    assert not isinstance(length, (bytes, bytearray))


def test_run_benchmarks_script_never_writes_a_raw_secret_context_field():
    """Structural guard: the orchestration script's serialization
    measurement function must route the private-context call through
    _measure_len_only (int-only), never assign its raw bytes to a row
    dict that gets written to CSV."""
    script = _load_benchmark_script()
    source = inspect.getsource(script.measure_serialization)
    assert "_measure_len_only" in source
    # The private-context row must be built from `private_len` (an int
    # already extracted via _measure_len_only), not from a raw bytes call.
    assert "private_len" in source


# --- environment metadata schema (Phase 11 Sec. 7) -----------------------


def test_collect_environment_metadata_has_required_fields():
    metadata = collect_environment_metadata(ckks_config_dict={"poly_modulus_degree": 8192})
    required = {
        "os", "kernel", "python_version", "tenseal_version", "cryptography_version",
        "cpu_model", "logical_cores", "physical_cores", "total_ram_gb", "is_wsl",
        "git_commit", "git_dirty", "competing_load_note", "ckks_config",
    }
    assert required.issubset(metadata.keys())
    assert metadata["ckks_config"] == {"poly_modulus_degree": 8192}


def test_collect_environment_metadata_contains_no_secret_looking_fields():
    metadata = collect_environment_metadata(ckks_config_dict={})
    keys_joined = " ".join(metadata.keys()).lower()
    for forbidden in ("secret", "private_key_bytes", "sk_he"):
        assert forbidden not in keys_joined
