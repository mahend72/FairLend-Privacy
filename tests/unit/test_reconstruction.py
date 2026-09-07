"""Unit tests for fairlend.audit.reconstruction using hand-built,
aggregate-only inputs (no CKKS, no credentials -- pure counting/formula
tests, mirroring tests/unit/test_fairness.py's style)."""
from __future__ import annotations

import inspect

import pytest

from fairlend.audit.aggregation import DecryptedAuditPacket, DecryptedGroupAuditCounts
from fairlend.audit.fairness import NOT_CONFIGURED, RELEASED, SUPPRESSED
from fairlend.audit.reconstruction import (
    compute_aggregate_reconstruction,
    compute_fairness_reconstruction,
    encrypted_result_from_raw_packet,
    encrypted_result_from_rounded_packet,
    plaintext_result_from_oracle_row,
)


def _oracle_row(**overrides) -> dict:
    row = {
        "C_m": 19, "C_f": 19, "A_m": 14, "A_f": 16,
        "P_m": 7, "P_f": 9, "TP_m": 7, "TP_f": 8,
        "N_m": 4, "N_f": 5, "FP_m": 3, "FP_f": 5,
        "test_population_n": 38, "resolved_test_n": 25, "unresolved_test_n": 13,
    }
    row.update(overrides)
    return row


def _packet(model="logistic_regression", noise=1e-6, **overrides) -> DecryptedAuditPacket:
    values = {
        "C_m": 19, "C_f": 19, "A_m": 14, "A_f": 16,
        "P_m": 7, "P_f": 9, "TP_m": 7, "TP_f": 8,
        "N_m": 4, "N_f": 5, "FP_m": 3, "FP_f": 5,
    }
    values.update(overrides)
    male = DecryptedGroupAuditCounts(
        C=values["C_m"] + noise, A=values["A_m"] + noise, P=values["P_m"] + noise,
        TP=values["TP_m"] + noise, N=values["N_m"] + noise, FP=values["FP_m"] + noise,
    )
    female = DecryptedGroupAuditCounts(
        C=values["C_f"] + noise, A=values["A_f"] + noise, P=values["P_f"] + noise,
        TP=values["TP_f"] + noise, N=values["N_f"] + noise, FP=values["FP_f"] + noise,
    )
    return DecryptedAuditPacket(
        male=male, female=female, model=model, test_population_n=38, resolved_test_n=25, unresolved_test_n=13
    )


# --- plaintext/encrypted result builders ------------------------------------


def test_plaintext_result_from_oracle_row_matches_input_counts():
    result = plaintext_result_from_oracle_row(_oracle_row(), "logistic_regression")
    assert result.male().C == 19
    assert result.female().A == 16
    assert result.full_test_n == 38


def test_encrypted_result_from_rounded_packet_rounds_correctly():
    packet = _packet(noise=0.4)  # rounds down
    result = encrypted_result_from_rounded_packet(packet)
    assert result.male().C == 19
    assert result.female().A == 16


def test_encrypted_result_from_rounded_packet_rounds_up():
    # +0.6 to every field of both groups rounds every value up by 1;
    # population metadata adjusted to match the resulting rounded sums
    # (C: 20+20=40; P: 8+10=18; N: 5+6=11; resolved=18+11=29).
    male = DecryptedGroupAuditCounts(C=19.6, A=14.6, P=7.6, TP=7.6, N=4.6, FP=3.6)
    female = DecryptedGroupAuditCounts(C=19.6, A=16.6, P=9.6, TP=8.6, N=5.6, FP=5.6)
    packet = DecryptedAuditPacket(
        male=male, female=female, model="logistic_regression",
        test_population_n=40, resolved_test_n=29, unresolved_test_n=11,
    )
    result = encrypted_result_from_rounded_packet(packet)
    assert result.male().C == 20


def test_encrypted_result_from_raw_packet_preserves_float_precision():
    packet = _packet(noise=1e-6)
    result = encrypted_result_from_raw_packet(packet)
    assert result.male().C == pytest.approx(19.000001)


def test_encrypted_result_from_raw_packet_clips_a_greater_than_c_noise():
    """Directly exercises the documented clipping behaviour: raw A
    slightly exceeding raw C (real, observed CKKS noise) must not crash
    GroupAuditCounts's A<=C invariant."""
    packet = _packet(A_m=19.0000025, C_m=19.0000022)  # A_m raw > C_m raw
    result = encrypted_result_from_raw_packet(packet)
    assert result.male().A == result.male().C  # clipped to C


# --- aggregate reconstruction ------------------------------------------------


def test_aggregate_reconstruction_all_match_when_rounding_recovers_plaintext():
    row = _oracle_row()
    packet = _packet(noise=1e-5)
    result = compute_aggregate_reconstruction(row, packet, "logistic_regression")
    assert result.all_rounded_match_plaintext is True
    assert result.max_absolute_error < 1e-4
    assert result.rounded["C_m"] == 19
    assert result.plaintext["C_m"] == 19


def test_aggregate_reconstruction_flags_mismatch_when_rounding_diverges():
    row = _oracle_row()
    packet = _packet(C_m=19.6)  # rounds to 20, plaintext says 19
    result = compute_aggregate_reconstruction(row, packet, "logistic_regression")
    assert result.all_rounded_match_plaintext is False
    assert result.rounded["C_m"] == 20
    assert result.plaintext["C_m"] == 19


# --- fairness reconstruction: exact-match fixture (task Sec. 9) ------------


def test_fairness_reconstruction_gives_zero_error_when_rounded_counts_match_exactly():
    row = _oracle_row()
    packet = _packet(noise=1e-6)
    result = compute_fairness_reconstruction(row, packet, "logistic_regression", minimum_cell_size=None)
    assert result.dp_reconstruction_error == 0.0
    assert result.eo_reconstruction_error == 0.0
    assert result.dp_plain.value == result.dp_encrypted.value
    assert result.eo_plain.value == result.eo_encrypted.value


def test_fairness_reconstruction_dp_matches_hand_calculation():
    row = _oracle_row()
    packet = _packet(noise=0.0)
    result = compute_fairness_reconstruction(row, packet, "logistic_regression", minimum_cell_size=None)
    # approval_rate_m = 14/19, approval_rate_f = 16/19 -> DP = |16/19 - 14/19| = 2/19
    assert result.dp_plain.value == pytest.approx(2 / 19)


def test_raw_ckks_diagnostic_is_separately_labelled_and_nonzero_with_noise():
    row = _oracle_row()
    packet = _packet(noise=1e-3)
    result = compute_fairness_reconstruction(row, packet, "logistic_regression", minimum_cell_size=None)
    assert result.dp_raw_ckks is not None
    assert result.dp_raw_ckks_error is not None
    # The raw diagnostic error must be independent of (and generally
    # larger before rounding than) the production (rounded) error.
    assert result.dp_reconstruction_error == 0.0
    assert result.dp_raw_ckks.value != result.dp_plain.value  # noise visible pre-rounding


def test_raw_ckks_diagnostic_can_be_disabled():
    row = _oracle_row()
    packet = _packet(noise=1e-6)
    result = compute_fairness_reconstruction(
        row, packet, "logistic_regression", minimum_cell_size=None, include_raw_ckks_diagnostic=False
    )
    assert result.dp_raw_ckks is None
    assert result.eo_raw_ckks is None
    assert result.dp_raw_ckks_error is None


# --- k_min release status agreement -----------------------------------------


def test_release_status_not_configured_agrees_between_plain_and_encrypted():
    row = _oracle_row()
    packet = _packet(noise=1e-6)
    result = compute_fairness_reconstruction(row, packet, "logistic_regression", minimum_cell_size=None)
    assert result.dp_release_status_plain == NOT_CONFIGURED
    assert result.dp_release_status_encrypted == NOT_CONFIGURED
    assert result.eo_release_status_plain == NOT_CONFIGURED
    assert result.eo_release_status_encrypted == NOT_CONFIGURED


def test_release_status_configured_suppression_agrees_between_plain_and_encrypted():
    row = _oracle_row()
    packet = _packet(noise=1e-6)
    result = compute_fairness_reconstruction(row, packet, "logistic_regression", minimum_cell_size=10)
    # C_m=C_f=19 >= 10 -> released for both.
    assert result.dp_release_status_plain == RELEASED
    assert result.dp_release_status_encrypted == RELEASED


def test_release_status_configured_suppression_triggers_identically():
    # A smaller, self-consistent male group (C_m=5) below k_min=10, with
    # A/P/TP/N/FP shrunk to stay within C_m and population totals adjusted
    # to match (test_population_n=5+19=24; resolved=2+2+9+5=18).
    small_group = dict(C_m=5, A_m=2, P_m=2, TP_m=1, N_m=2, FP_m=1)
    row = _oracle_row(test_population_n=24, resolved_test_n=18, unresolved_test_n=6, **small_group)
    packet_base = _packet(noise=1e-6, **small_group)
    packet = DecryptedAuditPacket(
        male=packet_base.male, female=packet_base.female, model=packet_base.model,
        test_population_n=24, resolved_test_n=18, unresolved_test_n=6,
    )
    result = compute_fairness_reconstruction(row, packet, "logistic_regression", minimum_cell_size=10)
    assert result.dp_release_status_plain == SUPPRESSED
    assert result.dp_release_status_encrypted == SUPPRESSED


# --- zero-denominator consistency -------------------------------------------


def test_zero_denominator_unavailable_agrees_between_plain_and_encrypted():
    # A group with genuinely zero members: C_m/A_m/P_m/N_m/TP_m/FP_m all 0,
    # with population totals adjusted so C_m+C_f/P_m+P_f+N_m+N_f still sum
    # correctly (assert_consistent() requires this).
    zero_group = dict(C_m=0, A_m=0, P_m=0, N_m=0, TP_m=0, FP_m=0)
    row = _oracle_row(test_population_n=19, resolved_test_n=14, unresolved_test_n=5, **zero_group)
    packet = _packet(noise=1e-6, **zero_group)
    packet = DecryptedAuditPacket(
        male=packet.male, female=packet.female, model=packet.model,
        test_population_n=19, resolved_test_n=14, unresolved_test_n=5,
    )
    result = compute_fairness_reconstruction(row, packet, "logistic_regression", minimum_cell_size=None)
    assert result.approval_rate_m_plain.available is False
    assert result.approval_rate_m_encrypted.available is False
    assert result.dp_plain.available is False
    assert result.dp_encrypted.available is False
    assert result.dp_reconstruction_error is None  # never a fabricated 0.0 gap


# --- aggregate-only structural check (task Sec. 14) -------------------------


def test_reconstruction_functions_take_no_borrower_level_parameter():
    forbidden_names = {"uid", "row_index", "synthetic_gender_label", "account", "score", "y_pred", "y_true", "records", "df", "dataframe"}
    for fn in (
        plaintext_result_from_oracle_row,
        encrypted_result_from_rounded_packet,
        encrypted_result_from_raw_packet,
        compute_aggregate_reconstruction,
        compute_fairness_reconstruction,
    ):
        params = set(inspect.signature(fn).parameters)
        assert params.isdisjoint(forbidden_names), (fn.__name__, params)
