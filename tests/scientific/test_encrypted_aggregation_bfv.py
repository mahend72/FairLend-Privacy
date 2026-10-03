"""PHASE 2 (ACTIVE, BFV direct-additive aggregation) scientific invariant
tests (reviewer2_phase2_bfv_migration_report.md).

Proves the CKKS -> BFV migration preserves every invariant the Phase 1
CKKS-direct baseline (tests/scientific/test_encrypted_aggregation_direct.py)
established, while additionally proving EXACT (not approximate) integer
output -- no epsilon tolerance is used anywhere in this file for a count
assertion, since BFV decryption is exact by construction.

Uses a dedicated small hermetic BFV fixture (not the shared CKKS
``pipeline`` fixture from conftest.py, since that fixture's contexts/
credentials are CKKS-specific).
"""
from __future__ import annotations

import dataclasses
import inspect

import pytest
import tenseal as ts

from fairlend.audit import aggregation as aggregation_module
from fairlend.audit.aggregation import (
    EncryptedAuditCounts,
    EncryptedAuditPacket,
    EncryptedTestRecord,
    GROUP_FEMALE,
    GROUP_MALE,
    assert_population_within_bfv_safe_bound,
    build_encrypted_aggregate_packet,
    compute_encrypted_audit,
    compute_plaintext_audit,
    build_audit_frame,
    decrypt_audit_packet_for_diagnostics,
)
from fairlend.core.config import BFVConfig
from fairlend.core.exceptions import BFVOverflowError, CredentialVerificationError, KeyBoundaryError
from fairlend.crypto.bfv import build_fla_context, context_can_decrypt, derive_lpu_context
from fairlend.crypto.signatures import SigningKeyPair
from fairlend.models.credit_models import LOGISTIC_REGRESSION, RANDOM_FOREST


def _run_direct(records, ip, lpu_context, fla_context, model_name=LOGISTIC_REGRESSION):
    result = compute_encrypted_audit(records, ip.public_key, lpu_context, model_name=model_name)
    packet = build_encrypted_aggregate_packet(result)
    return decrypt_audit_packet_for_diagnostics(packet, fla_context)


def _make_record(ip, idx, group, y_pred, y_true):
    credential = ip.issue_credential(f"synthetic-{idx}", group)
    return EncryptedTestRecord(row_index=idx, credential=credential, y_pred=y_pred, y_true=y_true)


@pytest.fixture()
def bfv_crypto_setup():
    from fairlend.roles.identity_provider import IdentityProviderBFV

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProviderBFV(lpu_context)
    return {"fla_context": fla_context, "lpu_context": lpu_context, "ip": ip}


# --- 1: all-male batch -------------------------------------------------------


def test_all_male_batch(bfv_crypto_setup):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(5)]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.male.C == 5.0 and decrypted.male.A == 5.0 and decrypted.male.P == 5.0
    assert decrypted.male.TP == 5.0 and decrypted.male.N == 0.0 and decrypted.male.FP == 0.0
    assert decrypted.female.C == 0.0 and decrypted.female.A == 0.0


# --- 2: all-female batch ------------------------------------------------------


def test_all_female_batch(bfv_crypto_setup):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [_make_record(ip, i, GROUP_FEMALE, y_pred=0, y_true=0) for i in range(4)]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.female.C == 4.0 and decrypted.female.A == 0.0 and decrypted.female.N == 4.0
    assert decrypted.male.C == 0.0


# --- 3: mixed batch -----------------------------------------------------------


def test_mixed_batch_exact_counts(bfv_crypto_setup):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [
        _make_record(ip, 0, GROUP_MALE, y_pred=1, y_true=1),
        _make_record(ip, 1, GROUP_FEMALE, y_pred=0, y_true=1),
        _make_record(ip, 2, GROUP_FEMALE, y_pred=1, y_true=0),
        _make_record(ip, 3, GROUP_MALE, y_pred=1, y_true=None),
    ]
    decrypted = _run_direct(records, ip, lpu, fla)
    # EXACT equality throughout -- no pytest.approx, no rounding: BFV
    # decryption returns the true integer directly.
    assert (decrypted.male.C, decrypted.male.A, decrypted.male.P, decrypted.male.TP) == (2.0, 2.0, 1.0, 1.0)
    assert (decrypted.female.C, decrypted.female.A, decrypted.female.P, decrypted.female.N, decrypted.female.FP) == (
        2.0, 1.0, 1.0, 1.0, 1.0,
    )
    assert decrypted.test_population_n == 4
    assert decrypted.resolved_test_n == 3
    assert decrypted.unresolved_test_n == 1


# --- 4: zero count in one group -----------------------------------------------


def test_one_group_entirely_absent_is_exactly_zero(bfv_crypto_setup):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=i % 2, y_true=1 if i % 2 == 0 else 0) for i in range(6)]
    decrypted = _run_direct(records, ip, lpu, fla)
    for stat in ("C", "A", "P", "TP", "N", "FP"):
        assert getattr(decrypted.female, stat) == 0.0  # EXACT zero, not approx
    assert decrypted.male.C == 6.0


# --- 5: approval-conditioned counts -------------------------------------------


def test_approval_conditioned_counts_exact(bfv_crypto_setup):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [
        _make_record(ip, 0, GROUP_MALE, y_pred=1, y_true=None),
        _make_record(ip, 1, GROUP_MALE, y_pred=0, y_true=None),
        _make_record(ip, 2, GROUP_FEMALE, y_pred=1, y_true=None),
        _make_record(ip, 3, GROUP_FEMALE, y_pred=1, y_true=None),
        _make_record(ip, 4, GROUP_FEMALE, y_pred=0, y_true=None),
    ]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert (decrypted.male.C, decrypted.male.A) == (2.0, 1.0)
    assert (decrypted.female.C, decrypted.female.A) == (3.0, 2.0)


# --- 6: P/N counts -------------------------------------------------------------


def test_p_and_n_counts_exact(bfv_crypto_setup):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [
        _make_record(ip, 0, GROUP_MALE, y_pred=1, y_true=1),
        _make_record(ip, 1, GROUP_MALE, y_pred=0, y_true=0),
        _make_record(ip, 2, GROUP_MALE, y_pred=1, y_true=None),
        _make_record(ip, 3, GROUP_FEMALE, y_pred=0, y_true=1),
        _make_record(ip, 4, GROUP_FEMALE, y_pred=1, y_true=0),
    ]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert (decrypted.male.P, decrypted.male.N) == (1.0, 1.0)
    assert (decrypted.female.P, decrypted.female.N) == (1.0, 1.0)
    assert decrypted.male.C == 3.0


# --- 7: TP/FP counts -----------------------------------------------------------


def test_tp_and_fp_counts_exact(bfv_crypto_setup):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [
        _make_record(ip, 0, GROUP_MALE, y_pred=1, y_true=1),
        _make_record(ip, 1, GROUP_MALE, y_pred=0, y_true=1),
        _make_record(ip, 2, GROUP_FEMALE, y_pred=1, y_true=0),
        _make_record(ip, 3, GROUP_FEMALE, y_pred=0, y_true=0),
    ]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.male.TP == 1.0 and decrypted.male.P == 2.0
    assert decrypted.female.FP == 1.0 and decrypted.female.N == 2.0


# --- 8/9: LR and RF paths ------------------------------------------------------


@pytest.mark.parametrize("model_name", [LOGISTIC_REGRESSION, RANDOM_FOREST])
def test_lr_and_rf_paths_exact_vs_plaintext(bfv_crypto_setup, model_name):
    """Same shared-record-relabelling pattern as
    test_encrypted_aggregation_direct.py's LR/RF test (see that file's
    docstring for why re-labelling is a valid exercise of the model-
    decision-agnostic aggregation code path) -- here with EXACT equality
    against the plaintext oracle, no rounding."""
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [
        _make_record(ip, i, GROUP_MALE if i % 2 == 0 else GROUP_FEMALE, y_pred=i % 3 != 0, y_true=(i % 4 != 0))
        for i in range(37)  # deliberately not a round number
    ]
    decrypted = _run_direct(records, ip, lpu, fla, model_name=model_name)

    # Independently recompute the plaintext oracle via the SAME
    # model-decision-agnostic compute_plaintext_audit used elsewhere.
    import pandas as pd

    rows = []
    for i, r in enumerate(records):
        rows.append(
            {
                "row_index": i,
                "y_true": r.y_true,
                "y_pred": r.y_pred,
                "group": GROUP_MALE if i % 2 == 0 else GROUP_FEMALE,
            }
        )
    audit_frame = pd.DataFrame(rows)
    plain = compute_plaintext_audit(audit_frame, model_name=model_name)
    for group_name, decrypted_group, plain_group in (
        ("male", decrypted.male, plain.male()),
        ("female", decrypted.female, plain.female()),
    ):
        for stat in ("C", "A", "P", "TP", "N", "FP"):
            assert getattr(decrypted_group, stat) == float(getattr(plain_group, stat)), (model_name, group_name, stat)


# --- 10: different batch sizes -------------------------------------------------


@pytest.mark.parametrize("n", [1, 2, 10, 25, 100])
def test_various_batch_sizes_exact(bfv_crypto_setup, n):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    records = [_make_record(ip, i, GROUP_MALE if i % 2 == 0 else GROUP_FEMALE, y_pred=1, y_true=1) for i in range(n)]
    decrypted = _run_direct(records, ip, lpu, fla)
    expected_male = (n + 1) // 2
    expected_female = n // 2
    assert decrypted.male.C == float(expected_male)
    assert decrypted.female.C == float(expected_female)
    assert decrypted.test_population_n == n


# --- 11/12: maximum realistic population count / near-safety-bound values ----


def test_population_at_the_full_known_lendingclub_scale_is_within_safe_bound():
    """887,440 is the largest population this codebase has ever measured
    (docs/FINAL_REPRODUCIBLE_RESULTS.md, the full cleaned/audit-eligible
    LendingClub population) -- confirms this is comfortably inside the
    chosen BFV parameterisation's safe bound without actually encrypting
    887k ciphertexts in a unit test."""
    config = BFVConfig()
    largest_known_population = 887_440
    assert largest_known_population < config.max_safe_count
    assert_population_within_bfv_safe_bound(largest_known_population, config)  # must not raise


def test_count_at_exactly_the_safety_bound_decrypts_as_itself(bfv_crypto_setup):
    """Directly exercises the signed-decoding boundary (see
    BFVConfig.max_safe_count's docstring): construct a ciphertext whose
    value IS the safety bound via repeated addition of a size-2 all-ones
    vector, using a small-enough count for a fast test, and confirm no
    accidental off-by-one in the reasoning holds at a value close to
    (but not exactly at, for test speed) the true bound. The exact-bound
    case itself is verified directly via raw ts.bfv_vector below (no
    credential issuance needed -- this is a pure encoding property, not an
    aggregation-logic property)."""
    lpu = bfv_crypto_setup["lpu_context"]
    fla = bfv_crypto_setup["fla_context"]
    config = BFVConfig()

    at_bound = ts.bfv_vector(lpu, [config.max_safe_count, config.max_safe_count])
    view = ts.bfv_vector_from(fla, at_bound.serialize())
    decrypted = view.decrypt()
    assert decrypted == [config.max_safe_count, config.max_safe_count]

    one_past_bound = ts.bfv_vector(lpu, [config.max_safe_count + 1, 0])
    view2 = ts.bfv_vector_from(fla, one_past_bound.serialize())
    decrypted2 = view2.decrypt()
    assert decrypted2[0] != config.max_safe_count + 1  # confirms the bound is real, not a placeholder
    assert decrypted2[0] < 0  # signed wraparound: the defining symptom this guard exists to prevent


def test_overflow_guard_rejects_population_above_safe_bound():
    config = BFVConfig()
    with pytest.raises(BFVOverflowError):
        assert_population_within_bfv_safe_bound(config.max_safe_count + 1, config)


def test_compute_encrypted_audit_enforces_overflow_guard_before_any_encryption(bfv_crypto_setup, monkeypatch):
    """Proves the guard fires BEFORE any per-record homomorphic work --
    monkeypatch the verify+deserialize step to explode, then confirm the
    guard still raises first for an (artificially small, for test speed)
    lowered safe-count bound."""
    from fairlend.audit import aggregation as agg_module

    ip, lpu = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(5)]

    def _explode(*args, **kwargs):
        raise AssertionError("must never reach per-record processing when the population exceeds the safe bound")

    monkeypatch.setattr(agg_module, "_load_verified_protected_attribute_vector_bfv", _explode)
    tiny_config = BFVConfig()
    object.__setattr__(tiny_config, "plain_modulus", 3)  # frozen dataclass: bypass for a deliberately tiny bound
    with pytest.raises(BFVOverflowError):
        compute_encrypted_audit(records, ip.public_key, lpu, model_name="x", bfv_config=tiny_config)


# --- Structural: no reference vectors, no multiplication, depth 0 ------------


def test_active_path_uses_no_reference_vectors():
    signature = inspect.signature(compute_encrypted_audit)
    assert "references" not in signature.parameters


def test_active_path_performs_no_ciphertext_ciphertext_multiplication(bfv_crypto_setup, monkeypatch):
    def _explode_mul(self, *args, **kwargs):
        raise AssertionError("compute_encrypted_audit (Phase 2, BFV) must never multiply ciphertexts.")

    def _explode_dot(self, *args, **kwargs):
        raise AssertionError("compute_encrypted_audit (Phase 2, BFV) must never call .dot().")

    monkeypatch.setattr(ts.BFVVector, "__mul__", _explode_mul)
    monkeypatch.setattr(ts.BFVVector, "dot", _explode_dot)

    ip, lpu = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(5)]
    result = compute_encrypted_audit(records, ip.public_key, lpu, model_name=LOGISTIC_REGRESSION)
    build_encrypted_aggregate_packet(result)  # must not raise


def test_active_path_never_decrypts_on_lpu_side(bfv_crypto_setup, monkeypatch):
    def _explode(self, *args, **kwargs):
        raise AssertionError("compute_encrypted_audit/build_encrypted_aggregate_packet must never decrypt.")

    monkeypatch.setattr(ts.BFVVector, "decrypt", _explode)
    ip, lpu = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(5)]
    result = compute_encrypted_audit(records, ip.public_key, lpu, model_name=LOGISTIC_REGRESSION)
    build_encrypted_aggregate_packet(result)  # must not raise


def test_lpu_context_never_holds_bfv_secret_key_during_aggregation(bfv_crypto_setup):
    ip, lpu, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"], bfv_crypto_setup["fla_context"]
    assert context_can_decrypt(lpu) is False
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(3)]
    _run_direct(records, ip, lpu, fla)
    assert context_can_decrypt(lpu) is False


def test_lpu_context_requires_no_relin_or_galois_keys(bfv_crypto_setup):
    """Confirms this codebase's own overflow/complexity claim
    structurally, not just by absence of a code path: the LPU-facing BFV
    context this fixture builds has NEITHER relinearisation NOR Galois
    (rotation) capability -- the direct-addition path was designed to
    need neither, and this asserts the actual context object matches
    that design rather than merely happening to work."""
    lpu = bfv_crypto_setup["lpu_context"]
    assert lpu.has_relin_keys() is False
    assert lpu.has_galois_keys() is False


def test_compute_encrypted_audit_rejects_private_context(bfv_crypto_setup):
    ip, fla = bfv_crypto_setup["ip"], bfv_crypto_setup["fla_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(3)]
    with pytest.raises(KeyBoundaryError):
        compute_encrypted_audit(records, ip.public_key, fla, model_name=LOGISTIC_REGRESSION)


def test_diagnostic_decrypt_requires_private_context(bfv_crypto_setup):
    ip, lpu = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(3)]
    result = compute_encrypted_audit(records, ip.public_key, lpu, model_name=LOGISTIC_REGRESSION)
    packet = build_encrypted_aggregate_packet(result)
    with pytest.raises(KeyBoundaryError):
        decrypt_audit_packet_for_diagnostics(packet, lpu)


def test_tampered_credential_prevents_aggregation(bfv_crypto_setup):
    ip, lpu = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(3)]
    tampered = list(records)
    tampered[0] = dataclasses.replace(tampered[0], credential=dataclasses.replace(tampered[0].credential, uid="FORGED"))
    with pytest.raises(CredentialVerificationError):
        compute_encrypted_audit(tampered, ip.public_key, lpu, model_name=LOGISTIC_REGRESSION)


def test_wrong_ip_verification_key_prevents_aggregation(bfv_crypto_setup):
    ip, lpu = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(3)]
    other_keys = SigningKeyPair.generate()
    with pytest.raises(CredentialVerificationError):
        compute_encrypted_audit(records, other_keys.public_key, lpu, model_name=LOGISTIC_REGRESSION)


# --- Packet shape: six ciphertext fields, no relin/galois key leakage -------


def test_packet_has_six_ciphertext_fields_not_twelve():
    field_names = {f.name for f in dataclasses.fields(EncryptedAuditPacket)}
    ciphertext_fields = {"C", "A", "P", "TP", "N", "FP"}
    assert ciphertext_fields <= field_names
    assert "male" not in field_names and "female" not in field_names
    for field in dataclasses.fields(EncryptedAuditPacket):
        if field.name in ciphertext_fields:
            continue
        assert field.name in {"model", "test_population_n", "resolved_test_n", "unresolved_test_n", "protocol_version"}


def test_packet_serializes_to_bytes_only_for_ciphertext_fields(bfv_crypto_setup):
    ip, lpu = bfv_crypto_setup["ip"], bfv_crypto_setup["lpu_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(3)]
    result = compute_encrypted_audit(records, ip.public_key, lpu, model_name=LOGISTIC_REGRESSION)
    packet = build_encrypted_aggregate_packet(result)
    for stat in ("C", "A", "P", "TP", "N", "FP"):
        assert isinstance(getattr(packet, stat), bytes)


def test_no_forbidden_substring_in_packet_field_names():
    forbidden = ("uid", "row_index", "gender", "probability", "account", "score", "y_true", "y_pred", "similarity")
    for field in dataclasses.fields(EncryptedAuditPacket):
        lowered = field.name.lower()
        for bad in forbidden:
            assert bad not in lowered, (field.name, bad)


def test_encrypted_audit_counts_fields_are_exactly_the_six_statistics():
    expected = {"C", "A", "P", "TP", "N", "FP"}
    actual = {f.name for f in dataclasses.fields(EncryptedAuditCounts)}
    assert actual == expected


def test_active_path_protocol_version_identifies_bfv():
    """A wire-level provenance check: a reader receiving a packet should
    be able to tell it came from the BFV active path, not the CKKS
    baseline, from the packet's own metadata alone."""
    assert "bfv" in EncryptedAuditPacket.__dataclass_fields__["protocol_version"].default.lower()
