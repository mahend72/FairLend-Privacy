"""PHASE 1 (production, direct encrypted-additive aggregation) scientific
invariant tests: proves the compSim-removal architecture correction
(reviewer2_phase1_compsim_removal_report.md) preserves every invariant
the legacy compSim-based path (tests/scientific/test_encrypted_
aggregation.py, now legacy) established, while using strictly less
homomorphic machinery (addition only, no reference vectors, no
ciphertext-ciphertext multiplication, multiplicative depth 0).

Uses the same hermetic ``pipeline`` fixture (tests/scientific/conftest.py)
as the legacy test files, so this suite is directly comparable to them --
same fixture data, same credentials, same frozen predictions.
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
    build_encrypted_aggregate_packet,
    compute_encrypted_audit,
    decrypt_audit_packet_for_diagnostics,
)
from fairlend.core.exceptions import CredentialVerificationError, KeyBoundaryError
from fairlend.crypto.ckks import context_can_decrypt
from fairlend.crypto.signatures import SigningKeyPair
from fairlend.models.credit_models import LOGISTIC_REGRESSION, RANDOM_FOREST

# The `pipeline` fixture is defined in tests/scientific/conftest.py and is
# provided automatically via pytest fixture discovery (shared with the
# legacy test files). It is built from the logistic-regression model only
# (see conftest.py); this file additionally builds a small, self-contained
# all-male/all-female/mixed/empty-group fixture directly (scenarios 1-4
# below), since the shared pipeline's synthetic-gender mix is not
# guaranteed to contain those exact cases.


def _run_direct(records, ip, lpu_context, fla_context, model_name=LOGISTIC_REGRESSION):
    result = compute_encrypted_audit(records, ip.public_key, lpu_context, model_name=model_name)
    packet = build_encrypted_aggregate_packet(result)
    return decrypt_audit_packet_for_diagnostics(packet, fla_context)


def _make_record(ip, idx, group, y_pred, y_true):
    credential = ip.issue_credential(f"synthetic-{idx}", group)
    return EncryptedTestRecord(row_index=idx, credential=credential, y_pred=y_pred, y_true=y_true)


@pytest.fixture()
def small_crypto_setup():
    from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
    from fairlend.roles.identity_provider import IdentityProvider

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)
    return {"fla_context": fla_context, "lpu_context": lpu_context, "ip": ip}


# --- 1: all-male batch -------------------------------------------------------


def test_all_male_batch(small_crypto_setup):
    ip, lpu, fla = small_crypto_setup["ip"], small_crypto_setup["lpu_context"], small_crypto_setup["fla_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=1, y_true=1) for i in range(5)]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.male.rounded() == {"C": 5, "A": 5, "P": 5, "TP": 5, "N": 0, "FP": 0}
    assert decrypted.female.rounded() == {"C": 0, "A": 0, "P": 0, "TP": 0, "N": 0, "FP": 0}


# --- 2: all-female batch ------------------------------------------------------


def test_all_female_batch(small_crypto_setup):
    ip, lpu, fla = small_crypto_setup["ip"], small_crypto_setup["lpu_context"], small_crypto_setup["fla_context"]
    records = [_make_record(ip, i, GROUP_FEMALE, y_pred=0, y_true=0) for i in range(4)]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.female.rounded() == {"C": 4, "A": 0, "P": 0, "TP": 0, "N": 4, "FP": 0}
    assert decrypted.male.rounded() == {"C": 0, "A": 0, "P": 0, "TP": 0, "N": 0, "FP": 0}


# --- 3: mixed batch -----------------------------------------------------------


def test_mixed_batch_matches_hand_computed_counts(small_crypto_setup):
    ip, lpu, fla = small_crypto_setup["ip"], small_crypto_setup["lpu_context"], small_crypto_setup["fla_context"]
    records = [
        _make_record(ip, 0, GROUP_MALE, y_pred=1, y_true=1),  # C_m,A_m,P_m,TP_m
        _make_record(ip, 1, GROUP_FEMALE, y_pred=0, y_true=1),  # C_f,P_f
        _make_record(ip, 2, GROUP_FEMALE, y_pred=1, y_true=0),  # C_f,A_f,N_f,FP_f
        _make_record(ip, 3, GROUP_MALE, y_pred=1, y_true=None),  # C_m,A_m (unresolved)
    ]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.male.rounded() == {"C": 2, "A": 2, "P": 1, "TP": 1, "N": 0, "FP": 0}
    assert decrypted.female.rounded() == {"C": 2, "A": 1, "P": 1, "TP": 0, "N": 1, "FP": 1}
    assert decrypted.test_population_n == 4
    assert decrypted.resolved_test_n == 3
    assert decrypted.unresolved_test_n == 1


# --- 4: empty/zero-count group (valid: one group entirely absent) -----------


def test_one_group_entirely_absent_reconstructs_as_exact_zero(small_crypto_setup):
    ip, lpu, fla = small_crypto_setup["ip"], small_crypto_setup["lpu_context"], small_crypto_setup["fla_context"]
    records = [_make_record(ip, i, GROUP_MALE, y_pred=i % 2, y_true=1 if i % 2 == 0 else 0) for i in range(6)]
    decrypted = _run_direct(records, ip, lpu, fla)
    for stat in ("C", "A", "P", "TP", "N", "FP"):
        assert getattr(decrypted.female, stat) == pytest.approx(0.0, abs=1e-3)
    assert decrypted.male.rounded()["C"] == 6


# --- 5: approval-conditioned counts (A) --------------------------------------


def test_approval_conditioned_counts(small_crypto_setup):
    ip, lpu, fla = small_crypto_setup["ip"], small_crypto_setup["lpu_context"], small_crypto_setup["fla_context"]
    records = [
        _make_record(ip, 0, GROUP_MALE, y_pred=1, y_true=None),
        _make_record(ip, 1, GROUP_MALE, y_pred=0, y_true=None),
        _make_record(ip, 2, GROUP_FEMALE, y_pred=1, y_true=None),
        _make_record(ip, 3, GROUP_FEMALE, y_pred=1, y_true=None),
        _make_record(ip, 4, GROUP_FEMALE, y_pred=0, y_true=None),
    ]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.male.rounded()["C"] == 2 and decrypted.male.rounded()["A"] == 1
    assert decrypted.female.rounded()["C"] == 3 and decrypted.female.rounded()["A"] == 2


# --- 6: positive/negative outcome-conditioned counts (P/N) -------------------


def test_outcome_conditioned_p_and_n_counts(small_crypto_setup):
    ip, lpu, fla = small_crypto_setup["ip"], small_crypto_setup["lpu_context"], small_crypto_setup["fla_context"]
    records = [
        _make_record(ip, 0, GROUP_MALE, y_pred=1, y_true=1),
        _make_record(ip, 1, GROUP_MALE, y_pred=0, y_true=0),
        _make_record(ip, 2, GROUP_MALE, y_pred=1, y_true=None),  # unresolved: must not affect P/N
        _make_record(ip, 3, GROUP_FEMALE, y_pred=0, y_true=1),
        _make_record(ip, 4, GROUP_FEMALE, y_pred=1, y_true=0),
    ]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.male.rounded()["P"] == 1 and decrypted.male.rounded()["N"] == 1
    assert decrypted.female.rounded()["P"] == 1 and decrypted.female.rounded()["N"] == 1
    assert decrypted.male.rounded()["C"] == 3  # includes the unresolved record


# --- 7: TP/FP counts ----------------------------------------------------------


def test_tp_and_fp_counts(small_crypto_setup):
    ip, lpu, fla = small_crypto_setup["ip"], small_crypto_setup["lpu_context"], small_crypto_setup["fla_context"]
    records = [
        _make_record(ip, 0, GROUP_MALE, y_pred=1, y_true=1),  # TP_m
        _make_record(ip, 1, GROUP_MALE, y_pred=0, y_true=1),  # P_m only, not TP (not approved)
        _make_record(ip, 2, GROUP_FEMALE, y_pred=1, y_true=0),  # FP_f
        _make_record(ip, 3, GROUP_FEMALE, y_pred=0, y_true=0),  # N_f only, not FP (not approved)
    ]
    decrypted = _run_direct(records, ip, lpu, fla)
    assert decrypted.male.rounded()["TP"] == 1
    assert decrypted.male.rounded()["P"] == 2
    assert decrypted.female.rounded()["FP"] == 1
    assert decrypted.female.rounded()["N"] == 2


# --- 8/9: LR and RF evaluation paths (via the shared hermetic pipeline) -----


@pytest.mark.parametrize("model_name", [LOGISTIC_REGRESSION, RANDOM_FOREST])
def test_lr_and_rf_paths_match_plaintext_audit(pipeline, model_name):
    """The shared `pipeline` fixture is built with a logistic-regression
    model (conftest.py), but its plaintext-audit oracle and its
    EncryptedTestRecord list depend only on y_pred/y_true/credential --
    not on which model produced y_pred. Re-labelling the SAME records
    under a different model_name and re-running compute_plaintext_audit
    exercises the identical LR-vs-RF code path
    (fairlend.audit.aggregation is model-decision-agnostic by design, see
    its module docstring) without needing a second trained model here."""
    from fairlend.audit.aggregation import compute_plaintext_audit

    decrypted = _run_direct(
        pipeline["records"], pipeline["ip"], pipeline["lpu_context"], pipeline["fla_context"], model_name=model_name
    )
    plain = compute_plaintext_audit(pipeline["audit_frame"], model_name=model_name)
    for group_name, decrypted_group, plain_group in (
        ("male", decrypted.male, plain.male()),
        ("female", decrypted.female, plain.female()),
    ):
        for stat in ("C", "A", "P", "TP", "N", "FP"):
            assert round(getattr(decrypted_group, stat)) == getattr(plain_group, stat), (model_name, group_name, stat)


# --- Structural: no comp_sim, no ciphertext multiplication, depth 0 ---------


def test_direct_path_does_not_call_comp_sim():
    # Checks for an actual CALL (``comp_sim(``), not the bare substring --
    # this function's own docstring legitimately mentions "comp_sim" in
    # prose when explaining what it replaces.
    source = inspect.getsource(aggregation_module.compute_encrypted_audit)
    assert "comp_sim(" not in source
    packet_source = inspect.getsource(aggregation_module.build_encrypted_aggregate_packet)
    assert "comp_sim(" not in packet_source


def test_direct_path_uses_no_reference_vectors():
    signature = inspect.signature(compute_encrypted_audit)
    assert "references" not in signature.parameters


def test_direct_path_performs_no_ciphertext_ciphertext_multiplication(pipeline, monkeypatch):
    """Monkeypatches CKKSVector's multiplication entry points so that ANY
    multiplication attempted during compute_encrypted_audit raises --
    mirroring the existing test_no_decrypt_call_occurs_during_lpu_side_
    aggregation pattern in the legacy privacy test file. If this test
    passes, the direct-addition path performed zero multiplications for
    this run, not merely "probably none"."""

    def _explode_mul(self, *args, **kwargs):
        raise AssertionError("compute_encrypted_audit (Phase 1, direct addition) must never multiply ciphertexts.")

    def _explode_dot(self, *args, **kwargs):
        raise AssertionError("compute_encrypted_audit (Phase 1, direct addition) must never call .dot().")

    monkeypatch.setattr(ts.CKKSVector, "__mul__", _explode_mul)
    monkeypatch.setattr(ts.CKKSVector, "dot", _explode_dot)

    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["lpu_context"], model_name=LOGISTIC_REGRESSION
    )
    build_encrypted_aggregate_packet(result)  # must not raise


def test_direct_path_never_decrypts_on_lpu_side(pipeline, monkeypatch):
    def _explode(self, *args, **kwargs):
        raise AssertionError("compute_encrypted_audit/build_encrypted_aggregate_packet must never decrypt.")

    monkeypatch.setattr(ts.CKKSVector, "decrypt", _explode)
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["lpu_context"], model_name=LOGISTIC_REGRESSION
    )
    build_encrypted_aggregate_packet(result)  # must not raise


def test_lpu_context_never_holds_sk_he_during_direct_aggregation(pipeline):
    assert context_can_decrypt(pipeline["lpu_context"]) is False
    _run_direct(pipeline["records"], pipeline["ip"], pipeline["lpu_context"], pipeline["fla_context"])
    assert context_can_decrypt(pipeline["lpu_context"]) is False


def test_compute_encrypted_audit_rejects_private_context(pipeline):
    with pytest.raises(KeyBoundaryError):
        compute_encrypted_audit(
            pipeline["records"], pipeline["ip"].public_key, pipeline["fla_context"], model_name=LOGISTIC_REGRESSION
        )


def test_diagnostic_decrypt_requires_private_context(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["lpu_context"], model_name=LOGISTIC_REGRESSION
    )
    packet = build_encrypted_aggregate_packet(result)
    with pytest.raises(KeyBoundaryError):
        decrypt_audit_packet_for_diagnostics(packet, pipeline["lpu_context"])


def test_tampered_credential_prevents_aggregation(pipeline):
    tampered_records = list(pipeline["records"])
    tampered_records[0] = dataclasses.replace(
        tampered_records[0], credential=dataclasses.replace(tampered_records[0].credential, uid="FORGED")
    )
    with pytest.raises(CredentialVerificationError):
        compute_encrypted_audit(
            tampered_records, pipeline["ip"].public_key, pipeline["lpu_context"], model_name=LOGISTIC_REGRESSION
        )


def test_wrong_ip_verification_key_prevents_aggregation(pipeline):
    other_ip_keys = SigningKeyPair.generate()
    with pytest.raises(CredentialVerificationError):
        compute_encrypted_audit(
            pipeline["records"], other_ip_keys.public_key, pipeline["lpu_context"], model_name=LOGISTIC_REGRESSION
        )


# --- Packet shape: half the legacy path's ciphertext count -------------------


def test_packet_has_six_ciphertext_fields_not_twelve():
    field_names = {f.name for f in dataclasses.fields(EncryptedAuditPacket)}
    ciphertext_fields = {"C", "A", "P", "TP", "N", "FP"}
    assert ciphertext_fields <= field_names
    assert "male" not in field_names and "female" not in field_names
    for field in dataclasses.fields(EncryptedAuditPacket):
        if field.name in ciphertext_fields:
            continue
        assert field.name in {"model", "test_population_n", "resolved_test_n", "unresolved_test_n", "protocol_version"}


def test_packet_serializes_to_bytes_only_for_ciphertext_fields(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["lpu_context"], model_name=LOGISTIC_REGRESSION
    )
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
