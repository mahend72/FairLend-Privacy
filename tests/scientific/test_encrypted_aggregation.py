"""Scientific invariant tests for the encrypted audit aggregation (Phase 5,
manuscript Algorithm 5): C/A/P/TP/N/FP population logic, key-boundary
enforcement, packet round-trip, and tamper/wrong-key rejection.

Uses a hermetic, self-contained pipeline built from
tests/fixtures/lendingclub_sample.csv via library calls (exactly the
pattern of tests/scientific/test_plaintext_audit.py) -- no dependency on
the (gitignored) data/processed/ directory, so this test suite is
portable to a fresh clone/CI. A separate, skip-guarded test at the bottom
of this file checks the actual committed
results/fixture_validation/evaluation/model_predictions.parquet against
the exact fixture counts named in the Phase 5 task spec, when that
gitignored intermediate data happens to be present in this environment.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pandas as pd
import pytest
import tenseal as ts

from fairlend.audit.aggregation import (
    EncryptedTestRecord,
    build_audit_frame,
    build_encrypted_aggregate_packet,
    compute_encrypted_audit,
    decrypt_audit_packet_for_diagnostics,
)
from fairlend.core.exceptions import CredentialVerificationError, KeyBoundaryError
from fairlend.crypto.ckks import build_fla_context, context_can_decrypt, derive_lpu_context
from fairlend.crypto.signatures import SigningKeyPair
from fairlend.models.credit_models import LOGISTIC_REGRESSION
from fairlend.audit.similarity import generate_encrypted_references, load_reference_vectors
from fairlend.roles.identity_provider import IdentityProvider

# The `pipeline` fixture used throughout this module (and shared with
# test_encrypted_aggregation_privacy.py) is defined in
# tests/scientific/conftest.py and is provided automatically via pytest
# fixture discovery.


def _run_encrypted(protocol) -> "DecryptedAuditPacket":  # noqa: F821 (type imported lazily below)
    result = compute_encrypted_audit(
        protocol["records"], protocol["ip"].public_key, protocol["references"], protocol["lpu_context"],
        model_name=LOGISTIC_REGRESSION,
    )
    packet = build_encrypted_aggregate_packet(result)
    return decrypt_audit_packet_for_diagnostics(packet, protocol["fla_context"])


# --- A: encrypted-zero initialisation compatibility -------------------------


def test_encrypted_zero_is_addable_to_a_postmultiplication_ciphertext(pipeline):
    """Directly exercises the level/scale compatibility this phase's
    design note relies on: TenSEAL's auto_mod_switch must reconcile a
    fresh top-level zero with a post-comp_sim (one-multiplication-deep)
    ciphertext without manual level handling."""
    lpu_context = pipeline["lpu_context"]
    from fairlend.audit.similarity import comp_sim

    credential = pipeline["records"][0].credential
    pair = comp_sim(credential, pipeline["ip"].public_key, pipeline["references"], lpu_context)
    zero = ts.ckks_vector(lpu_context, [0.0])
    combined = zero + pair.male_score_ciphertext  # must not raise
    decrypted = decrypt_via_fla(combined, pipeline["fla_context"])
    assert decrypted == pytest.approx(pair_expected_male(pipeline), abs=1e-2)


def decrypt_via_fla(ciphertext, fla_context) -> float:
    view = ts.ckks_vector_from(fla_context, ciphertext.serialize())
    return view.decrypt()[0]


def pair_expected_male(pipeline) -> float:
    first_row = pipeline["audit_frame"].iloc[0]
    return 1.0 if first_row["group"] == "male" else 0.0


# --- B/C/D/E: population logic (compared against Phase 2 plaintext) --------


def test_encrypted_c_matches_plaintext(pipeline):
    decrypted = _run_encrypted(pipeline)
    plain = pipeline["plaintext_result"]
    assert round(decrypted.male.C) == plain.male().C
    assert round(decrypted.female.C) == plain.female().C


def test_encrypted_a_matches_plaintext(pipeline):
    decrypted = _run_encrypted(pipeline)
    plain = pipeline["plaintext_result"]
    assert round(decrypted.male.A) == plain.male().A
    assert round(decrypted.female.A) == plain.female().A


def test_encrypted_p_and_n_match_plaintext(pipeline):
    decrypted = _run_encrypted(pipeline)
    plain = pipeline["plaintext_result"]
    assert round(decrypted.male.P) == plain.male().P
    assert round(decrypted.female.P) == plain.female().P
    assert round(decrypted.male.N) == plain.male().N
    assert round(decrypted.female.N) == plain.female().N


def test_encrypted_tp_and_fp_match_plaintext(pipeline):
    decrypted = _run_encrypted(pipeline)
    plain = pipeline["plaintext_result"]
    assert round(decrypted.male.TP) == plain.male().TP
    assert round(decrypted.female.TP) == plain.female().TP
    assert round(decrypted.male.FP) == plain.male().FP
    assert round(decrypted.female.FP) == plain.female().FP


# --- F: unresolved rows never contribute to P/N/TP/FP -----------------------


def test_unresolved_rows_excluded_from_outcome_aggregates(pipeline):
    unresolved_records = [r for r in pipeline["records"] if r.y_true is None]
    assert len(unresolved_records) > 0  # fixture must actually exercise this

    result_without_unresolved = compute_encrypted_audit(
        [r for r in pipeline["records"] if r.y_true is not None],
        pipeline["ip"].public_key,
        pipeline["references"],
        pipeline["lpu_context"],
        model_name=LOGISTIC_REGRESSION,
    )
    packet = build_encrypted_aggregate_packet(result_without_unresolved)
    decrypted_without_unresolved = decrypt_audit_packet_for_diagnostics(packet, pipeline["fla_context"])
    decrypted_with_unresolved = _run_encrypted(pipeline)

    # P/N/TP/FP must be IDENTICAL whether or not unresolved rows are
    # included -- proving they never contribute -- while C changes.
    for stat in ("P", "N", "TP", "FP"):
        for group in ("male", "female"):
            with_val = round(getattr(getattr(decrypted_with_unresolved, group), stat))
            without_val = round(getattr(getattr(decrypted_without_unresolved, group), stat))
            assert with_val == without_val
    assert round(decrypted_with_unresolved.male.C) + round(decrypted_with_unresolved.female.C) > round(
        decrypted_without_unresolved.male.C
    ) + round(decrypted_without_unresolved.female.C)


# --- G: model separation (structural, no cross-model mixing) ---------------


def test_metadata_records_the_correct_model_name(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name=LOGISTIC_REGRESSION,
    )
    packet = build_encrypted_aggregate_packet(result)
    assert packet.model == LOGISTIC_REGRESSION


# --- I/J: public-only LPU execution, no decrypt -----------------------------


def test_lpu_context_never_holds_sk_he_during_aggregation(pipeline):
    assert context_can_decrypt(pipeline["lpu_context"]) is False
    _run_encrypted(pipeline)  # must succeed without ever needing sk_HE
    assert context_can_decrypt(pipeline["lpu_context"]) is False  # still true afterwards


def test_compute_encrypted_audit_rejects_private_context(pipeline):
    with pytest.raises(KeyBoundaryError):
        compute_encrypted_audit(
            pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["fla_context"],
            model_name=LOGISTIC_REGRESSION,
        )


def test_no_decrypt_call_occurs_during_lpu_side_aggregation(pipeline, monkeypatch):
    def _explode(self, *args, **kwargs):
        raise AssertionError("compute_encrypted_audit/build_encrypted_aggregate_packet must never decrypt.")

    monkeypatch.setattr(ts.CKKSVector, "decrypt", _explode)
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name=LOGISTIC_REGRESSION,
    )
    build_encrypted_aggregate_packet(result)  # must not raise


# --- K/L/M: packet structure, serialization round trip, FLA decryption -----


def test_packet_serializes_to_bytes_only_fields(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name=LOGISTIC_REGRESSION,
    )
    packet = build_encrypted_aggregate_packet(result)
    for group_counts in (packet.male, packet.female):
        for field in dataclasses.fields(group_counts):
            assert isinstance(getattr(group_counts, field.name), bytes)


def test_serialization_round_trip_through_fla_context(pipeline):
    decrypted = _run_encrypted(pipeline)
    plain = pipeline["plaintext_result"]
    assert round(decrypted.male.C) == plain.male().C
    assert round(decrypted.female.C) == plain.female().C


def test_diagnostic_decrypt_requires_private_context(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name=LOGISTIC_REGRESSION,
    )
    packet = build_encrypted_aggregate_packet(result)
    with pytest.raises(KeyBoundaryError):
        decrypt_audit_packet_for_diagnostics(packet, pipeline["lpu_context"])


# --- N: rounded counts equal plaintext fixture counts -----------------------


def test_all_rounded_encrypted_counts_equal_plaintext_counts(pipeline):
    decrypted = _run_encrypted(pipeline)
    plain = pipeline["plaintext_result"]
    for group_name, decrypted_group, plain_group in (
        ("male", decrypted.male, plain.male()),
        ("female", decrypted.female, plain.female()),
    ):
        for stat in ("C", "A", "P", "TP", "N", "FP"):
            assert round(getattr(decrypted_group, stat)) == getattr(plain_group, stat), (group_name, stat)


# --- O/P: tampered/invalid credential and wrong IP key prevent aggregation --


def test_tampered_credential_prevents_aggregation(pipeline):
    tampered_records = list(pipeline["records"])
    tampered_records[0] = dataclasses.replace(
        tampered_records[0], credential=dataclasses.replace(tampered_records[0].credential, uid="FORGED")
    )
    with pytest.raises(CredentialVerificationError):
        compute_encrypted_audit(
            tampered_records, pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
            model_name=LOGISTIC_REGRESSION,
        )


def test_wrong_ip_verification_key_prevents_aggregation(pipeline):
    other_ip_keys = SigningKeyPair.generate()
    with pytest.raises(CredentialVerificationError):
        compute_encrypted_audit(
            pipeline["records"], other_ip_keys.public_key, pipeline["references"], pipeline["lpu_context"],
            model_name=LOGISTIC_REGRESSION,
        )


# --- Skip-guarded golden-fixture check against the real committed artifact -


REPO_ROOT = Path(__file__).resolve().parents[2]
FROZEN_PREDICTIONS = REPO_ROOT / "results" / "fixture_validation" / "evaluation" / "model_predictions.parquet"
FIXTURE_PROCESSED_DIR = REPO_ROOT / "data" / "processed" / "fixture_validation"

EXPECTED_FIXTURE_COUNTS = {
    "logistic_regression": {
        "C_m": 19, "C_f": 19, "A_m": 14, "A_f": 16, "P_m": 7, "P_f": 9,
        "TP_m": 7, "TP_f": 8, "N_m": 4, "N_f": 5, "FP_m": 3, "FP_f": 5,
    },
    "random_forest": {
        "C_m": 19, "C_f": 19, "A_m": 19, "A_f": 19, "P_m": 7, "P_f": 9,
        "TP_m": 7, "TP_f": 9, "N_m": 4, "N_f": 5, "FP_m": 4, "FP_f": 5,
    },
}


@pytest.mark.skipif(
    not (FROZEN_PREDICTIONS.exists() and FIXTURE_PROCESSED_DIR.exists()),
    reason="gitignored data/processed/fixture_validation intermediate not present in this checkout",
)
@pytest.mark.parametrize("model_name", ["logistic_regression", "random_forest"])
def test_golden_fixture_counts_match_task_specified_values(model_name):
    """These specific numbers are fixture expected values for THIS test
    only (task Sec. 13) -- they are not hardcoded into any implementation
    logic anywhere in src/fairlend."""
    predictions = pd.read_parquet(FROZEN_PREDICTIONS)
    synthetic_gender = pd.read_parquet(FIXTURE_PROCESSED_DIR / "synthetic_gender_alpha1_0.7_seed_0.parquet")
    train_index = pd.Index(pd.read_parquet(FIXTURE_PROCESSED_DIR / "train_index.parquet")["index"])
    validation_index = pd.Index(pd.read_parquet(FIXTURE_PROCESSED_DIR / "validation_index.parquet")["index"])
    test_index = pd.Index(pd.read_parquet(FIXTURE_PROCESSED_DIR / "test_index.parquet")["index"])
    test_eo_index = pd.Index(pd.read_parquet(FIXTURE_PROCESSED_DIR / "test_eo_index.parquet")["index"])

    model_predictions = predictions[predictions["model"] == model_name]
    audit_frame = build_audit_frame(
        model_predictions, synthetic_gender, test_index, test_eo_index, train_index, validation_index
    )

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)
    references = load_reference_vectors(generate_encrypted_references(fla_context), lpu_context)

    records = []
    for row in audit_frame.itertuples(index=False):
        credential = ip.issue_credential(str(row.id), row.group)
        y_true = None if pd.isna(row.y_true) else int(row.y_true)
        records.append(
            EncryptedTestRecord(row_index=int(row.row_index), credential=credential, y_pred=int(row.y_pred), y_true=y_true)
        )

    result = compute_encrypted_audit(records, ip.public_key, references, lpu_context, model_name=model_name)
    packet = build_encrypted_aggregate_packet(result)
    decrypted = decrypt_audit_packet_for_diagnostics(packet, fla_context)

    expected = EXPECTED_FIXTURE_COUNTS[model_name]
    actual = {
        "C_m": round(decrypted.male.C), "C_f": round(decrypted.female.C),
        "A_m": round(decrypted.male.A), "A_f": round(decrypted.female.A),
        "P_m": round(decrypted.male.P), "P_f": round(decrypted.female.P),
        "TP_m": round(decrypted.male.TP), "TP_f": round(decrypted.female.TP),
        "N_m": round(decrypted.male.N), "N_f": round(decrypted.female.N),
        "FP_m": round(decrypted.male.FP), "FP_f": round(decrypted.female.FP),
    }
    assert actual == expected
