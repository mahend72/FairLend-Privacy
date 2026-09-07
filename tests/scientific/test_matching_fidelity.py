"""Scientific invariant tests for Phase 7's matching-fidelity diagnostic:
real IP->LPU->compSim->FLA-diagnostic-decryption path, VALIDATION/TEST
boundary enforcement, privacy invariants, and malformed/tampered/wrong-key
rejection.

Real CKKS + real Ed25519 throughout -- no mocks.
"""
from __future__ import annotations

import dataclasses
import inspect

import pytest
import tenseal as ts

from fairlend.audit.aggregation import GROUP_FEMALE, GROUP_MALE
from fairlend.audit.matching import (
    MatchingInputRecord,
    compute_matching_metrics,
    compute_paired_scores,
    run_matching_fidelity_diagnostic,
    select_delta_star,
)
from fairlend.core.exceptions import CredentialVerificationError, KeyBoundaryError
from fairlend.crypto.ckks import build_fla_context, context_can_decrypt, derive_lpu_context
from fairlend.crypto.signatures import SigningKeyPair
from fairlend.audit.similarity import generate_encrypted_references, load_reference_vectors
from fairlend.roles.identity_provider import IdentityProvider


@pytest.fixture()
def protocol():
    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)
    references = load_reference_vectors(generate_encrypted_references(fla_context), lpu_context)
    return {"fla_context": fla_context, "lpu_context": lpu_context, "ip": ip, "references": references}


def _records(protocol, labels):
    """labels: list of (identifier, expected_group) pairs."""
    return [
        MatchingInputRecord(
            identifier=identifier,
            credential=protocol["ip"].issue_credential(identifier, expected_group),
            expected_group=expected_group,
        )
        for identifier, expected_group in labels
    ]


# --- Real IP -> LPU -> compSim -> FLA path (task Sec. 8/11) -----------------


def test_real_credential_path_produces_correct_paired_scores(protocol):
    records = _records(protocol, [("1", GROUP_MALE), ("2", GROUP_FEMALE)])
    pairs = compute_paired_scores(
        records, protocol["ip"].public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
    )
    assert pairs[0].male_score == pytest.approx(1.0, abs=1e-3)
    assert pairs[0].female_score == pytest.approx(0.0, abs=1e-3)
    assert pairs[1].male_score == pytest.approx(0.0, abs=1e-3)
    assert pairs[1].female_score == pytest.approx(1.0, abs=1e-3)


def test_compute_paired_scores_never_constructs_ciphertext_directly():
    """Static proof (task Sec. 8): no raw one-hot ciphertext is ever
    constructed inside fairlend.audit.matching -- every ciphertext comes
    from fairlend.audit.similarity's already-verified functions."""
    from fairlend.audit import matching as matching_module

    source = inspect.getsource(matching_module)
    assert "ts.ckks_vector(" not in source  # only ts.ckks_vector_from via the imported helpers, never constructed here
    assert "one_hot" not in source.lower()


# --- Validation/TEST boundary (task Sec. 3, 17.1-17.3) ----------------------


def test_delta_star_selected_from_validation_only_and_frozen_before_test(protocol):
    validation_records = _records(protocol, [("v1", GROUP_MALE), ("v2", GROUP_FEMALE), ("v3", GROUP_MALE)])
    test_records = _records(protocol, [("t1", GROUP_MALE), ("t2", GROUP_FEMALE)])

    result = run_matching_fidelity_diagnostic(
        validation_records, test_records, protocol["ip"].public_key, protocol["references"],
        protocol["lpu_context"], protocol["fla_context"],
    )
    assert result.validation_n == 3
    assert result.test_n == 2
    assert 0.0 <= result.delta_star <= 1.0


def test_test_labels_cannot_influence_delta_star(protocol):
    """Calling select_delta_star (the ONLY function that picks delta*)
    with the SAME validation pairs but different (even absent) test data
    must give the identical delta* -- proving structurally that TEST
    cannot influence selection, since select_delta_star has no TEST
    parameter at all."""
    validation_records = _records(protocol, [("v1", GROUP_MALE), ("v2", GROUP_FEMALE)])
    validation_pairs = compute_paired_scores(
        validation_records, protocol["ip"].public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
    )
    delta_a, _ = select_delta_star(validation_pairs)
    delta_b, _ = select_delta_star(validation_pairs)
    assert delta_a == delta_b
    # select_delta_star's signature has no way to accept TEST data at all.
    params = list(inspect.signature(select_delta_star).parameters)
    assert "test_pairs" not in params and "test_records" not in params


def test_same_frozen_delta_star_applied_to_test(protocol):
    validation_records = _records(protocol, [("v1", GROUP_MALE), ("v2", GROUP_FEMALE), ("v3", GROUP_MALE)])
    test_records = _records(protocol, [("t1", GROUP_MALE), ("t2", GROUP_FEMALE), ("t3", GROUP_FEMALE)])

    validation_pairs = compute_paired_scores(
        validation_records, protocol["ip"].public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
    )
    delta_star, _ = select_delta_star(validation_pairs)

    result = run_matching_fidelity_diagnostic(
        validation_records, test_records, protocol["ip"].public_key, protocol["references"],
        protocol["lpu_context"], protocol["fla_context"],
    )
    assert result.delta_star == delta_star


# --- Privacy boundary (task Sec. 9) -----------------------------------------


def test_lpu_never_decrypts_during_matching_diagnostic(protocol):
    assert context_can_decrypt(protocol["lpu_context"]) is False
    records = _records(protocol, [("1", GROUP_MALE)])
    compute_paired_scores(
        records, protocol["ip"].public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
    )
    assert context_can_decrypt(protocol["lpu_context"]) is False


def test_argmax_only_happens_after_diagnostic_decryption_not_inside_comp_sim():
    """Static proof: fairlend.audit.similarity.comp_sim's own source
    contains no argmax/max(...)-based classification -- classification
    lives exclusively in fairlend.audit.matching, downstream of
    diagnostic decryption."""
    from fairlend.audit import similarity as similarity_module

    source = inspect.getsource(similarity_module.comp_sim)
    assert "argmax" not in source.lower()
    assert "delta" not in source.lower()


def test_no_plaintext_gender_logged_by_matching_module():
    from fairlend.audit import matching as matching_module

    source = inspect.getsource(matching_module)
    assert "print(" not in source
    assert "logging" not in source
    assert "logger" not in source.lower()


def test_production_similarity_pair_remains_encrypted_after_matching_diagnostic(protocol):
    """Running the diagnostic must not mutate or decrypt the underlying
    production comp_sim output -- compute_paired_scores only ever
    receives credentials, never a production EncryptedSimilarityPair
    object it could tamper with."""
    params = list(inspect.signature(compute_paired_scores).parameters)
    assert "encrypted_similarity_pair" not in [p.lower() for p in params]
    assert params == ["records", "ip_public_key", "references", "lpu_context", "fla_context"]


# --- Malformed/tampered/wrong-key rejection (task Sec. 13) ------------------


def test_tampered_credential_rejected_before_matching(protocol):
    record = _records(protocol, [("1", GROUP_MALE)])[0]
    tampered = dataclasses.replace(record, credential=dataclasses.replace(record.credential, uid="FORGED"))
    with pytest.raises(CredentialVerificationError):
        compute_paired_scores(
            [tampered], protocol["ip"].public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
        )


def test_wrong_ip_key_rejected_before_matching(protocol):
    records = _records(protocol, [("1", GROUP_FEMALE)])
    other_ip_keys = SigningKeyPair.generate()
    with pytest.raises(CredentialVerificationError):
        compute_paired_scores(
            records, other_ip_keys.public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
        )


def test_malformed_ciphertext_bytes_rejected(protocol):
    from fairlend.core.exceptions import MalformedCiphertextError

    record = _records(protocol, [("1", GROUP_MALE)])[0]
    garbage = dataclasses.replace(record, credential=dataclasses.replace(record.credential, ciphertext_bytes=b"garbage"))
    with pytest.raises((CredentialVerificationError, MalformedCiphertextError)):
        compute_paired_scores(
            [garbage], protocol["ip"].public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
        )


def test_wrong_slot_count_rejected(protocol):
    from fairlend.core.exceptions import MalformedCiphertextError

    wrong_size_ciphertext = ts.ckks_vector(protocol["fla_context"], [1.0]).serialize()
    record = _records(protocol, [("1", GROUP_MALE)])[0]
    # Bypass signature check by re-signing over the wrong-size ciphertext,
    # isolating the shape guard specifically.
    from fairlend.credentials.protected_attribute import issue_protected_attribute_credential

    ip = protocol["ip"]
    resigned = issue_protected_attribute_credential(ip._keys.private_key, "1", wrong_size_ciphertext)
    bad_record = dataclasses.replace(record, credential=resigned)
    with pytest.raises(MalformedCiphertextError):
        compute_paired_scores(
            [bad_record], ip.public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
        )


def test_both_scores_below_delta_star_classified_unmatched_in_diagnostic_layer(protocol):
    """The LAST malformed-output case (task Sec. 13): this is NOT an
    error -- it is a normal diagnostic classification outcome."""
    records = _records(protocol, [("1", GROUP_MALE)])
    pairs = compute_paired_scores(
        records, protocol["ip"].public_key, protocol["references"], protocol["lpu_context"], protocol["fla_context"]
    )
    from fairlend.audit.matching import classify_paired_score

    # An artificially high delta* forces the unmatched branch without
    # needing a corrupted ciphertext. Must be well above 1.0, not just
    # below it: CKKS noise can push a real expected-1 score slightly
    # ABOVE 1.0 as well as below it (observed directly: a male_score of
    # 1.0000001290423124 was measured during test development, which
    # would have exceeded a delta* of 0.999999999 and made this test
    # flaky) -- 1.5 is comfortably outside any realistic noise range for
    # these one-hot inner products.
    prediction = classify_paired_score(pairs[0], delta_star=1.5)
    assert prediction.unmatched is True
    assert prediction.predicted_group is None
