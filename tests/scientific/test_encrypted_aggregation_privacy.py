"""Privacy invariant tests for the encrypted audit packet (task Sec.
7/10): exhaustive field-level proof that EncryptedAuditPacket contains no
borrower-level data, plus the LPU-side execution/decrypt-boundary checks
from Sec. 10.

Uses the same hermetic pipeline as test_encrypted_aggregation.py.
"""
from __future__ import annotations

import dataclasses
import inspect

import pytest
import tenseal as ts

from fairlend.audit import aggregation as aggregation_module
from fairlend.audit.aggregation import (
    EncryptedAuditPacket,
    SerializedGroupAuditCounts,
    build_encrypted_aggregate_packet,
    compute_encrypted_audit,
)
from fairlend.crypto.ckks import context_can_decrypt

# The `pipeline` fixture is defined in tests/scientific/conftest.py and is
# provided automatically via pytest fixture discovery (shared with
# test_encrypted_aggregation.py).

FORBIDDEN_FIELD_SUBSTRINGS = (
    "uid",
    "id",
    "row_index",
    "gender",
    "male",  # also catches "female"
    "probability",
    "account",
    "score",
    "y_true",
    "y_pred",
    "similarity",
)
# "male"/"female" are legitimate STRUCTURAL group keys on the packet
# (EncryptedAuditPacket.male / .female) -- those are allowed; what must
# never exist is a field carrying the borrower's actual plaintext label
# or a per-record value. We check field NAMES at the top level separately
# from the nested SerializedGroupAuditCounts (which legitimately has no
# such fields either).


def _all_field_names(dataclass_type) -> list:
    names = []
    for field in dataclasses.fields(dataclass_type):
        names.append(field.name)
    return names


def test_encrypted_audit_packet_top_level_fields_are_exactly_expected():
    expected = {"male", "female", "model", "test_population_n", "resolved_test_n", "unresolved_test_n", "protocol_version"}
    actual = set(_all_field_names(EncryptedAuditPacket))
    assert actual == expected


def test_serialized_group_counts_fields_are_exactly_the_six_statistics():
    expected = {"C", "A", "P", "TP", "N", "FP"}
    actual = set(_all_field_names(SerializedGroupAuditCounts))
    assert actual == expected


def test_no_forbidden_substring_in_any_packet_field_name():
    allowed_exceptions = {"male", "female"}  # structural group keys, not a leaked label
    for dataclass_type in (EncryptedAuditPacket, SerializedGroupAuditCounts):
        for name in _all_field_names(dataclass_type):
            if name in allowed_exceptions:
                continue
            lowered = name.lower()
            for bad in FORBIDDEN_FIELD_SUBSTRINGS:
                if bad in ("male",):
                    continue  # handled via allowed_exceptions above
                assert bad not in lowered, (dataclass_type.__name__, name, bad)


def test_packet_contains_no_uid_or_row_index_valued_fields(pipeline):
    """Structural proof, not a byte-substring search: a short numeric uid
    (e.g. "45") WILL appear by pure chance somewhere in ~400KB of
    pseudo-random CKKS ciphertext bytes (P(a given 2-byte pattern occurs
    in 400KB of noise) is close to 1) -- searching for it there is
    statistically meaningless and was found, during implementation, to
    produce exactly that false positive. The real guarantee is
    structural: no packet field is typed/named to HOLD a uid or
    row_index at all -- every field is either a fixed-shape ciphertext
    (bytes) or a population-count integer explicitly enumerated by
    test_encrypted_audit_packet_top_level_fields_are_exactly_expected."""
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    packet = build_encrypted_aggregate_packet(result)
    top_level_int_fields = {"test_population_n", "resolved_test_n", "unresolved_test_n"}
    for field in dataclasses.fields(packet):
        if field.name in ("male", "female"):
            continue
        value = getattr(packet, field.name)
        if field.name in top_level_int_fields:
            assert isinstance(value, int)
            # These are POPULATION counts (<= len(records)), never a
            # specific row_index or uid value.
            assert 0 <= value <= len(pipeline["records"])
        else:
            assert isinstance(value, str)  # model / protocol_version only


def test_packet_field_count_is_small_and_fixed_regardless_of_test_population_size(pipeline):
    """The packet's shape must not grow with the number of TEST records --
    a growing packet would itself be a sign of per-record data leaking in."""
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    packet = build_encrypted_aggregate_packet(result)
    assert len(dataclasses.fields(packet)) == 7  # fixed, independent of len(records)


# --- Sec. 10 numbered privacy checks ----------------------------------------


def test_1_lpu_has_no_sk_he_throughout_aggregation(pipeline):
    assert context_can_decrypt(pipeline["lpu_context"]) is False
    compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    assert context_can_decrypt(pipeline["lpu_context"]) is False


def test_2_aggregation_module_never_calls_decrypt_outside_diagnostic_function():
    source = inspect.getsource(aggregation_module)
    # The ONLY legitimate ".decrypt(" call in this module must be inside
    # decrypt_audit_packet_for_diagnostics / _decrypt_group (its helper).
    lines_with_decrypt = [line for line in source.splitlines() if ".decrypt(" in line]
    assert len(lines_with_decrypt) >= 1  # the diagnostic path itself must exist
    # Structural check: compute_encrypted_audit's and
    # build_encrypted_aggregate_packet's own source (not the whole module)
    # contain no decrypt call.
    compute_source = inspect.getsource(aggregation_module.compute_encrypted_audit)
    packet_source = inspect.getsource(aggregation_module.build_encrypted_aggregate_packet)
    assert ".decrypt(" not in compute_source
    assert ".decrypt(" not in packet_source


def test_3_packet_contains_no_uid(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    packet = build_encrypted_aggregate_packet(result)
    assert not hasattr(packet, "uid")


def test_4_packet_contains_no_row_index(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    packet = build_encrypted_aggregate_packet(result)
    assert not hasattr(packet, "row_index")


def test_5_packet_contains_no_plaintext_protected_attribute(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    packet = build_encrypted_aggregate_packet(result)
    for group_counts in (packet.male, packet.female):
        for field in dataclasses.fields(group_counts):
            assert isinstance(getattr(group_counts, field.name), bytes)  # ciphertext only, never a plaintext label


def test_6_packet_contains_no_per_record_similarity_list(pipeline):
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    packet = build_encrypted_aggregate_packet(result)
    # Exactly 6 ciphertexts per group (the aggregates), not len(records).
    assert len(dataclasses.fields(packet.male)) == 6
    assert len(dataclasses.fields(packet.female)) == 6


def test_7_packet_contains_no_account_or_score_credential_values():
    expected = {"male", "female", "model", "test_population_n", "resolved_test_n", "unresolved_test_n", "protocol_version"}
    actual = set(_all_field_names(EncryptedAuditPacket))
    assert "account" not in actual
    assert "score" not in actual
    assert actual == expected


def test_8_packet_producible_with_public_only_context(pipeline):
    assert context_can_decrypt(pipeline["lpu_context"]) is False
    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    packet = build_encrypted_aggregate_packet(result)
    assert packet is not None


def test_9_packet_consumable_by_fla_private_context(pipeline):
    from fairlend.audit.aggregation import decrypt_audit_packet_for_diagnostics

    result = compute_encrypted_audit(
        pipeline["records"], pipeline["ip"].public_key, pipeline["references"], pipeline["lpu_context"],
        model_name="logistic_regression",
    )
    packet = build_encrypted_aggregate_packet(result)
    decrypted = decrypt_audit_packet_for_diagnostics(packet, pipeline["fla_context"])
    assert decrypted.male.C > 0


def test_10_no_print_or_logging_in_aggregation_module():
    source = inspect.getsource(aggregation_module)
    assert "print(" not in source
    assert "logging" not in source
    assert "logger" not in source.lower()
