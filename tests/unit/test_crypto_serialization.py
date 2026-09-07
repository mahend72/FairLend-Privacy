"""Unit tests for fairlend.crypto.serialization.canonical_encode:
determinism, field-boundary collision resistance, and type strictness."""
from __future__ import annotations

import pytest

from fairlend.crypto.serialization import canonical_encode


def test_identical_logical_objects_encode_identically_regardless_of_key_order():
    a = canonical_encode({"uid": "B001", "account": "ACC001"})
    b = canonical_encode({"account": "ACC001", "uid": "B001"})
    assert a == b


def test_encoding_is_deterministic_across_repeated_calls():
    fields = {"domain": "fairlend/account/v1", "uid": "B001", "account": "ACC001"}
    assert canonical_encode(fields) == canonical_encode(dict(fields))


def test_different_field_boundaries_do_not_collide():
    """The classic naive-concatenation forgery: str(uid)+str(account) would
    make uid='AB',account='C' collide with uid='A',account='BC'. Canonical
    encoding must keep these distinct."""
    a = canonical_encode({"uid": "AB", "account": "C"})
    b = canonical_encode({"uid": "A", "account": "BC"})
    assert a != b


def test_different_values_produce_different_encodings():
    a = canonical_encode({"uid": "B001", "score": 720})
    b = canonical_encode({"uid": "B001", "score": 721})
    assert a != b


def test_domain_tag_prevents_cross_credential_type_collision():
    """Two different credential types with otherwise-identical fields must
    not encode identically -- this is the domain-separation mechanism."""
    a = canonical_encode({"domain": "fairlend/account/v1", "uid": "B001", "value": "X"})
    b = canonical_encode({"domain": "fairlend/score/v1", "uid": "B001", "value": "X"})
    assert a != b


def test_bytes_values_are_hex_encoded_and_round_trip_distinctly():
    a = canonical_encode({"digest": b"\x00\x01"})
    b = canonical_encode({"digest": b"\x00\x02"})
    assert a != b
    assert b"__bytes_hex__" in a


def test_bytes_value_is_never_confused_with_a_string_that_looks_similar():
    a = canonical_encode({"field": b"AB"})
    b = canonical_encode({"field": "4142"})  # hex of b"AB", as a plain string
    assert a != b


def test_nested_mapping_is_supported_and_deterministic():
    a = canonical_encode({"outer": {"b": 2, "a": 1}})
    b = canonical_encode({"outer": {"a": 1, "b": 2}})
    assert a == b


def test_list_order_is_preserved_and_significant():
    a = canonical_encode({"items": [1, 2, 3]})
    b = canonical_encode({"items": [3, 2, 1]})
    assert a != b


def test_output_is_utf8_bytes():
    result = canonical_encode({"uid": "B001"})
    assert isinstance(result, bytes)
    result.decode("utf-8")  # must not raise


def test_unsupported_type_raises_rather_than_silently_stringifying():
    class Unsupported:
        pass

    with pytest.raises(TypeError):
        canonical_encode({"value": Unsupported()})


def test_no_incidental_whitespace():
    encoded = canonical_encode({"a": 1, "b": 2})
    assert b" " not in encoded
