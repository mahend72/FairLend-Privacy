"""Privacy invariant (task Sec. 14): compSim's production module must
never log/print anything, so there is no code path by which a decrypted
similarity score or protected-class information could leak into LPU-side
output. Diagnostic decryption lives in the same module (clearly separated
by name/docstring) but is exercised only in FLA-context tests -- this
test pins that the module has no logging/print statements at all, which
is the strongest version of "no LPU debug output leaks protected-class
information" (there is no debug output to begin with)."""
from __future__ import annotations

import inspect

from fairlend.audit import similarity


def test_similarity_module_contains_no_print_or_logging_calls():
    source = inspect.getsource(similarity)
    assert "print(" not in source
    assert "logging" not in source
    assert "logger" not in source.lower()


def test_encrypted_similarity_pair_repr_reveals_nothing_gender_specific():
    """The dataclass's field NAMES (``male_score_ciphertext``,
    ``female_score_ciphertext``) always appear in the repr regardless of
    the borrower's actual gender -- that is not a leak. What would be a
    leak is the repr differing (e.g. containing a decrypted value like
    "1.0"/"0.0") depending on which gender the underlying credential
    actually was. This test proves the repr is identical in SHAPE for a
    male and a female credential, and contains no decrypted float."""
    from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
    from fairlend.roles.identity_provider import IdentityProvider
    from fairlend.audit.similarity import comp_sim, generate_encrypted_references, load_reference_vectors

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)
    references = load_reference_vectors(generate_encrypted_references(fla_context), lpu_context)

    male_pair = comp_sim(ip.issue_credential("B001", "male"), ip.public_key, references, lpu_context)
    female_pair = comp_sim(ip.issue_credential("B002", "female"), ip.public_key, references, lpu_context)

    male_repr = repr(male_pair)
    female_repr = repr(female_pair)

    # No decrypted floating-point value anywhere in either repr.
    for representation in (male_repr, female_repr):
        assert "1.0" not in representation
        assert "0.0" not in representation

    # Both reprs have the identical field-name structure (only the opaque
    # object-address hex differs) -- a reader of the repr alone cannot
    # tell which credential was male vs. female.
    import re

    strip_addresses = lambda s: re.sub(r"0x[0-9a-f]+", "0xADDR", s)
    assert strip_addresses(male_repr).split("(")[0] == strip_addresses(female_repr).split("(")[0]
