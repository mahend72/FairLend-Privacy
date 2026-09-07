"""Package-level tests for installed-package behaviour (not scientific
correctness, which is covered elsewhere under tests/unit and
tests/scientific).

These tests are deliberately independent of the current working
directory / repository checkout layout: they only touch the installed
`fairlend` package plus a small in-memory-constructed CKKS context, so
they pass identically whether run from a repository clone or against a
wheel installed in an unrelated directory.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import fairlend


def test_fairlend_imports():
    assert fairlend is not None


def test_fairlend_version_resolves():
    assert isinstance(fairlend.__version__, str)
    assert fairlend.__version__ != ""


def test_secure_compute_imports_and_public_names_resolve():
    from fairlend.secure_compute import (
        build_encrypted_aggregate_packet,
        build_fla_context,
        comp_sim,
        compute_encrypted_audit,
        compute_fairness_reconstruction,
        context_can_decrypt,
        decrypt_audit_packet_for_diagnostics,
        derive_lpu_context,
        generate_encrypted_references,
        load_reference_vectors,
    )

    assert callable(build_fla_context)
    assert callable(derive_lpu_context)
    assert callable(context_can_decrypt)
    assert callable(generate_encrypted_references)
    assert callable(load_reference_vectors)
    assert callable(comp_sim)
    assert callable(compute_encrypted_audit)
    assert callable(build_encrypted_aggregate_packet)
    assert callable(decrypt_audit_packet_for_diagnostics)
    assert callable(compute_fairness_reconstruction)


def test_secure_compute_is_a_facade_over_the_canonical_implementation():
    """fairlend.secure_compute must not be a second implementation --
    every re-exported name must be object-identical to its canonical
    home in fairlend.crypto / fairlend.audit."""
    from fairlend import secure_compute
    from fairlend.audit import aggregation, reconstruction, similarity
    from fairlend.crypto import ckks

    assert secure_compute.build_fla_context is ckks.build_fla_context
    assert secure_compute.derive_lpu_context is ckks.derive_lpu_context
    assert secure_compute.comp_sim is similarity.comp_sim
    assert secure_compute.compute_encrypted_audit is aggregation.compute_encrypted_audit
    assert (
        secure_compute.compute_fairness_reconstruction
        is reconstruction.compute_fairness_reconstruction
    )


def test_lpu_fla_key_separation_via_public_api():
    from fairlend.secure_compute import build_fla_context, derive_lpu_context

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)

    assert fla_context.has_secret_key()
    assert not lpu_context.has_secret_key()


def test_credentials_public_api_resolves():
    from fairlend.credentials import (
        AccountCredential,
        ProtectedAttributeCredential,
        ScoreCredential,
        issue_account_credential,
        issue_protected_attribute_credential,
        issue_score_credential,
    )

    assert isinstance(AccountCredential, type)
    assert isinstance(ScoreCredential, type)
    assert isinstance(ProtectedAttributeCredential, type)
    assert callable(issue_account_credential)
    assert callable(issue_score_credential)
    assert callable(issue_protected_attribute_credential)


def test_audit_fairness_public_api_resolves():
    from fairlend.audit import (
        DemographicParityResult,
        EqualisedOddsResult,
        compute_demographic_parity,
        compute_equalised_odds,
    )

    assert isinstance(DemographicParityResult, type)
    assert isinstance(EqualisedOddsResult, type)
    assert callable(compute_demographic_parity)
    assert callable(compute_equalised_odds)


def test_subpackages_import_independent_of_cwd(tmp_path, monkeypatch):
    """Simulates the portability requirement (section 11): importing
    every top-level subpackage must not depend on the current working
    directory being inside the repository checkout."""
    monkeypatch.chdir(tmp_path)
    for module_name in [
        "fairlend",
        "fairlend.secure_compute",
        "fairlend.audit",
        "fairlend.credentials",
        "fairlend.crypto",
        "fairlend.roles",
        "fairlend.core",
    ]:
        importlib.import_module(module_name)


def test_installed_package_does_not_bundle_raw_or_processed_data():
    """No dataset file (raw CSV, processed parquet, cache) should ship
    inside the fairlend package tree itself."""
    package_root = Path(fairlend.__file__).resolve().parent
    forbidden_suffixes = {".csv", ".parquet"}
    offending = [
        path
        for path in package_root.rglob("*")
        if path.suffix.lower() in forbidden_suffixes
    ]
    assert offending == []
