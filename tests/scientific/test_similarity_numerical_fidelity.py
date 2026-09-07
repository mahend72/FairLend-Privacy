"""compSim numerical fidelity, repeated-encryption error statistics, and a
runtime sanity check (task Sec. 11-13).

These are cryptographic numerical-fidelity checks against a deterministic
diagnostic fixture -- NOT a dataset experiment, and NOT the matching-
fidelity delta* evaluation (a later phase). No group classification
(argmax/delta*/matched-unmatched) is computed here; only the raw
decrypted similarity scores and their error against the exact plaintext
inner product t in {0, 1}.

Run with `pytest -s` to see the printed summary tables (pytest captures
stdout by default; the assertions themselves are the checked-in scientific
result regardless of `-s`).
"""
from __future__ import annotations

import statistics
import time

import pytest

from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
from fairlend.roles.identity_provider import IdentityProvider
from fairlend.audit.similarity import (
    comp_sim,
    decrypt_similarity_pair_for_diagnostics,
    generate_encrypted_references,
    load_reference_vectors,
)

# Test-choice sample size -- NOT a manuscript-required number (task Sec. 12).
N_PER_GENDER = 100


@pytest.fixture(scope="module")
def protocol():
    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)
    references = generate_encrypted_references(fla_context)
    lpu_references = load_reference_vectors(references, lpu_context)
    return {
        "fla_context": fla_context,
        "lpu_context": lpu_context,
        "ip": ip,
        "lpu_references": lpu_references,
    }


def _score_for(protocol, uid: str, gender: str):
    credential = protocol["ip"].issue_credential(uid, gender)
    pair = comp_sim(credential, protocol["ip"].public_key, protocol["lpu_references"], protocol["lpu_context"])
    return decrypt_similarity_pair_for_diagnostics(pair.serialize(), protocol["fla_context"])


def _summarize(values, expected: float) -> dict:
    errors = [v - expected for v in values]
    abs_errors = [abs(e) for e in errors]
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "std": statistics.pstdev(values),
        "min": min(values),
        "max": max(values),
        "mae": statistics.fmean(abs_errors),
        "max_abs_error": max(abs_errors),
    }


@pytest.fixture(scope="module")
def repeated_encryption_results(protocol):
    """N_PER_GENDER independent, freshly-randomised encryptions per
    gender (task Sec. 12: "100 male credentials, 100 female credentials
    using fresh randomized CKKS encryption")."""
    male_own_scores = []  # male credential's OWN male_score (expect ~1)
    male_other_scores = []  # male credential's female_score (expect ~0)
    female_own_scores = []  # female credential's OWN female_score (expect ~1)
    female_other_scores = []  # female credential's male_score (expect ~0)

    for i in range(N_PER_GENDER):
        result = _score_for(protocol, f"male-{i}", "male")
        male_own_scores.append(result.male_score)
        male_other_scores.append(result.female_score)

    for i in range(N_PER_GENDER):
        result = _score_for(protocol, f"female-{i}", "female")
        female_own_scores.append(result.female_score)
        female_other_scores.append(result.male_score)

    return {
        "expected_one": male_own_scores + female_own_scores,
        "expected_zero": male_other_scores + female_other_scores,
    }


def test_numerical_fidelity_expected_one_scores(repeated_encryption_results):
    summary = _summarize(repeated_encryption_results["expected_one"], expected=1.0)
    print("\n=== compSim numerical fidelity: expected-1 scores (n=%d) ===" % summary["n"])
    print(f"  mean={summary['mean']:.8f} std={summary['std']:.8e}")
    print(f"  min={summary['min']:.8f} max={summary['max']:.8f}")
    print(f"  MAE={summary['mae']:.8e} max_abs_error={summary['max_abs_error']:.8e}")
    # Generous bound: this pins "compSim is numerically sound", not a
    # tight bound on CKKS noise for its own sake.
    assert summary["mae"] < 1e-3
    assert summary["max_abs_error"] < 1e-2


def test_numerical_fidelity_expected_zero_scores(repeated_encryption_results):
    summary = _summarize(repeated_encryption_results["expected_zero"], expected=0.0)
    print("\n=== compSim numerical fidelity: expected-0 scores (n=%d) ===" % summary["n"])
    print(f"  mean={summary['mean']:.8f} std={summary['std']:.8e}")
    print(f"  min={summary['min']:.8f} max={summary['max']:.8f}")
    print(f"  MAE={summary['mae']:.8e} max_abs_error={summary['max_abs_error']:.8e}")
    assert summary["mae"] < 1e-3
    assert summary["max_abs_error"] < 1e-2


def test_expected_one_and_expected_zero_score_ranges_do_not_overlap(repeated_encryption_results):
    """A basic separability sanity check for the LATER matching-fidelity
    phase (not implemented here) -- delta* selection is explicitly out of
    scope for this phase, but the raw scores should already be far apart
    on this deterministic one-hot fixture."""
    max_expected_zero = max(repeated_encryption_results["expected_zero"])
    min_expected_one = min(repeated_encryption_results["expected_one"])
    print(f"\nmax(expected-0)={max_expected_zero:.6f} min(expected-1)={min_expected_one:.6f}")
    assert max_expected_zero < min_expected_one


# --- Performance sanity check (task Sec. 13) --------------------------------


@pytest.mark.parametrize("n_operations", [1, 10, 100])
def test_compsim_runtime_sanity_check(protocol, n_operations):
    """Detects pathological behaviour (e.g. accidental O(n^2) context
    handling) -- NOT the final manuscript runtime benchmark."""
    credentials = [protocol["ip"].issue_credential(f"perf-{i}", "male") for i in range(n_operations)]

    durations = []
    for credential in credentials:
        start = time.perf_counter()
        comp_sim(credential, protocol["ip"].public_key, protocol["lpu_references"], protocol["lpu_context"])
        durations.append(time.perf_counter() - start)

    mean_s = statistics.fmean(durations)
    median_s = statistics.median(durations)
    print(
        f"\ncompSim runtime sanity (n={n_operations}): "
        f"mean={mean_s * 1000:.3f}ms median={median_s * 1000:.3f}ms "
        f"total={sum(durations):.3f}s"
    )
    # Generous ceiling to catch pathological behaviour only (e.g. a
    # per-call context rebuild), not a performance target.
    assert mean_s < 1.0
