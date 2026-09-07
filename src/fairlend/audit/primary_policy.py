"""Stage 4: primary-policy real-data evidence consolidation.

This module performs NO cryptography, model fitting, or threshold
selection. It only reads ALREADY-COMPLETED result artifacts written by
``evaluation/run_matching_fidelity.py`` (Stage 1) and
``evaluation/run_primary_policy_encrypted_audit.py`` (Stages 2/3, once per
model), independently re-derives each aggregate's absolute error from its
own stored ``raw_decrypted_count``/``plaintext_count`` pair, and asserts
internal consistency before combining them into one canonical
primary-policy table (``evaluation/build_primary_policy_results.py``).

Nothing here re-encrypts, re-aggregates, or re-selects a threshold --
doing so would defeat the point of this consolidation step, which is to
prove the STORED artifacts are internally consistent and mutually
compatible, not to regenerate them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

STAT_KEYS: Tuple[str, ...] = (
    "C_m", "C_f", "A_m", "A_f", "P_m", "P_f",
    "TP_m", "TP_f", "N_m", "N_f", "FP_m", "FP_f",
)


class ProvenanceMismatchError(ValueError):
    """Raised when a stored artifact's provenance fields disagree with
    the expected primary-policy configuration (dataset hash, alpha1,
    seed, threshold_policy, tau, population sizes)."""


class DataScopeMismatchError(ValueError):
    """Raised when a stored artifact's ``data_scope`` is not the expected
    one -- e.g. refusing to silently combine a ``synthetic_fixture``
    artifact into a ``real_lendingclub`` primary-policy result."""


class AggregateReconstructionMismatchError(ValueError):
    """Raised when a stored artifact's rounded decrypted count does not
    exactly equal its stored plaintext count for one or more of the 12
    aggregates."""


def verify_provenance(
    report: Mapping[str, Any],
    *,
    expected_dataset_sha256: str,
    expected_alpha1: float,
    expected_seed: int,
    expected_threshold_policy: str,
    expected_tau: float,
    expected_data_scope: str,
    expected_test_population_n: int | None = None,
    expected_resolved_test_n: int | None = None,
    expected_unresolved_test_n: int | None = None,
    label: str = "artifact",
) -> None:
    """Raises ``ProvenanceMismatchError``/``DataScopeMismatchError`` if
    any expected provenance field disagrees with what ``report`` (an
    encrypted-audit or fairness-reconstruction report dict) actually
    stored. Population-size checks are optional since fairness-
    reconstruction reports do not carry them."""
    checks = {
        "dataset_sha256": (report.get("dataset_sha256"), expected_dataset_sha256),
        "alpha1": (report.get("alpha1"), expected_alpha1),
        "synthetic_seed": (report.get("synthetic_seed"), expected_seed),
        "threshold_policy": (report.get("threshold_policy"), expected_threshold_policy),
        "tau": (report.get("tau"), expected_tau),
    }
    if expected_test_population_n is not None:
        checks["test_population_n"] = (report.get("test_population_n"), expected_test_population_n)
    if expected_resolved_test_n is not None:
        checks["resolved_test_n"] = (report.get("resolved_test_n"), expected_resolved_test_n)
    if expected_unresolved_test_n is not None:
        checks["unresolved_test_n"] = (report.get("unresolved_test_n"), expected_unresolved_test_n)

    mismatches = {k: v for k, v in checks.items() if v[0] != v[1]}
    if mismatches:
        raise ProvenanceMismatchError(f"{label}: provenance mismatch: {mismatches!r}")

    if report.get("data_scope") != expected_data_scope:
        raise DataScopeMismatchError(
            f"{label}: data_scope mismatch -- artifact has "
            f"{report.get('data_scope')!r}, expected {expected_data_scope!r}. "
            "Refusing to combine a fixture-scope artifact into a real-data "
            "primary-policy result (or vice versa)."
        )


def verify_aggregate_reconstruction(audit_report: Mapping[str, Any], label: str) -> Dict[str, float]:
    """Independently recomputes ``abs(raw_decrypted - plaintext)`` for all
    12 stored aggregates and asserts ``rounded == plaintext`` for every
    one. Returns the recomputed absolute-error dict (keyed the same as
    ``STAT_KEYS``). Raises ``AggregateReconstructionMismatchError`` on any
    mismatch -- this is a hard stop, per Stage 4's instructions."""
    statistics = audit_report.get("statistics")
    if statistics is None:
        raise ValueError(f"{label}: audit report has no 'statistics' field.")
    missing = set(STAT_KEYS) - set(statistics)
    if missing:
        raise ValueError(f"{label}: statistics missing keys {sorted(missing)!r}")

    recomputed_errors: Dict[str, float] = {}
    mismatched = []
    for key in STAT_KEYS:
        stat = statistics[key]
        plaintext = stat["plaintext_count"]
        raw = stat["raw_decrypted_count"]
        rounded = stat["rounded_encrypted_count"]
        recomputed_errors[key] = abs(raw - plaintext)
        if rounded != plaintext:
            mismatched.append(key)

    if mismatched:
        raise AggregateReconstructionMismatchError(
            f"{label}: rounded_encrypted_count != plaintext_count for {mismatched!r} "
            "-- STOP: do not proceed to fairness reconstruction on a mismatched artifact."
        )
    return recomputed_errors


@dataclass(frozen=True)
class PrimaryPolicyModelRow:
    """One model's canonical primary-policy row (Stage 4 Sec. 4)."""

    model: str
    tau: float
    approval_count: int
    approval_rate: float
    stats: Dict[str, int]
    dp_plain: float
    dp_encrypted: float
    dp_reconstruction_error: float
    eo_plain: float
    eo_encrypted: float
    eo_reconstruction_error: float
    dp_raw_ckks: float
    eo_raw_ckks: float
    aggregate_max_abs_error: float
    aggregate_mean_abs_error: float
    rounding_safety_margin: float
    runtime_seconds: float
    records_per_second: float
    run_id: str
    packet_sha256: str
    reference_fingerprint: str


def build_primary_policy_row(
    audit_report: Mapping[str, Any], fairness_report: Mapping[str, Any], model_name: str
) -> PrimaryPolicyModelRow:
    """Builds one model's canonical row, re-verifying aggregate
    reconstruction (never trusting the stored ``absolute_error`` field
    without recomputing it) and cross-checking that ``audit_report`` and
    ``fairness_report`` are the SAME run (same ``run_id``/
    ``packet_sha256``/``reference_fingerprint``) before combining them."""
    for key in ("run_id", "packet_sha256", "reference_fingerprint"):
        if audit_report.get(key) != fairness_report.get(key):
            raise ProvenanceMismatchError(
                f"{model_name}: audit report and fairness report disagree on {key!r} "
                f"({audit_report.get(key)!r} != {fairness_report.get(key)!r}) -- "
                "these do not appear to be the same run's artifacts."
            )

    recomputed_errors = verify_aggregate_reconstruction(audit_report, model_name)
    stats = {k: audit_report["statistics"][k]["plaintext_count"] for k in STAT_KEYS}
    max_abs_error = max(recomputed_errors.values())
    mean_abs_error = sum(recomputed_errors.values()) / len(recomputed_errors)

    return PrimaryPolicyModelRow(
        model=model_name,
        tau=audit_report["tau"],
        approval_count=audit_report["test_approval_count"],
        approval_rate=audit_report["test_approval_rate"],
        stats=stats,
        dp_plain=fairness_report["DP_plain"],
        dp_encrypted=fairness_report["DP_encrypted"],
        dp_reconstruction_error=fairness_report["e_DP"],
        eo_plain=fairness_report["EO_plain"],
        eo_encrypted=fairness_report["EO_encrypted"],
        eo_reconstruction_error=fairness_report["e_EO"],
        dp_raw_ckks=fairness_report["DP_raw_ckks"],
        eo_raw_ckks=fairness_report["EO_raw_ckks"],
        aggregate_max_abs_error=max_abs_error,
        aggregate_mean_abs_error=mean_abs_error,
        rounding_safety_margin=0.5 - max_abs_error,
        runtime_seconds=audit_report["runtime_seconds"],
        records_per_second=audit_report["records_per_second"],
        run_id=audit_report["run_id"],
        packet_sha256=audit_report["packet_sha256"],
        reference_fingerprint=audit_report["reference_fingerprint"],
    )


def verify_matching_dataset_hash(
    matching_threshold: Mapping[str, Any],
    matching_run_row: Mapping[str, Any],
    *,
    expected_dataset_sha256: str,
    expected_data_scope: str,
) -> None:
    """Stage 4 Sec. 2/6: the Stage-1 matching-fidelity artifact (a
    SEPARATE evaluation script/result from the Stage 2/3 encrypted
    audits) must agree with the same dataset SHA-256 and data_scope
    before being merged into one primary-policy document. Checks both
    the summary ``matching_threshold.json`` document and the
    corresponding row of ``matching_fidelity_runs.csv``."""
    for label, source in (
        ("matching_threshold.json", matching_threshold),
        ("matching_fidelity_runs.csv row", matching_run_row),
    ):
        actual_hash = str(source.get("dataset_sha256"))
        if actual_hash != expected_dataset_sha256:
            raise ProvenanceMismatchError(
                f"{label}: dataset_sha256 ({actual_hash!r}) does not match "
                f"the expected dataset SHA-256 ({expected_dataset_sha256!r})."
            )
    if matching_threshold.get("data_scope") != expected_data_scope:
        raise DataScopeMismatchError(
            f"matching_threshold.json: data_scope ({matching_threshold.get('data_scope')!r}) "
            f"does not match expected data_scope ({expected_data_scope!r})."
        )


def assert_distinct_realisations(rows: Mapping[str, PrimaryPolicyModelRow]) -> None:
    """Stage 4 Sec. 2: each model's cryptographic realisation
    (``run_id``/``packet_sha256``/``reference_fingerprint``) must be
    distinct from every other model's -- CKKS encryption is
    non-deterministic by design, so two genuinely independent runs must
    never coincidentally (or due to accidental artifact reuse) share a
    fingerprint."""
    for field in ("run_id", "packet_sha256", "reference_fingerprint"):
        values = [getattr(row, field) for row in rows.values()]
        if len(set(values)) != len(values):
            raise ProvenanceMismatchError(
                f"Two or more models share the same {field!r} ({values!r}) -- "
                "expected independent cryptographic realisations per model."
            )
