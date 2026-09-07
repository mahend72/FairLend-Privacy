#!/usr/bin/env python3
"""Phase 11: reproducible runtime and communication-size benchmarking of
the REBUILT FairLend implementation.

Every timing benchmark calls the actual production functions
(``fairlend.crypto``/``fairlend.audit``/``fairlend.roles``) unmodified --
this script adds no new cryptographic or protocol behaviour, only
measurement. Two concepts are kept strictly separate throughout, per the
task's standing instruction:

  A. RUNTIME measurements (this script's timing benchmarks + the
     already-measured Phase 9 full-scale application runs, reported
     separately and never averaged together).
  B. COMMUNICATION/STORAGE measurements, themselves split into:
     1. ACTUAL serialized-object byte measurements (``len(...)`` on the
        real bytes the implementation produces).
     2. ANALYTICAL CKKS size ESTIMATES (``fairlend.benchmarks.
        serialization_estimate`` -- a formula, never inferred from or
        forced to match the measured bytes).

No secret key material (``sk_HE``, Ed25519 private keys, private-context
serialized bytes) is ever written to a result file -- only integer byte
LENGTHS of secret-bearing objects are computed transiently and discarded
(see ``_measure_len_only``).

Usage:
    python evaluation/run_benchmarks.py --output-dir results/benchmarks/ \\
        --metadata-output results/metadata/benchmark_environment.json
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Callable, List, Optional

import tenseal as ts

from fairlend.audit.aggregation import (
    GROUP_FEMALE,
    GROUP_MALE,
    GROUPS,
    EncryptedTestRecord,
    GroupAuditCounts,
    PlaintextAuditResult,
    build_encrypted_aggregate_packet,
    compute_encrypted_audit,
    decrypt_audit_packet_for_diagnostics,
)
from fairlend.audit.fairness import compute_demographic_parity, compute_equalised_odds
from fairlend.audit.similarity import comp_sim, generate_encrypted_references, load_reference_vectors
from fairlend.benchmarks.communication import (
    ONE_TIME,
    PER_APPLICATION,
    PER_AUDIT_BATCH,
    CommunicationPathEntry,
    project_total_communication_bytes,
    total_bytes_by_category,
)
from fairlend.benchmarks.environment import collect_environment_metadata
from fairlend.benchmarks.serialization_estimate import analytical_ciphertext_bytes, percentage_difference
from fairlend.benchmarks.timing import TimingResult, time_repeated
from fairlend.core.config import CKKSConfig
from fairlend.credentials.account import AccountCredential
from fairlend.credentials.protected_attribute import ProtectedAttributeCredential
from fairlend.credentials.score import ScoreCredential
from fairlend.crypto.ckks import build_fla_context, context_can_decrypt, derive_lpu_context
from fairlend.crypto.serialization import canonical_encode
from fairlend.roles.bank import Bank
from fairlend.roles.credit_agency import CreditAgency
from fairlend.roles.identity_provider import IdentityProvider
from fairlend.roles.lpu import LoanProcessingUnit

REPO_ROOT = Path(__file__).resolve().parents[1]
BATCH_SIZES = (1, 5, 10, 25, 50, 100, 250, 500, 1000)
FULL_SCALE_APPLICATION_RUNS = {
    # Phase 9's already-measured, real 177k/266k-record LendingClub runs --
    # stored here as a fixed constant (not recomputed) so this script can
    # report them ALONGSIDE its own controlled microbenchmarks without
    # rerunning a multi-hour experiment. See docs/MANUSCRIPT_EVIDENCE_STATUS.md
    # Phase 9 for the original measurement.
    "matching_fidelity": {
        "runtime_seconds": 7819.66, "n_records": 266233, "run_id": "cd08706ed9b4428fb232b89a7ac9d1b1",
    },
    "lr_encrypted_aggregation": {
        "runtime_seconds": 5273.05, "n_records": 177489, "run_id": "9459dbee9e814e4bbe18745b8bf3fead",
    },
    "rf_encrypted_aggregation": {
        "runtime_seconds": 5641.28, "n_records": 177489, "run_id": "e9ef4b95f79c43febe040fba47b2b5dc",
    },
}


def _repeats_for_batch_size(batch_size: int) -> int:
    """Phase 11 Sec. 4: 30 repeats for micro-operations, at least 5 for
    larger batches "where runtime remains practical"."""
    if batch_size <= 10:
        return 30
    if batch_size <= 100:
        return 10
    return 5


def _ckks_config_dict(config: CKKSConfig) -> dict:
    return {
        "poly_modulus_degree": config.poly_modulus_degree,
        "coeff_mod_bit_sizes": list(config.coeff_mod_bit_sizes),
        "global_scale_power": config.global_scale_power,
    }


def _measure_len_only(fn: Callable[[], bytes]) -> int:
    """Calls ``fn`` (expected to return secret-bearing serialized bytes),
    records ONLY the integer length, and lets the actual bytes fall out of
    scope immediately -- never returned, never written anywhere (Phase 11
    Sec. 10)."""
    data = fn()
    length = len(data)
    del data
    return length


def _timing_row(result: TimingResult) -> dict:
    return {
        "component": result.component,
        "operation": result.operation,
        "batch_size": result.batch_size,
        "n_warmup": result.n_warmup,
        "n": result.n,
        "mean_ns": result.mean_ns,
        "std_ns": result.std_ns,
        "median_ns": result.median_ns,
        "min_ns": result.min_ns,
        "max_ns": result.max_ns,
        "p95_ns": result.p95_ns,
        "mean_ms_per_record": result.mean_ms_per_record,
        "records_per_second": result.records_per_second,
    }


def run_timing_benchmarks(fla_context, lpu_context, ip, bank, ca, lpu, references) -> List[TimingResult]:
    results: List[TimingResult] = []

    # --- A. CKKS setup (constant-cost operations, 30 repeats) ---
    results.append(time_repeated(lambda: build_fla_context(), component="A_ckks_setup",
                                  operation="fla_private_context_generation", batch_size=1, n_repeats=30, n_warmup=3))
    results.append(time_repeated(lambda: derive_lpu_context(fla_context), component="A_ckks_setup",
                                  operation="lpu_public_context_derivation", batch_size=1, n_repeats=30, n_warmup=3))
    results.append(time_repeated(lambda: generate_encrypted_references(fla_context), component="A_ckks_setup",
                                  operation="encrypted_reference_generation", batch_size=1, n_repeats=30, n_warmup=3))

    for batch_size in BATCH_SIZES:
        n_repeats = _repeats_for_batch_size(batch_size)

        # --- B. Credential issuance ---
        results.append(time_repeated(
            lambda n=batch_size: [bank.issue_account_credential(f"uid{i}", f"acct{i}") for i in range(n)],
            component="B_credential_issuance", operation="bank_account_credential",
            batch_size=batch_size, n_repeats=n_repeats, n_warmup=2,
        ))
        results.append(time_repeated(
            lambda n=batch_size: [ca.issue_score_credential(f"uid{i}", 650 + i % 100) for i in range(n)],
            component="B_credential_issuance", operation="ca_score_credential",
            batch_size=batch_size, n_repeats=n_repeats, n_warmup=2,
        ))
        results.append(time_repeated(
            lambda n=batch_size: [ip.issue_credential(f"uid{i}", GROUP_MALE if i % 2 == 0 else GROUP_FEMALE) for i in range(n)],
            component="B_credential_issuance", operation="ip_protected_attribute_credential",
            batch_size=batch_size, n_repeats=n_repeats, n_warmup=2,
        ))

        # --- C. Credential verification (pre-issue once, untimed) ---
        account_creds = [bank.issue_account_credential(f"vuid{i}", f"vacct{i}") for i in range(batch_size)]
        score_creds = [ca.issue_score_credential(f"vuid{i}", 700) for i in range(batch_size)]
        ip_creds = [ip.issue_credential(f"vuid{i}", GROUP_MALE if i % 2 == 0 else GROUP_FEMALE) for i in range(batch_size)]

        results.append(time_repeated(
            lambda creds=account_creds: [lpu.verify_account_credential(c) for c in creds],
            component="C_credential_verification", operation="bank_verification",
            batch_size=batch_size, n_repeats=n_repeats, n_warmup=2,
        ))
        results.append(time_repeated(
            lambda creds=score_creds: [lpu.verify_score_credential(c) for c in creds],
            component="C_credential_verification", operation="ca_verification",
            batch_size=batch_size, n_repeats=n_repeats, n_warmup=2,
        ))
        results.append(time_repeated(
            lambda creds=ip_creds: [lpu.verify_protected_attribute_credential(c) for c in creds],
            component="C_credential_verification", operation="ip_verification",
            batch_size=batch_size, n_repeats=n_repeats, n_warmup=2,
        ))

        # --- D. Protected-group processing ---
        results.append(time_repeated(
            lambda creds=ip_creds: [comp_sim(c, ip.public_key, references, lpu_context) for c in creds],
            component="D_protected_group_processing", operation="comp_sim",
            batch_size=batch_size, n_repeats=n_repeats, n_warmup=2,
        ))

        similarity_pairs = [comp_sim(c, ip.public_key, references, lpu_context) for c in ip_creds]

        def _aggregate_update(pairs=similarity_pairs):
            accumulators = {g: {s: ts.ckks_vector(lpu_context, [0.0]) for s in ("C", "A", "P", "TP", "N", "FP")} for g in GROUPS}
            for pair in pairs:
                scores = {GROUP_MALE: pair.male_score_ciphertext, GROUP_FEMALE: pair.female_score_ciphertext}
                for group in GROUPS:
                    s = scores[group]
                    for stat in ("C", "A", "P", "TP", "N", "FP"):
                        accumulators[group][stat] = accumulators[group][stat] + s

        results.append(time_repeated(
            _aggregate_update, component="D_protected_group_processing", operation="aggregate_addition_update_12_per_record",
            batch_size=batch_size, n_repeats=n_repeats, n_warmup=2,
        ))

    return results


def run_audit_finalization_benchmarks(fla_context, lpu_context, ip, references) -> List[TimingResult]:
    """Fixed-cost operations (Component E): a small (50-record) encrypted
    audit result is built ONCE, untimed, then packet
    serialization/deserialization/decryption/DP/EO are each timed 30
    times against that SAME fixed-size aggregate object -- these do NOT
    scale with population size (one packet always holds exactly 12
    ciphertexts), so batching by record count does not apply here."""
    results: List[TimingResult] = []
    n_setup_records = 50
    records = []
    for i in range(n_setup_records):
        credential = ip.issue_credential(f"finaluid{i}", GROUP_MALE if i % 2 == 0 else GROUP_FEMALE)
        records.append(EncryptedTestRecord(row_index=i, credential=credential, y_pred=i % 2, y_true=(i % 3 == 0)))
    result = compute_encrypted_audit(records, ip.public_key, references, lpu_context, model_name="benchmark")
    packet = build_encrypted_aggregate_packet(result)

    results.append(time_repeated(lambda: build_encrypted_aggregate_packet(result), component="E_audit_finalization",
                                  operation="aggregate_packet_serialization", batch_size=1, n_repeats=30, n_warmup=3))

    def _deserialize_only():
        for group_bytes in (packet.male, packet.female):
            for field_bytes in (group_bytes.C, group_bytes.A, group_bytes.P, group_bytes.TP, group_bytes.N, group_bytes.FP):
                ts.ckks_vector_from(fla_context, field_bytes)

    results.append(time_repeated(_deserialize_only, component="E_audit_finalization",
                                  operation="fla_aggregate_deserialization_12_ciphertexts", batch_size=1, n_repeats=30, n_warmup=3))

    results.append(time_repeated(lambda: decrypt_audit_packet_for_diagnostics(packet, fla_context),
                                  component="E_audit_finalization", operation="aggregate_decryption_full_12_ciphertexts",
                                  batch_size=1, n_repeats=30, n_warmup=3))

    decrypted = decrypt_audit_packet_for_diagnostics(packet, fla_context)
    plaintext_result = PlaintextAuditResult(
        model_name="benchmark",
        groups={
            GROUP_MALE: GroupAuditCounts(group=GROUP_MALE, **decrypted.male.rounded()),
            GROUP_FEMALE: GroupAuditCounts(group=GROUP_FEMALE, **decrypted.female.rounded()),
        },
        full_test_n=decrypted.test_population_n,
        resolved_test_n=decrypted.resolved_test_n,
        unresolved_test_n=decrypted.unresolved_test_n,
    )
    results.append(time_repeated(lambda: compute_demographic_parity(plaintext_result), component="E_audit_finalization",
                                  operation="dp_calculation", batch_size=1, n_repeats=30, n_warmup=3))
    results.append(time_repeated(lambda: compute_equalised_odds(plaintext_result), component="E_audit_finalization",
                                  operation="eo_calculation", batch_size=1, n_repeats=30, n_warmup=3))
    return results, packet, result


def measure_serialization(fla_context, lpu_context, ip, bank, ca, references_bytes, references, packet) -> List[dict]:
    """Phase 11 Sec. 9: ACTUAL serialized-object byte measurements only --
    every row here is ``len(...)`` on real bytes the implementation
    produced. No analytical inference anywhere in this function."""
    rows: List[dict] = []

    def _add(object_name: str, description: str, measured_bytes: int, method: str) -> None:
        rows.append({"object": object_name, "description": description, "measured_bytes": measured_bytes, "measurement_method": method})

    # CKKS context/material -- public/evaluation context and its
    # sub-components in isolation via TenSEAL's own serialize() flags.
    _add("lpu_public_evaluation_context", "LPU's full public context (public key + Galois + relin keys, no secret key)",
         len(lpu_context.serialize(save_public_key=True, save_secret_key=False, save_galois_keys=True, save_relin_keys=True)),
         "ts.Context.serialize(save_secret_key=False, save_galois_keys=True, save_relin_keys=True)")
    _add("public_key_material_only", "Public key material in isolation (no Galois/relin keys)",
         len(lpu_context.serialize(save_public_key=True, save_secret_key=False, save_galois_keys=False, save_relin_keys=False)),
         "ts.Context.serialize(save_galois_keys=False, save_relin_keys=False)")
    _add("galois_evaluation_material_delta", "Galois (rotation) key material, isolated as a size delta",
         len(lpu_context.serialize(save_public_key=True, save_secret_key=False, save_galois_keys=True, save_relin_keys=False))
         - len(lpu_context.serialize(save_public_key=True, save_secret_key=False, save_galois_keys=False, save_relin_keys=False)),
         "delta of ts.Context.serialize() with/without save_galois_keys")
    _add("relinearization_material_delta", "Relinearization key material, isolated as a size delta",
         len(lpu_context.serialize(save_public_key=True, save_secret_key=False, save_galois_keys=False, save_relin_keys=True))
         - len(lpu_context.serialize(save_public_key=True, save_secret_key=False, save_galois_keys=False, save_relin_keys=False)),
         "delta of ts.Context.serialize() with/without save_relin_keys")

    # Private context: length ONLY, bytes never persisted (Phase 11 Sec. 10).
    private_len = _measure_len_only(lambda: fla_context.serialize(save_public_key=True, save_secret_key=True, save_galois_keys=True, save_relin_keys=True))
    _add("fla_private_context_LENGTH_ONLY", "FLA private context -- LENGTH ONLY, secret bytes discarded immediately, never written",
         private_len, "len() computed transiently; actual bytes never stored (contains sk_HE)")

    # Protocol objects.
    male_ref_bytes, female_ref_bytes = references_bytes.male_reference_bytes, references_bytes.female_reference_bytes
    _add("male_reference_vector", "HE.r_m, generated once by the FLA", len(male_ref_bytes), "EncryptedReferenceVectors.male_reference_bytes")
    _add("female_reference_vector", "HE.r_f, generated once by the FLA", len(female_ref_bytes), "EncryptedReferenceVectors.female_reference_bytes")

    one_scalar_bytes = ts.ckks_vector(lpu_context, [1.0]).serialize()
    _add("one_encrypted_scalar", "A single fresh CKKS-encrypted scalar (size-1 vector)", len(one_scalar_bytes), "ts.CKKSVector.serialize()")

    sample_credential = ip.issue_credential("serialization-sample", GROUP_MALE)
    _add("encrypted_protected_attribute_pair", "HE.g_i -- the credential's own ciphertext bytes (one-hot, size-2 vector)",
         len(sample_credential.ciphertext_bytes), "ProtectedAttributeCredential.ciphertext_bytes")

    similarity_pair = comp_sim(sample_credential, ip.public_key, references, lpu_context)
    serialized_pair = similarity_pair.serialize()
    _add("encrypted_similarity_pair", "One EncryptedSimilarityPair (male+female compSim scores), serialized",
         len(serialized_pair.male_score_bytes) + len(serialized_pair.female_score_bytes), "SerializedSimilarityPair field bytes summed")

    bank_credential = bank.issue_account_credential("serialization-sample", "ACCT-000001")
    ca_credential = ca.issue_score_credential("serialization-sample", 700)
    _add("bank_account_credential", "AccountCredential, canonical-JSON wire encoding",
         len(canonical_encode(asdict(bank_credential))), "canonical_encode(dataclasses.asdict(AccountCredential))")
    _add("ca_score_credential", "ScoreCredential, canonical-JSON wire encoding",
         len(canonical_encode(asdict(ca_credential))), "canonical_encode(dataclasses.asdict(ScoreCredential))")
    _add("ip_protected_attribute_credential", "ProtectedAttributeCredential, canonical-JSON wire encoding",
         len(canonical_encode(asdict(sample_credential))), "canonical_encode(dataclasses.asdict(ProtectedAttributeCredential))")

    _add("one_serialized_group_audit_counts", "SerializedGroupAuditCounts (one group's 6 aggregate ciphertexts)",
         sum(len(getattr(packet.male, stat)) for stat in ("C", "A", "P", "TP", "N", "FP")),
         "sum of len() over the 6 stat ciphertext byte-strings for one group")
    _add("complete_encrypted_audit_packet", "Complete EncryptedAuditPacket (both groups, all 12 ciphertexts + metadata)",
         len(canonical_encode(asdict(packet))), "canonical_encode(dataclasses.asdict(EncryptedAuditPacket))")

    return rows


def build_analytical_estimates(ckks_config: CKKSConfig, measured_rows: List[dict]) -> List[dict]:
    """Phase 11 Sec. 11: analytical estimates computed PURELY from CKKS
    parameters, then compared (percentage difference) against the
    corresponding ACTUAL measured row above -- never forced to agree."""
    measured_by_name = {row["object"]: row["measured_bytes"] for row in measured_rows}
    full_chain = tuple(ckks_config.coeff_mod_bit_sizes)
    # A ciphertext that has gone through exactly one CKKS multiplication +
    # automatic rescale (compSim's output) has consumed one modulus from
    # the chain -- approximated here by dropping the smallest active
    # modulus, an approximation (see this module's docstring caveat), not
    # an exact statement about which specific prime SEAL drops.
    one_level_down_chain = tuple(sorted(full_chain)[1:]) if len(full_chain) > 1 else full_chain

    rows = []

    def _add(object_name: str, estimate, measured_key: Optional[str]) -> None:
        measured = measured_by_name.get(measured_key) if measured_key else None
        rows.append({
            "object": object_name,
            "poly_modulus_degree": estimate.poly_modulus_degree,
            "active_moduli_bit_sizes": list(estimate.active_moduli_bit_sizes),
            "num_polys": estimate.num_polys,
            "bytes_per_coefficient": estimate.bytes_per_coefficient,
            "analytical_estimate_bytes": estimate.analytical_estimate_bytes,
            "corresponding_measured_object": measured_key,
            "actual_measured_bytes": measured,
            "percentage_difference": percentage_difference(measured, estimate.analytical_estimate_bytes) if measured is not None else None,
        })

    _add("fresh_ciphertext_full_chain", analytical_ciphertext_bytes(ckks_config.poly_modulus_degree, full_chain, num_polys=2),
         "one_encrypted_scalar")
    _add("post_compsim_ciphertext_one_level_down", analytical_ciphertext_bytes(ckks_config.poly_modulus_degree, one_level_down_chain, num_polys=2),
         None)
    return rows


def build_communication_tables(measured_rows: List[dict]) -> List[dict]:
    """Phase 11 Sec. 12-14: a communication-cost table for the
    manuscript's protocol flows, with one-time/per-application/per-audit
    categories kept separate, plus derived (never network-measured)
    projections at several n."""
    measured_by_name = {row["object"]: row["measured_bytes"] for row in measured_rows}

    entries = [
        CommunicationPathEntry("IP -> Borrower", "encrypted_protected_attribute_pair (as part of the IP credential)",
                                measured_by_name["ip_protected_attribute_credential"], PER_APPLICATION,
                                "Full ProtectedAttributeCredential, canonical-JSON wire encoding."),
        CommunicationPathEntry("Borrower -> LPU", "bank_account_credential",
                                measured_by_name["bank_account_credential"], PER_APPLICATION, ""),
        CommunicationPathEntry("Borrower -> LPU", "ca_score_credential",
                                measured_by_name["ca_score_credential"], PER_APPLICATION, ""),
        CommunicationPathEntry("Borrower -> LPU", "ip_protected_attribute_credential",
                                measured_by_name["ip_protected_attribute_credential"], PER_APPLICATION, ""),
        CommunicationPathEntry("LPU -> FLA", "complete_encrypted_audit_packet",
                                measured_by_name["complete_encrypted_audit_packet"], PER_AUDIT_BATCH,
                                "ONE packet per audit run, regardless of population size."),
        CommunicationPathEntry("FLA -> LPU (setup)", "lpu_public_evaluation_context",
                                measured_by_name["lpu_public_evaluation_context"], ONE_TIME, ""),
        CommunicationPathEntry("FLA -> LPU (setup)", "male_reference_vector",
                                measured_by_name["male_reference_vector"], ONE_TIME, ""),
        CommunicationPathEntry("FLA -> LPU (setup)", "female_reference_vector",
                                measured_by_name["female_reference_vector"], ONE_TIME, ""),
    ]

    rows = [{"row_type": "communication_path", "path": e.path, "object": e.object_name,
             "measured_bytes": e.measured_bytes, "category": e.category, "notes": e.notes} for e in entries]

    totals = total_bytes_by_category(entries)
    fixed_setup_bytes = totals[ONE_TIME]
    per_application_bytes = totals[PER_APPLICATION]
    audit_packet_bytes = totals[PER_AUDIT_BATCH]

    for n in (1, 100, 1000, 10000, 100000):
        projected = project_total_communication_bytes(
            fixed_setup_bytes=fixed_setup_bytes, per_application_bytes=per_application_bytes,
            audit_packet_bytes=audit_packet_bytes, n_applications=n,
        )
        rows.append({
            "row_type": "projection", "path": f"n={n} applications (DERIVED PROJECTION, not a network measurement)",
            "object": "fixed_setup + n*per_application + one_audit_packet", "measured_bytes": projected,
            "category": "derived_projection", "notes": f"fixed_setup_bytes={fixed_setup_bytes}, per_application_bytes={per_application_bytes}, audit_packet_bytes={audit_packet_bytes}, n={n}",
        })
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "results" / "benchmarks"))
    parser.add_argument("--metadata-output", default=str(REPO_ROOT / "results" / "metadata" / "benchmark_environment.json"))
    return parser.parse_args()


def _write_csv(rows: List[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    ckks_config = CKKSConfig()

    fla_context = build_fla_context(ckks_config)
    lpu_context = derive_lpu_context(fla_context)
    assert not context_can_decrypt(lpu_context)
    bank = Bank()
    ca = CreditAgency()
    ip = IdentityProvider(lpu_context)
    lpu = LoanProcessingUnit(lpu_context, bank_public_key=bank.public_key, ca_public_key=ca.public_key, ip_public_key=ip.public_key)
    references_bytes = generate_encrypted_references(fla_context)
    references = load_reference_vectors(references_bytes, lpu_context)

    print("Running timing benchmarks (Components A-D)...")
    start = time.perf_counter()
    timing_results = run_timing_benchmarks(fla_context, lpu_context, ip, bank, ca, lpu, references)
    print("Running audit-finalization benchmarks (Component E)...")
    finalization_results, packet, _ = run_audit_finalization_benchmarks(fla_context, lpu_context, ip, references)
    timing_results.extend(finalization_results)
    total_benchmark_seconds = time.perf_counter() - start
    print(f"All timing benchmarks completed in {total_benchmark_seconds:.1f}s.")

    # --- runtime_raw.csv / runtime_summary.csv ---
    raw_rows = []
    for result in timing_results:
        for i, ns in enumerate(result.raw_ns):
            raw_rows.append({
                "component": result.component, "operation": result.operation, "batch_size": result.batch_size,
                "repeat_index": i, "duration_ns": ns,
            })
    _write_csv(raw_rows, output_dir / "runtime_raw.csv")
    summary_rows = [_timing_row(r) for r in timing_results]
    _write_csv(summary_rows, output_dir / "runtime_summary.csv")
    print(f"Wrote {len(raw_rows)} raw observations, {len(summary_rows)} summary rows.")

    # --- serialization_measured.csv / serialization_analytical.csv ---
    print("Measuring actual serialized-object sizes...")
    serialization_rows = measure_serialization(fla_context, lpu_context, ip, bank, ca, references_bytes, references, packet)
    _write_csv(serialization_rows, output_dir / "serialization_measured.csv")

    analytical_rows = build_analytical_estimates(ckks_config, serialization_rows)
    _write_csv(analytical_rows, output_dir / "serialization_analytical.csv")

    # --- communication_summary.csv ---
    communication_rows = build_communication_tables(serialization_rows)
    _write_csv(communication_rows, output_dir / "communication_summary.csv")

    # --- benchmark_environment.json ---
    env = collect_environment_metadata(_ckks_config_dict(ckks_config))
    env["full_scale_application_runs_observed_previously"] = FULL_SCALE_APPLICATION_RUNS
    env["total_benchmark_wallclock_seconds"] = total_benchmark_seconds
    metadata_path = Path(args.metadata_output)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    with open(metadata_path, "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=2, sort_keys=True, default=str)
    print(f"Wrote {metadata_path}")

    print(f"\nDone. Total wall-clock for this benchmark run: {total_benchmark_seconds:.1f}s.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
