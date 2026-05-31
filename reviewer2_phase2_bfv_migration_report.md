# Phase 2: CKKS → BFV Migration of the Active Aggregation Path

Scope: Reviewer #2 point 2 (CKKS approximate arithmetic / IND-CPA vs. IND-CPA^D) only, targeting the active protocol's aggregation path (established in Phase 1 to be pure integer addition). No manuscript edits. No NIZKP work. No 9-configuration real-data experiment. No historical artifact overwritten. No decision-model or fairness-definition change. No privacy/security test weakened.

**Provenance flag**: all new artifacts in this report were produced at git commit `54379d9` (Phase 1's commit) with `git_dirty=true` (Phase 2's own changes were still uncommitted at measurement time). Per this report's own item 17 standard, **these numbers are PROVISIONAL** until re-measured from a clean, tagged commit — see §"Readiness for Phase 3" for the recommended re-run.

---

## Executive conclusion

- **BFV migration succeeded.** A complete, working BFV implementation (`fairlend.crypto.bfv`, `fairlend.secure_compute.bfv`, `IdentityProviderBFV`, and a BFV-backed `compute_encrypted_audit`/`EncryptedAuditPacket` in `fairlend.audit.aggregation`) is now the ACTIVE protocol, exercised end-to-end by `evaluation/run_encrypted_audit.py` and `evaluation/run_fairness_reconstruction.py`.
- **All aggregate counts are exact.** Verified on 24 (model × group × statistic) combinations on the fixture differential check (`results/fixture_validation/evaluation/ckks_vs_bfv_equivalence.csv`): `bfv_minus_plaintext == 0` for every row, with zero tolerance — the comparison script asserts this and would abort otherwise. 32 new unit-level exactness/structural tests (`tests/scientific/test_encrypted_aggregation_bfv.py`) confirm this further, including at batch sizes 1/2/10/25/100 and at the parameterisation's safety boundary.
- **Fairness outputs remain identical.** DP/EO for both LR and RF agree exactly across plaintext, CKKS-direct, and BFV-direct (see §"Fairness equivalence").
- **Privacy/key-separation tests remain valid and were extended, not weakened.** Full suite: **543 passed, 2 skipped, 0 failed** (up from the Phase 1 baseline of 511 passed — the +32 is exactly the new BFV test file; no other test count changed, and the same 2 pre-existing tests remain skipped for the same gitignored-data reason as before).
- **CKKS is no longer necessary anywhere in the ACTIVE protocol's aggregation path.** It remains necessary only for `fairlend.audit.matching`'s matching-fidelity evaluation (a separate, unrelated concern that still uses `comp_sim`) and for the legacy compSim path (retained for historical reproducibility). The active audit-aggregation pipeline (`compute_encrypted_audit` → `build_encrypted_aggregate_packet` → `decrypt_audit_packet_for_diagnostics`) uses BFV exclusively.

---

## Architecture comparison

| Property | Legacy CKKS+compSim | CKKS direct | BFV direct (ACTIVE) |
|---|---:|---:|---:|
| Protected vector ciphertexts (per record) | 1 (2-slot) | 1 (2-slot) | 1 (2-slot) |
| Encrypted reference vectors | 2 (`HE.r_m`, `HE.r_f`) | 0 | 0 |
| Aggregate ciphertexts (per audit packet) | 12 (6 stats × 2 groups, 1-slot each) | 6 (6 stats, 2-slot each) | 6 (6 stats, 2-slot each) |
| Ciphertext-ciphertext multiplications (per record) | 2 | 0 | 0 |
| Additions (per record, up to) | 12 (2 groups × 6 stats, conditional) | 6 (6 stats, conditional) | 6 (6 stats, conditional) |
| Multiplicative depth | 1 | 0 | 0 |
| Relinearisation | Yes (automatic, after each multiplication) | No | No (never generated for transmission; see below) |
| Rescaling | Yes (automatic, after each multiplication) | No | N/A — BFV has no rescale operation |
| Approximate arithmetic | Yes (CKKS) | Yes (CKKS) | **No** — BFV is exact |
| Rounding after decryption | Yes (to recover integer counts from float) | Yes | **No** — decryption returns the exact integer directly (verified: `_decrypt_stat_pair_bfv` asserts the raw decrypted value already equals its own `int()` cast) |
| Exact integer output | No (approximated, then rounded) | No (approximated, then rounded) | **Yes** |
| Galois/rotation keys needed | Yes (for `comp_sim`'s `.dot()`/`.sum()`) | No | No |
| Galois/rotation keys transmitted to LPU | Yes | No (never generated) | No (structurally stripped — see below) |
| Relin keys transmitted to LPU | Yes (auto-generated, always present) | Yes (auto-generated, always present, unused) | **No** — round-tripped through `serialize(save_relin_keys=False)` so the derived LPU context's own `has_relin_keys()` is `False`, not merely "present but unused" |

---

## BFV parameters

Derived from the actual FairLend workload (`src/fairlend/core/config.py::BFVConfig`), not copied from an unrelated example:

| Parameter | Value | Justification |
|---|---|---|
| `poly_modulus_degree` | 8192 | Matches the CKKS configuration's ring dimension exactly, so the CKKS-vs-BFV comparison varies only the scheme, not the ring dimension. This codebase never needs more than 2 SIMD slots, so 8192 is not a batching-capacity requirement — it is a comparability choice. |
| `plain_modulus` | 33,832,961 | The smallest prime ≥ 2²⁵ that is ALSO ≡ 1 (mod 16384 = 2×poly_modulus_degree) — i.e. the smallest batching-compatible ("NTT-friendly") prime at or above a 2²⁵ safety target. TenSEAL's `bfv_vector` raises `ValueError: encryption parameters are not valid for batching` for any non-compatible modulus — **verified empirically**, not assumed (a first attempt with an arbitrary large prime failed exactly this way). |
| `coeff_mod_bit_sizes` | `[]` (SEAL default) | Deliberately left unset so SEAL selects its own default coefficient-modulus chain for this `poly_modulus_degree`, which targets SEAL's documented default 128-bit security level (`sec_level_type::tc128`). This codebase does not hand-pick a coefficient modulus for BFV specifically so it never accidentally weakens (or gratuitously strengthens, at a size/performance cost) that default. |
| `max_safe_count` | 16,916,480 = (33,832,961 − 1) // 2 | **Not** `plain_modulus − 1`. See "signed decoding" below. |
| Slot count | 2 (male, female) | Matches Phase 1's packed representation exactly. |

**Security level**: could not be independently introspected via the installed TenSEAL 0.3.17 Python API — no accessor exposes SEAL's `EncryptionParameters`/`SEALContext` internals (`ctx.data.seal_context` returns an opaque `PyCapsule`-backed method with no attributes). This is a genuine, verified **limitation of this API build**, documented rather than papered over. The 128-bit security claim rests on SEAL's own well-documented default behaviour when `coeff_mod_bit_sizes` is left empty, which is precisely why this codebase relies on that default instead of hand-selecting a modulus it cannot independently verify.

**CRITICAL, empirically-verified correctness finding — BFV plaintext decoding is SIGNED, not unsigned.** A naive first attempt assumed the safe range was `[0, plain_modulus − 1]`. Direct testing disproved this:

```
>>> ts.bfv_vector(ctx, [33832960, 33832960]).decrypt()   # plain_modulus - 1
[-1, -1]                                                  # NOT 33832960 -- wraps to -1
```

TenSEAL/SEAL's BFV decoding returns a value in `[0, (p−1)//2]` as itself, and any value in `[(p−1)//2 + 1, p−1]` as its negative residue (`v − p`). The actual safe range for a non-negative count is therefore `[0, (plain_modulus−1)//2] = [0, 16,916,480]`, roughly **half** of what an unsigned assumption would have claimed. This is documented in `BFVConfig.max_safe_count`'s docstring and directly verified by `tests/scientific/test_encrypted_aggregation_bfv.py::test_count_at_exactly_the_safety_bound_decrypts_as_itself`, which also confirms the next value up wraps negative. 16,916,480 is ~19× the largest population this codebase has ever processed (887,440, the full cleaned LendingClub audit-eligible population) and ~7.5× the raw unfiltered dataset row count (2,260,701).

**Relinearisation/Galois keys are unnecessary and are not transmitted.** SEAL auto-generates relin keys at BFV context construction (unlike CKKS, where only Galois-key generation is explicit) — there is no constructor flag to suppress this. Since the addition-only path never multiplies, these keys are never used; `derive_lpu_context` therefore round-trips the context through `serialize(save_relin_keys=False, save_galois_keys=False)` before returning it, producing an LPU context whose **own** `has_relin_keys()`/`has_galois_keys()` are both `False` — a structural guarantee, not merely an unused-but-present capability. Measured effect: the LPU-facing public context shrinks from 2,708,752 B (default flags) to 541,772–542,011 B (stripped) — a **5×** reduction.

---

## Exactness validation

`results/fixture_validation/evaluation/ckks_vs_bfv_equivalence.csv` (24 rows: 2 models × 2 groups × 6 statistics), sample:

| model | group | stat | plaintext | ckks_raw | ckks_rounded | bfv_exact | bfv−plaintext |
|---|---|---|---|---|---|---|---|
| logistic_regression | male | C | 19 | 18.999999987593 | 19 | 19.0 | **0.0** |
| logistic_regression | male | A | 14 | 13.999999990670648 | 14 | 14.0 | **0.0** |
| logistic_regression | female | FP | 5 | 4.99999999876015 | 5 | 5.0 | **0.0** |
| random_forest | male | C | 19 | 19.000000010436516 | 19 | 19.0 | **0.0** |

All 24 rows: `bfv_minus_plaintext == 0` exactly (script-enforced assertion, not a post-hoc observation). CKKS's raw error is consistently on the order of 1e-8–1e-11; BFV's is exactly zero at every decimal place, because BFV has none to be wrong in.

`tests/scientific/test_encrypted_aggregation_bfv.py` (32 tests, all passing) additionally covers, with exact (`==`, never `pytest.approx`) equality throughout: all-male/all-female/mixed batches, one-group-entirely-absent, approval-conditioned counts, P/N counts, TP/FP counts, LR and RF paths (independently recomputed against a plaintext oracle), batch sizes {1, 2, 10, 25, 100}, the full-known-LendingClub-scale population (887,440) confirmed within the safe bound, the exact safety-bound value and one-past-bound wraparound, and the overflow guard rejecting an oversized population before any encryption occurs.

---

## Fairness equivalence

`results/fixture_validation/evaluation/ckks_vs_bfv_equivalence_summary.json`:

| model | DP_plain | DP_ckks_direct | DP_bfv_direct | EO_plain | EO_ckks_direct | EO_bfv_direct |
|---|---|---|---|---|---|---|
| logistic_regression | 0.10526315789473684 | 0.10526315789473684 | 0.10526315789473684 | 0.25 | 0.25 | 0.25 |
| random_forest | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

Both models, both metrics, all three paths agree exactly — the HE-scheme migration changes the cryptographic representation but not the fairness result, exactly as intended and as Phase 1 already established for CKKS-direct vs. legacy.

---

## Privacy/security regression results

Explicitly re-verified for the BFV path (all in `tests/scientific/test_encrypted_aggregation_bfv.py` unless noted):

- **IP sees plaintext, issues encrypted credential**: `IdentityProviderBFV.issue_credential` — unchanged contract from `IdentityProvider`, only the encryption primitive differs (`ts.bfv_vector` on integer one-hot slots vs. `ts.ckks_vector` on float slots).
- **LPU receives only encrypted protected attribute; has no BFV secret key**: `test_lpu_context_never_holds_bfv_secret_key_during_aggregation`, `test_compute_encrypted_audit_rejects_private_context`.
- **LPU cannot decrypt per-record protected attributes; no per-record decryption occurs**: `test_active_path_never_decrypts_on_lpu_side` (monkeypatch-enforced: `ts.BFVVector.decrypt` raises if ever called during aggregation/packet-building).
- **FLA alone receives the authorised decryption capability; decrypts aggregate ciphertexts only**: `test_diagnostic_decrypt_requires_private_context`; the packet contains six aggregate ciphertexts and no per-record field (`test_packet_has_six_ciphertext_fields_not_twelve`, `test_no_forbidden_substring_in_packet_field_names`).
- **Packet fields do not reveal plaintext gender**: same field-enumeration proof as the CKKS-direct/legacy packets, applied to `EncryptedAuditPacket`'s new (BFV-backed) shape.
- **Decision models never receive protected attribute**: unaffected, untouched (`fairlend.models.credit_models`, `tests/scientific/test_gender_exclusion.py` still passing unmodified).
- **No debug/logging path exposes the protected attribute**: no `print`/`logging` added anywhere in `aggregation.py`, `bfv.py`, or `identity_provider.py`'s new `IdentityProviderBFV` class.
- **No multiplication, no relinearisation capability transmitted**: `test_active_path_performs_no_ciphertext_ciphertext_multiplication` (monkeypatch-enforced on `ts.BFVVector.__mul__`/`.dot`), `test_lpu_context_requires_no_relin_or_galois_keys` (structural: asserts `has_relin_keys() is False` and `has_galois_keys() is False` on the actual LPU context object, not merely "unused").
- **Overflow cannot silently wrap**: `test_overflow_guard_rejects_population_above_safe_bound`, `test_compute_encrypted_audit_enforces_overflow_guard_before_any_encryption` (proves the guard fires before any per-record homomorphic work, via a monkeypatch that would fail the test if reached).

No existing test was weakened, relaxed, or had its expected value silently changed. Every CKKS-specific test (legacy and Phase 1 baseline) continues to test exactly what it always tested, under its own explicit `_legacy_compsim`/`_ckks_direct` names, unchanged.

**Full suite**: **543 passed, 2 skipped, 0 failed** (274.47s), vs. the Phase 1 baseline of 511 passed, 2 skipped. The +32 is exactly `tests/scientific/test_encrypted_aggregation_bfv.py`; no other test count changed; the same 2 tests remain skipped for the same reason (gitignored `data/processed/fixture_validation` intermediate absent in this checkout). No failed-test classification is needed — nothing failed.

---

## Runtime comparison

`results/benchmarks/ckks_vs_bfv_runtime_summary.csv` (mean ± std over n repeats; hardware: Intel i7-10610U, 8 logical/4 physical cores, WSL2/Linux, Python 3.13.5, TenSEAL 0.3.17 — full environment in `results/metadata/ckks_vs_bfv_benchmark_environment.json`):

| Component | Operation | Mean | Std | n |
|---|---|---:|---:|---:|
| Context setup | CKKS FLA context build | 275.5 ms | 35.1 ms | 10 |
| Context setup | **BFV** FLA context build | **66.4 ms** | 4.7 ms | 10 |
| Context setup | CKKS LPU context derive | 316.1 ms | 28.8 ms | 10 |
| Context setup | **BFV** LPU context derive | **109.0 ms** | 8.2 ms | 10 |
| Credential issuance | CKKS protected-attribute credential | 10.03 ms | 0.88 ms | 30 |
| Credential issuance | **BFV** protected-attribute credential | **7.92 ms** | 0.31 ms | 30 |
| Aggregation (batch=1) | CKKS direct | 39.58 ms | 1.57 ms | 10 |
| Aggregation (batch=1) | BFV | 37.49 ms | 3.13 ms | 10 |
| Aggregation (batch=100) | CKKS direct | 366.7 ms | 37.6 ms | 10 |
| Aggregation (batch=100) | BFV | 520.7 ms | 187.6 ms | 10 |
| Aggregation (batch=1000) | CKKS direct | 2834.9 ms | 781.5 ms | 3 |
| Aggregation (batch=1000) | BFV | 3231.5 ms | 210.8 ms | 3 |
| Audit decryption (1 packet) | CKKS direct | 18.51 ms | 3.01 ms | 20 |
| Audit decryption (1 packet) | BFV | 24.22 ms | 5.70 ms | 20 |
| Total audit, N=100 | CKKS direct | 715.9 ms | 348.2 ms | 5 |
| Total audit, N=100 | BFV | 497.5 ms | 89.0 ms | 5 |

**Honest reading, not a forced narrative**: context/key setup and credential issuance are consistently faster for BFV (both context-build operations are 2.9–4.1× faster; credential issuance ~21% faster). Per-record aggregation and decryption show no consistent winner at this measurement precision — BFV is marginally faster at batch=1, slower at batch=100/1000 for the mean, but the std at batch=1000 (781.5 ms for CKKS on only 3 repeats) is large enough relative to the batch means to make that particular comparison unreliable; the N=100 *total audit* figure favours BFV. This environment (WSL2, shared machine, "low" but nonzero competing load per the recorded load average) is not a clean-room benchmarking environment; a definitive per-record aggregation-speed verdict would need more repeats on quieter hardware, which this report does not claim to provide. No number here is fabricated or smoothed — the full raw observations are in `results/benchmarks/ckks_vs_bfv_runtime_raw.csv` (242 rows) for independent reanalysis.

---

## Serialization comparison

`results/benchmarks/serialization_ckks_direct_vs_bfv.csv` (all MEASURED, `len()` on real serialized objects — no analytical estimates in this table):

| Object | CKKS-direct bytes | BFV bytes | Δ bytes | Δ % |
|---|---:|---:|---:|---:|
| Protected-attribute ciphertext (credential) | 331,567 | 432,458 | +100,891 | **+30.4%** |
| **LPU-facing public context** | 35,289,669 | **542,011** | **−34,747,658** | **−98.5%** |
| FLA private context (length only) | 697,395 | 812,853 | +115,458 | +16.6% |
| Complete six-ciphertext audit packet | 1,989,886 | 2,594,751 | +604,865 | +30.4% |

`results/benchmarks/serialization_bfv_measured.csv` has the BFV-only figures in isolation.

**Interpretation, both directions reported honestly**: BFV's per-ciphertext objects (credential, audit packet) are **~30% larger** than CKKS-direct's at this codebase's chosen parameters — a real, measured cost of BFV's exact-integer coefficient encoding relative to CKKS's parameter set here. But the **LPU-facing public context is 98.5% smaller** (35.3 MB → 542 KB), because CKKS's LPU context must carry Galois key material (needed for `comp_sim`'s rotations, which the direct-addition paths never use in the first place, but which CKKS's context object still happened to include by default in this codebase's Phase 1 setup) while BFV's LPU context carries neither Galois nor relin keys at all. This is the single largest, least ambiguous win in this comparison and directly validates the "do not generate unnecessary keys" design choice (§"BFV parameters" above).

---

## Security-model implications

*(Wording recommendations for a later manuscript phase — Theorem 1 itself is not rewritten here, per this phase's constraints.)*

**A. Ciphertext confidentiality against the LPU.** Unaffected by the scheme choice: the LPU never holds the secret key in either CKKS or BFV (structurally enforced and tested in both). This claim only ever needed ordinary IND-CPA security (computational indistinguishability of ciphertexts to a non-decrypting adversary), which both CKKS and BFV provide under RLWE at appropriate parameters. **This part of Theorem 1's hypothesis can be restated for BFV with no loss of rigor** — it is not weaker or stronger, just a different scheme satisfying the same notion.

**B. Intentional aggregate disclosure to the FLA.** Identical in both schemes and **unaffected by this migration**: the FLA deliberately decrypts six aggregate ciphertexts (C, A, P, TP, N, FP) every audit — this is the protocol's designed output, not a side channel. BFV does not hide this disclosure, does not reduce it, and must not be described as protecting against it (per this report's own constraint). The existing leakage-profile and collusion discussion elsewhere in the security analysis already treats this correctly and needs no change on account of the scheme migration.

**C. The approximate-decryption issue associated with CKKS (Li and Micciancio, EUROCRYPT 2021).** This result concerns CKKS specifically: because CKKS decryption returns an *approximate* plaintext, an adversary who can observe many decryptions of related ciphertexts (exactly FairLend's aggregate-disclosure setting — the FLA repeatedly decrypts aggregate ciphertexts across audits) can, without noise flooding ("smudging"), sometimes extract information about the secret key or the true plaintext from the pattern of approximation errors — a strictly stronger adversarial capability than plain IND-CPA anticipates, formalised as IND-CPA^D (security under a decryption oracle). Reviewer #2's original criticism was that Theorem 1 invoked plain IND-CPA in exactly this decryption-exposed setting, where the applicable notion for CKKS is IND-CPA^D.

**D. Whether this CKKS-specific issue remains relevant to the ACTIVE BFV path: No.** BFV is an exact scheme — decryption is a deterministic function of ciphertext and secret key returning the precise integer plaintext, with no residual "leftover noise" reported as part of the answer the way CKKS's rounding does (verified directly in this phase: `_decrypt_stat_pair_bfv` asserts the raw decrypted value already equals its own integer cast, and this assertion has held on every measured run). The Li–Micciancio attack is specifically a consequence of CKKS's approximate output; it has no BFV analogue, because there is no approximation for repeated decryptions to leak information through. **Because the active path no longer uses CKKS at all, the IND-CPA^D discussion Theorem 1 currently needs can be dropped for the active protocol** — ordinary IND-CPA is now sufficient for the whole active pipeline, not just the LPU-confidentiality half of it.

**What must NOT be claimed**: BFV does not make the aggregate disclosure itself more private, does not reduce what the FLA learns, and does not address LPU–FLA collusion, small-group re-identification, or proxy-attribute inference from operational data — all of which are orthogonal to the HE scheme and remain exactly as documented elsewhere in the manuscript's security analysis. The only thing this migration removes is an *unnecessary additional attack surface* (CKKS's approximate-decryption side channel) that existed **alongside** the intentional aggregate-disclosure design, not a substitute for addressing that design's own residual risks.

**Recommended wording changes for the later manuscript phase** (not applied here):
1. Theorem 1's hypothesis: replace "the CKKS encryption scheme is IND-CPA secure" with "the BFV encryption scheme is IND-CPA secure under the underlying Ring-LWE assumption" (or state it scheme-agnostically, since the proof no longer depends on CKKS-specific behaviour).
2. Remove or substantially shorten any surrounding discussion of approximate-arithmetic/rounding-tolerance, since BFV decryption requires none.
3. Add one sentence near Theorem 1 or in the leakage-profile section along the lines of: "Because BFV decryption is exact, the FLA's released aggregate statistics carry no additional information beyond the intended disclosed counts; this contrasts with a CKKS-based instantiation, where repeated approximate decryption of related ciphertexts admits IND-CPA^D-style attacks (Li and Micciancio, EUROCRYPT 2021) absent noise flooding."
4. Retain, unchanged, every existing statement about the aggregate disclosure itself being intentional and about residual risks (collusion, small-group re-identification, proxy inference) — none of those change with the scheme.

---

## Code changes

| File | Function/class | Change | Rationale |
|---|---|---|---|
| `src/fairlend/core/config.py` | new `BFVConfig` | Added: `poly_modulus_degree=8192`, `plain_modulus=33832961`, `coeff_mod_bit_sizes=[]`, `max_safe_count` property. | Derived, documented BFV parameterisation (see "BFV parameters" above). |
| `src/fairlend/core/exceptions.py` | new `BFVOverflowError` | Added. | Explicit, typed failure for the overflow guard (task item 14). |
| `src/fairlend/crypto/bfv.py` | new module: `build_fla_context`, `derive_lpu_context`, `context_can_decrypt` | Added — mirrors `fairlend.crypto.ckks`'s API exactly. `derive_lpu_context` round-trips through serialize/deserialize with relin/galois keys stripped (unlike CKKS's copy-and-strip, which retains Galois keys because `comp_sim` needs them). | Clean, explicit BFV abstraction (task item 5); structural "no relin/galois capability" guarantee (task item 7). |
| `src/fairlend/secure_compute/bfv.py` | new module | Added — facade re-export, mirrors `secure_compute/ckks.py`. | Consistent public API surface. |
| `src/fairlend/roles/identity_provider.py` | new `IdentityProviderBFV`, `MALE_ONE_HOT_INT`/`FEMALE_ONE_HOT_INT` | Added, alongside unchanged `IdentityProvider` (CKKS). | Explicit, separately-named class so it is never ambiguous which scheme issued a credential (task item 5's "avoid aliasing"). |
| `src/fairlend/audit/aggregation.py` | `EncryptedAuditCounts`→`CKKSDirectAuditCounts`, `EncryptedAuditResult`→`CKKSDirectAuditResult`, `compute_encrypted_audit`→`compute_encrypted_audit_ckks_direct`, `SerializedEncryptedAuditCounts`→`SerializedCKKSDirectAuditCounts`, `EncryptedAuditPacket`→`CKKSDirectAuditPacket`, `build_encrypted_aggregate_packet`→`_ckks_direct`, `decrypt_audit_packet_for_diagnostics`→`_ckks_direct`, `_decrypt_stat_pair`→`_decrypt_stat_pair_ckks` | **Renamed** (Phase 1's canonical names), body unchanged. | Frees the canonical names for BFV as the new ACTIVE path, exactly mirroring how Phase 1 renamed the legacy compSim path. |
| `src/fairlend/audit/aggregation.py` | new `BFVAuditCounts`, `BFVAuditResult`, `assert_population_within_bfv_safe_bound`, `_load_verified_protected_attribute_vector_bfv`, `compute_encrypted_audit` (canonical, BFV), `SerializedBFVAuditCounts`, `EncryptedAuditPacket` (canonical, BFV), `build_encrypted_aggregate_packet` (canonical), `_decrypt_stat_pair_bfv`, `decrypt_audit_packet_for_diagnostics` (canonical) | Added. `EncryptedAuditCounts`/`EncryptedAuditResult` are plain aliases of `BFVAuditCounts`/`BFVAuditResult`. Overflow guard runs before any per-record work. Decryption asserts exactness (raises if a decrypted value is ever non-integer). | The BFV active-path implementation itself. |
| `src/fairlend/secure_compute/encrypted_aggregation.py`, `src/fairlend/secure_compute/__init__.py` | re-export lists | Updated to re-export ACTIVE (BFV), PHASE-1-BASELINE (`_ckks_direct`), and LEGACY (`_legacy_compsim`) names, all simultaneously importable and distinguishable. | Task item 5's "three conceptually distinguishable paths" requirement. |
| `evaluation/run_encrypted_audit.py`, `evaluation/run_fairness_reconstruction.py` | imports, config/metadata field names | Migrated to `fairlend.crypto.bfv`/`IdentityProviderBFV`; `ckks_config`→`bfv_config` in output JSON; packet fingerprint helper updated for the (unchanged) 6-field shape. | These are the ACTIVE-path evaluation scripts; migrating them is what "the active protocol now performs BFV" means operationally. |
| `evaluation/run_benchmarks.py`, `evaluation/run_primary_policy_encrypted_audit.py` | imports (already `_legacy_compsim`-aliased from Phase 1) | **No behavioural change** — docstrings updated for accuracy only (one docstring fix corrects a Phase-1-era inaccuracy that predates this phase). | These scripts produced already-committed artifacts; deliberately left untouched. |
| `evaluation/run_compsim_removal_equivalence_check.py`, `tests/scientific/test_encrypted_aggregation_direct.py` | imports | Repointed to explicit `_ckks_direct` names (previously bare canonical names, which now mean BFV). | Keeps the Phase 1 comparison exactly what it always was, unaffected by BFV's introduction (task item 5's "no deceptive test change" principle, applied again). |
| `tests/scientific/test_fairness_reconstruction.py` | imports, `_rebuild_packet` helper | Migrated to BFV (`IdentityProviderBFV`, `fairlend.crypto.bfv`, `ts.bfv_vector(lpu_context, [0, 0])` instead of `ts.ckks_vector`). | Consistent with its script counterpart's migration; becomes the primary real-model LR+RF exactness coverage for the ACTIVE path. |
| `tests/integration/test_run_encrypted_audit_script.py` | one test renamed and updated | `test_provenance_fields_present_and_ckks_config_matches_manuscript_defaults` → `..._and_bfv_config_matches_this_codebases_defaults`, asserting the new `bfv_config` JSON field shape. | Matches the migrated script's actual output. |
| `tests/scientific/test_encrypted_aggregation_bfv.py` | new file, 32 tests | Added. | Full BFV exactness/structural/privacy coverage (task item 8). |
| `evaluation/run_ckks_vs_bfv_equivalence_check.py` | new file | Added. | Differential correctness comparison (task item 9). |
| `evaluation/run_ckks_vs_bfv_benchmarks.py` | new file | Added. | Runtime + serialization comparison (task items 11-12, 17). |

---

## Existing-result validity matrix

| Artifact | Classification | Why |
|---|---|---|
| Proxy AUC / alpha1-seed sensitivity | **VALID UNCHANGED** | Plaintext-only; never touches `fairlend.crypto`/`fairlend.secure_compute` of any scheme. |
| Plaintext DP/EO | **VALID UNCHANGED** | `compute_plaintext_audit` untouched by either Phase 1 or Phase 2. |
| CKKS encrypted reconstruction (real-data, `{lr,rf}_balanced_accuracy_*.json`) | **LEGACY-ONLY** | Produced by `run_primary_policy_encrypted_audit.py`, deliberately left on the legacy compSim+CKKS path (Phase 1 decision, unchanged in Phase 2). Valid as a description of that path; not evidence for BFV. |
| Matching fidelity (`matching_fidelity_{runs,summary}.csv`) | **LEGACY-ONLY, UNCHANGED** | `fairlend.audit.matching` still uses CKKS `comp_sim` for its own, separate evaluation question — untouched by either phase. Not affected by, and does not need, a BFV counterpart under this report's scope. |
| Runtime (`runtime_{raw,summary}.csv`, legacy compSim) | **LEGACY-ONLY, UNCHANGED** | `run_benchmarks.py` still benchmarks only the legacy path (Phase 1 decision, unchanged). |
| Serialization (`serialization_{measured,analytical}.csv`, legacy compSim) | **LEGACY-ONLY, UNCHANGED** | Same reasoning; superseded, for the ACTIVE-path question specifically, by `serialization_ckks_direct_vs_bfv.csv`/`serialization_bfv_measured.csv` (this phase). |
| Communication (`communication_summary.csv`, legacy compSim) | **LEGACY-ONLY, UNCHANGED** | Same reasoning. |
| Figures 3/4 | **REQUIRES REGENERATION (already true before this phase)** | No source script exists for these images in the repository (established in the Phase 0 implementation-gap audit); unaffected by, and not newly obsoleted by, this phase specifically. |
| `results/fixture_validation/evaluation/compsim_removal_equivalence.csv` (Phase 1) | **VALID UNCHANGED, SUPERSEDED FOR THE SCHEME QUESTION** | Still an accurate legacy-vs-CKKS-direct comparison; the scheme question (CKKS vs. BFV) is now separately answered by this phase's `ckks_vs_bfv_equivalence.csv`. |
| This phase's new artifacts (`ckks_vs_bfv_*`, `serialization_bfv_measured.csv`, `serialization_ckks_direct_vs_bfv.csv`) | **NEW, VALID, PROVISIONAL** | Produced this session; `git_dirty=true` at measurement time (see provenance flag at top) — re-measure from a clean commit before treating as manuscript-final. |

---

## Phase 3 readiness

**Not yet ready to run the 9-configuration encrypted-fidelity subset under BFV**, for one procedural reason only: `evaluation/run_primary_policy_encrypted_audit.py` (the script that would actually run it against real LendingClub data) was deliberately left on the legacy CKKS+compSim path in both Phase 1 and Phase 2, to avoid touching the provenance-sensitive, already-committed real-data artifacts it produced. Before running the 9-config subset under BFV, that script (and its `reference_fingerprint`-based provenance fields in `fairlend.audit.primary_policy`, which assume a CKKS reference-vector concept that no longer exists in the active path) needs a small, contained migration — architecturally straightforward (identical to what was already done for `run_encrypted_audit.py`/`run_fairness_reconstruction.py`), but not done in this phase because it was not required to validate BFV's correctness/privacy/performance, which this report already establishes.

**Once that migration is done**, the exact command to run the 9-config subset (as pre-declared in `docs/MANUSCRIPT_EVIDENCE_STATUS.md`) would be, for each of the 9 `(alpha1, seed)` pairs in `{0.0, 0.7, 1.3} × {0, 5, 9}`:

```
python evaluation/run_primary_policy_encrypted_audit.py \
    --predictions results/evaluation/model_predictions.parquet \
    --synthetic-gender data/processed/synthetic_gender_alpha1_<ALPHA1>_seed_<SEED>.parquet \
    --split-dir data/processed/ \
    --data-scope real_lendingclub \
    --model logistic_regression \
    --threshold-policy validation_balanced_accuracy_max \
    --tau 0.80 \
    --alpha1 <ALPHA1> --seed <SEED> \
    --dataset-sha256 <sha256> \
    --output-predictions results/evaluation/lr_alpha<ALPHA1>_seed<SEED>_predictions.parquet \
    --output-audit results/evaluation/lr_alpha<ALPHA1>_seed<SEED>_encrypted_audit.json \
    --output-fairness results/evaluation/lr_alpha<ALPHA1>_seed<SEED>_fairness_reconstruction.json
```

**This is NOT executed in this phase** — per the task's explicit constraint, and because `data/raw/` is absent from this checkout regardless (the raw LendingClub CSV would need to be re-obtained first).

**NIZKP status, unchanged by this phase**: still zero code exists (`src/fairlend/nizkp/relations.py` remains a 17-line docstring with no `prove()`/`verify()`), exactly as established in the Phase 0 implementation-gap audit. Nothing in the BFV migration touches, requires, or blocks NIZKP work — they are fully independent workstreams. The NIZKP instantiation task (constraint counts, proof sizes, proving/verification times for `R_acc`/`R_score`/`R_bind`) remains entirely undone and is the one Reviewer #2 item this report cannot shortcut with existing artifacts.
