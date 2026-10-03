# Phase 1: compSim Removal — Direct Encrypted-Additive Aggregation

Scope: Reviewer #2 point 1 only (compSim degeneracy). CKKS is retained unchanged (no BFV/BGV migration). No NIZKP work. No manuscript edits. No expensive 9-configuration real-data experiment. This report documents an architectural correction to the executable implementation, isolated from every other Phase.

## 0. Preservation

- Pre-change state preserved as branch `pre-compsim-removal-checkpoint` → commit `b367abf` (identical to `main` before this session's edits; annotated tag creation failed only because git identity isn't configured in this environment — the branch pointer is sufficient and untouched).
- No file under `results/**` was modified or overwritten. Two new files were added under `results/fixture_validation/evaluation/` (`compsim_removal_equivalence.csv`, `compsim_removal_equivalence_summary.json`) — new artifacts, not replacements.
- All changes are currently uncommitted on `main` (working tree). Nothing was committed, per standing instruction to commit only when asked.

## 1. Architecture before

The legacy (compSim-based) path, still fully intact under explicit `_legacy_compsim`/`Legacy*` names:

1. `HE.g_i = (Enc(g_i,m), Enc(g_i,f))` — one 2-slot ciphertext, the credential itself.
2. `HE.r_m = Enc(1,0)`, `HE.r_f = Enc(0,1)` — two more encrypted ciphertexts, generated once by the FLA at setup (`generate_encrypted_references`) and shipped to the LPU.
3. Per record: `s_i,m = HE.g_i · HE.r_m`, `s_i,f = HE.g_i · HE.r_f` — two ciphertext-ciphertext multiplications (`comp_sim`, `CKKSVector.dot()`), each followed by TenSEAL's automatic relinearisation and rescale (multiplicative depth 1).
4. Per record, per group: `HE.C_k += s_i,k` (and conditionally `A_k/P_k/N_k/TP_k/FP_k`) — twelve separate 1-slot accumulators (`LegacyEncryptedGroupAuditCounts`, six per group × two groups).
5. Packet: `LegacyEncryptedAuditPacket` — 12 ciphertexts (`male.{C,A,P,TP,N,FP}`, `female.{C,A,P,TP,N,FP}`).

## 2. Architecture after

The new production path (`fairlend.audit.aggregation.compute_encrypted_audit`, called by `evaluation/run_encrypted_audit.py` and `evaluation/run_fairness_reconstruction.py`):

1. `HE.g_i` — the SAME 2-slot credential ciphertext, verified (`load_verified_protected_attribute_vector`, factored out of `comp_sim`'s old verify+deserialize logic) and then used **directly**, never multiplied.
2. No reference vectors exist anywhere in this path.
3. Per record: `HE.C += HE.g_i` (and conditionally `A/P/N/TP/FP`) — six 2-slot accumulators (`EncryptedAuditCounts`), each accumulating **both** groups simultaneously in its own SIMD slots. Pure ciphertext-ciphertext **addition**.
4. Packet: `EncryptedAuditPacket` — 6 ciphertexts (`C, A, P, TP, N, FP`), no `male`/`female` nesting at all — group separation lives entirely in each ciphertext's two slots.
5. Decryption (`decrypt_audit_packet_for_diagnostics`) splits each 2-slot ciphertext into `(male_value, female_value)` and reassembles the **same** `DecryptedAuditPacket`/`DecryptedGroupAuditCounts` shape the legacy path produced — so every downstream consumer (`fairlend.audit.reconstruction`, DP/EO computation) is byte-for-byte unaffected.

## 3. Mathematical equivalence

Given the manuscript's own reference-vector definitions:

```
compSim(Enc([g_m,g_f]), Enc([1,0])) = g_m·1 + g_f·0 = Enc(g_m)
compSim(Enc([g_m,g_f]), Enc([0,1])) = g_m·0 + g_f·1 = Enc(g_f)
```

This is an algebraic identity, not an approximation — it holds regardless of CKKS noise. `comp_sim` was recomputing, via two ciphertext-ciphertext multiplications, a value (`g_m`, `g_f`) already present in the credential's own ciphertext slots. Since every downstream aggregate (`C_k, A_k, P_k, N_k, TP_k, FP_k`) is defined as a **sum** of per-record group-membership values conditioned on **plaintext** decision/outcome flags (never on the ciphertext's own content), accumulating `HE.g_i` directly produces the identical sufficient statistics: `Dec(sum_i HE.g_i · [row i qualifies]) = [sum_i g_i,m · [...], sum_i g_i,f · [...]] = [C_m, C_f]` (or the corresponding conditioned statistic). No information used by DP/EO is lost; the reference vectors and the multiplication they required were pure overhead.

## 4. Code changes

| File | Function/class | What changed | Why |
|---|---|---|---|
| `src/fairlend/audit/similarity.py` | new `load_verified_protected_attribute_vector` | Added: verify signature + deserialize credential ciphertext, **no multiplication**. | Gives the new aggregation path the same "verify before touching ciphertext" guarantee `comp_sim` always had, without depending on `comp_sim`'s similarity computation. |
| `src/fairlend/audit/similarity.py` | `comp_sim` | Refactored (behaviour unchanged) to call the new helper internally instead of duplicating verify/deserialize logic. | Single source of truth; legacy tests confirm identical behaviour (31/31 pass unchanged). |
| `src/fairlend/audit/aggregation.py` | `EncryptedGroupAuditCounts`, `EncryptedAuditResult`, `compute_encrypted_audit`, `SerializedGroupAuditCounts`, `EncryptedAuditPacket`, `build_encrypted_aggregate_packet`, `decrypt_audit_packet_for_diagnostics`, helpers | **Renamed** to `Legacy*`/`*_legacy_compsim`, body otherwise byte-for-byte unchanged. | Preserve the exact legacy implementation, explicitly labelled, for equivalence testing and reproducibility. |
| `src/fairlend/audit/aggregation.py` | new `EncryptedAuditCounts`, `EncryptedAuditResult`, `compute_encrypted_audit`, `SerializedEncryptedAuditCounts`, `EncryptedAuditPacket`, `build_encrypted_aggregate_packet`, `decrypt_audit_packet_for_diagnostics` | Added: direct encrypted-additive aggregation, 6 two-slot ciphertexts, addition only. | Implements the Phase 1 architectural correction; these names are now what "the production path" means. |
| `src/fairlend/secure_compute/encrypted_aggregation.py`, `src/fairlend/secure_compute/__init__.py` | re-export lists | Updated to re-export both the new canonical names and the explicit legacy names. | Keeps the public facade consistent with the canonical module. |
| `evaluation/run_encrypted_audit.py` | imports, `_packet_sha256`, `main` | Removed reference-vector setup; call the new 4-arg `compute_encrypted_audit`; fingerprint now hashes 6 ciphertexts instead of 12. | Migrates the fixture/diagnostic script to the active production path. |
| `evaluation/run_fairness_reconstruction.py` | imports, `_packet_sha256`, `main` | Same migration as above (this script's own docstring already stated it uses "the same functions" as `run_encrypted_audit.py`). | Keeps that stated invariant true. |
| `evaluation/run_benchmarks.py` | imports only | Repointed 3 imports to explicit `_legacy_compsim` names via `as` aliasing — **zero behaviour change**. | Preserves exact reproducibility of `results/benchmarks/*.csv` (produced by the legacy path); benchmarking the new path is follow-up work (see §9). |
| `evaluation/run_primary_policy_encrypted_audit.py` | imports only | Same `as`-aliasing repoint to legacy names — **zero behaviour change**. | This script produced the already-committed real-data artifacts (`results/evaluation/{lr,rf}_balanced_accuracy_*.json`) whose `reference_fingerprint` provenance field only exists for the reference-vector-based path; migrating it is deliberately deferred, not blocked (see §9). |
| `tests/scientific/test_encrypted_aggregation.py`, `test_encrypted_aggregation_privacy.py` | imports | Repointed to explicit legacy names; one inline re-import and one structural-inspection assertion fixed to reference the legacy function explicitly. | These files now test the legacy path exclusively, unchanged expected results (classified obsolete-for-production, not deceptively altered). |
| `tests/scientific/test_fairness_reconstruction.py` | imports, `full_pipeline` fixture, `_rebuild_packet` | Migrated to the new path (real, independently-fitted LR+RF models). | Primary LR+RF coverage of the new path against genuinely different per-model predictions. |
| `tests/integration/test_run_encrypted_audit_script.py` | `_spy` helper | Signature updated to 4 args (dropped `references`). | Matches the migrated script's new call signature. |
| `tests/scientific/test_encrypted_aggregation_direct.py` | new file | 22 new tests: all-male/all-female/mixed/one-group-absent batches, approval-conditioned, P/N-conditioned, TP/FP-conditioned, LR+RF paths, structural "no comp_sim call", "no reference vectors in signature", "no ciphertext multiplication" (monkeypatch-enforced), "never decrypts on LPU side", key-boundary/tamper/wrong-key rejection, packet shape (6 fields, no male/female nesting). | Proves the new invariant end-to-end. |
| `evaluation/run_compsim_removal_equivalence_check.py` | new file | Runs legacy and new paths over the **identical** issued credentials on the small fixture pipeline; writes a CSV/JSON comparison. | Item 7's equivalence experiment, reproducible via a real script rather than a throwaway snippet. |

## 5. Removed/legacy components

| Component | Classification | Where it lives now |
|---|---|---|
| Encrypted reference vectors (`HE.r_m`, `HE.r_f`, `generate_encrypted_references`, `load_reference_vectors`) | **B** for audit-aggregation (no longer called by `compute_encrypted_audit`); **C** for matching-fidelity (`fairlend.audit.matching` still uses them for its own delta*/argmax classification — a distinct evaluation question, out of Phase 1 scope) | `fairlend/audit/similarity.py`, unchanged |
| `comp_sim` itself | **B**/**C** (same split as above) | `fairlend/audit/similarity.py`, unchanged, now documented as legacy-for-aggregation |
| Similarity threshold `delta*` / matching classification / matching accuracy/macro-F1 | **C** — entirely `fairlend.audit.matching`'s own concern, never touched `aggregation.py`, unaffected by this change | `fairlend/audit/matching.py`, `evaluation/run_matching_fidelity.py`, unchanged |
| Similarity-reconstruction/MAE tests (`test_similarity_numerical_fidelity.py`, `test_similarity.py`) | **C** — still validate `comp_sim`'s own numerical behaviour, needed for the matching-fidelity evaluation | Unchanged |
| Relinearisation/rescale caused by compSim's multiplication | **A** — removed from the active audit-aggregation path (0 multiplications, confirmed empirically, see §6/§8); still occurs wherever `comp_sim` itself is still called (matching-fidelity, legacy path) | N/A (structural consequence, not a file) |
| `LegacyEncryptedGroupAuditCounts`/`LegacyEncryptedAuditPacket` (12-ciphertext shape) and its build/decrypt functions | **B** — retained under explicit legacy names for equivalence testing and for `run_primary_policy_encrypted_audit.py`/`run_benchmarks.py`, which still produce/consume this exact shape | `fairlend/audit/aggregation.py` |
| `reference_fingerprint` provenance field | **C** for `run_primary_policy_encrypted_audit.py` (unchanged, still required there); not applicable to the migrated scripts (no references exist to fingerprint) | `evaluation/run_primary_policy_encrypted_audit.py` only |

Nothing was deleted. `git diff --stat` against the `pre-compsim-removal-checkpoint` branch shows only renames/additions within the touched files, no removed functionality.

## 6. Privacy regression results

**Targeted legacy suite** (proves the renamed-but-unchanged legacy path still behaves identically): `test_encrypted_aggregation.py` + `test_encrypted_aggregation_privacy.py` — 31 passed, 2 skipped (gitignored-data-dependent, same 2 as before any change).

**New direct-path suite**: `test_encrypted_aggregation_direct.py` — 22 passed, including the structural proofs that the new path never calls `comp_sim`, takes no `references` parameter, performs zero ciphertext-ciphertext multiplications (monkeypatch-enforced — the test fails loudly if any multiplication is attempted), never decrypts on the LPU side, and rejects a private (`sk_HE`-holding) context / tampered credential / wrong IP key exactly as the legacy path did.

**Full suite, before this session's changes**: 489 passed, 2 skipped.
**Full suite, after all Phase 1 changes**: **511 passed, 2 skipped, 0 failed** (252.4s). The 22-test increase is exactly the new `test_encrypted_aggregation_direct.py` file; no other test count changed, and the same 2 tests remain skipped for the same reason (gitignored `data/processed/fixture_validation` intermediate absent in this checkout).

Explicitly re-verified, per the task's checklist:
- LPU cannot decrypt protected attributes — `context_can_decrypt(lpu_context) is False` asserted before and after aggregation, both paths (`test_lpu_context_never_holds_sk_he_during_aggregation`, `test_lpu_context_never_holds_sk_he_during_direct_aggregation`, `test_1_lpu_has_no_sk_he_throughout_aggregation`).
- No per-record protected attribute is decrypted — monkeypatch-enforced on both paths (`test_no_decrypt_call_occurs_during_lpu_side_aggregation`, `test_direct_path_never_decrypts_on_lpu_side`).
- Key separation intact — `KeyBoundaryError` raised for a private-context call on both paths (`test_compute_encrypted_audit_rejects_private_context`, both versions).
- FLA receives/decrypts aggregate information only — packet field enumeration (`test_packet_has_six_ciphertext_fields_not_twelve`, `test_no_forbidden_substring_in_packet_field_names`) confirms no per-record field exists in the new packet, exactly as the legacy privacy suite already proved for the old one.
- Plaintext gender remains confined to the IP — `IdentityProvider.issue_credential` unchanged; `load_verified_protected_attribute_vector` only ever handles ciphertext bytes.
- Protected attribute excluded from decision-model features — untouched (`fairlend.models.credit_models`, `test_gender_exclusion.py` unmodified, still passing).
- No newly introduced logging/debug code leaks protected attributes — no `print`/`logging` statements added anywhere in `aggregation.py` or `similarity.py` (existing `test_10_no_print_or_logging_in_aggregation_module` still passes; `test_similarity_no_logging.py` unmodified, still passing).

No test was weakened to make the new architecture pass. Where an old test explicitly validated compSim-specific behaviour, it was repointed to the legacy function under its explicit name (same assertions, same expected values) rather than silently repurposed.

## 7. Numerical equivalence (small fixture experiment)

`evaluation/run_compsim_removal_equivalence_check.py`, run against the small hermetic fixture (`tests/fixtures/lendingclub_sample.csv`, 38-row TEST population), feeding the **identical** issued credentials into both the legacy and new aggregation calls. Full results in `results/fixture_validation/evaluation/compsim_removal_equivalence.csv` (24 rows: 2 models × 2 groups × 6 statistics). Every row:

| | old_rounded | new_rounded | old_minus_new_rounded |
|---|---|---|---|
| all 24 (model, group, statistic) combinations | matches plaintext oracle exactly | matches plaintext oracle exactly | **0** (script asserts this and would abort otherwise) |

Sample rows (full precision in the CSV):

| model | group | stat | plaintext | old_raw | old_abs_err | new_raw | new_abs_err |
|---|---|---|---|---|---|---|---|
| logistic_regression | male | C | 19 | 19.0000064 | 6.44e-6 | 18.9999999893 | 1.07e-8 |
| logistic_regression | female | A | 16 | 16.0000053 | 5.26e-6 | 15.9999999851 | 1.49e-8 |
| random_forest | male | TP | 7 | 7.0000026 | 2.59e-6 | 7.0000000055 | 5.50e-9 |

**A notable, unplanned finding**: the new path's raw (unrounded) CKKS error is consistently **~300-600x smaller** than the legacy path's (e.g. 1.07e-8 vs 6.44e-6 for the same statistic) — expected in hindsight, since the legacy path's error included one ciphertext-ciphertext multiplication's rescale noise on top of the summation noise, while the new path has only summation noise. Both remain far below the 0.5 rounding-safety margin.

DP/EO comparison (`compsim_removal_equivalence_summary.json`):

| model | DP_plain | DP_legacy | DP_direct | EO_plain | EO_legacy | EO_direct |
|---|---|---|---|---|---|---|
| logistic_regression | 0.10526315789473684 | 0.10526315789473684 | 0.10526315789473684 | 0.25 | 0.25 | 0.25 |
| random_forest | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

Both models: legacy and direct paths reproduce the plaintext DP/EO gap **exactly**, confirming removing compSim changes the computation graph, not the scientific output, exactly as intended.

## 8. Complexity change (measured, not estimated)

Measured directly (monkeypatch call-counting and wall-clock timing on the same credential set, `N=10` and `N=50` records respectively — see this session's ad hoc measurement scripts, not committed as they're one-off diagnostics; the underlying `compute_encrypted_audit`/`compute_encrypted_audit_legacy_compsim` calls are the real production functions):

| Metric | Legacy (compSim) | New (direct addition) |
|---|---|---|
| Ciphertext-ciphertext multiplications per record | 2 (`g_i · r_m`, `g_i · r_f`) | **0** |
| `.dot()` calls, 10 records | 20 | **0** |
| Additions, 10 records | 60 (up to 12 per record: 6 stats × 2 groups, conditional) | 30 (up to 6 per record: 6 stats, conditional — exactly half, since both groups now share one addition) |
| Multiplicative depth | 1 | **0** |
| Relinearisation | Yes (automatic, after each multiplication) | **No** (never triggered — nothing is ever multiplied) |
| Rescaling | Yes (automatic, after each multiplication) | **No** |
| Encrypted reference objects | 2 (`HE.r_m`, `HE.r_f`), generated once at setup | **0** |
| Aggregate ciphertexts per packet | 12 (6 stats × 2 groups, each 1 slot) | **6** (one 2-slot ciphertext per stat) |
| Aggregation+packet wall-clock, N=50 records | 1.5656 s (31.3 ms/record) | **0.2289 s (4.6 ms/record) — 6.84x faster** |
| Packet size, N=50 records | 2,821,211 B | **1,985,555 B — 1.42x smaller** |

This is direct, measured evidence for a manuscript statement that the revised construction is depth-zero additive aggregation, with roughly 7x lower aggregation latency and ~30% smaller aggregate packets, at the cost of no scientific-result change (§7).

## 9. Impact on existing result artifacts

| Artifact | Classification | Why |
|---|---|---|
| Proxy AUC / alpha1-seed sensitivity (`alpha1_seed_sensitivity_{runs,summary}.csv`) | **VALID UNCHANGED** | Plaintext-only path; never imports `fairlend.crypto`/`fairlend.secure_compute`; untouched by this change (verified: no `tenseal` import in `fairlend.audit.alpha_seed_sensitivity`). |
| Plaintext DP/EO (`plaintext_audit.{csv,json}`, `primary_policy_results.{csv,json}`'s `*_plain` columns) | **VALID UNCHANGED** | Same reasoning — `compute_plaintext_audit` was never touched. |
| Encrypted reconstruction, real-data (`{lr,rf}_balanced_accuracy_encrypted_audit.json`, `*_fairness_reconstruction.json`) | **VALID UNCHANGED (produced by the still-intact legacy path)** | `run_primary_policy_encrypted_audit.py` was deliberately left pointed at the legacy functions (§4) — these artifacts remain byte-for-byte what that unmodified code path produces. They are **not** yet evidence for the new path on real data; migrating this script and re-running on real LendingClub data is Phase 1-adjacent follow-up (§10), not done here (no `data/raw/` in this checkout; would cost ~3 hours per model at the measured 5000+s/run scale). |
| Runtime (`runtime_{raw,summary}.csv`) | **VALID UNCHANGED, describes the legacy path only** | `run_benchmarks.py` still benchmarks the legacy path (§4). A new benchmark run for the direct-addition path is follow-up work (§10) — this report's §7/§8 measurements are a preview of what it would show. |
| Serialization (`serialization_{measured,analytical}.csv`) | **VALID UNCHANGED, describes the legacy path only** | Same reasoning. The new path's actual measured sizes are in §8 above (from this session's ad hoc measurement) but not yet in a tracked benchmark CSV. |
| Communication (`communication_summary.csv`) | **VALID UNCHANGED, describes the legacy path only** | Same reasoning. |
| Matching fidelity (`matching_fidelity_{runs,summary}.csv`) | **VALID UNCHANGED — separate evaluation, untouched** | `fairlend.audit.matching` was never modified; still exercises `comp_sim` for its own delta*/argmax purpose (§5). Whether this evaluation still has a manuscript "object" per Reviewer #2's argument is a manuscript-text question, out of this report's scope. |
| Figures 3/4 (computation-cost.png, communication-cost.png) | **OBSOLETE AFTER ARCHITECTURE CHANGE (already obsolete before it)** | No source script for these images exists in the repository (established in the prior implementation-gap audit); they describe neither the legacy nor the new path's actual measured numbers and would need to be regenerated regardless of which path they describe. |
| This session's new equivalence artifacts (`compsim_removal_equivalence.csv/json`) | **NEW, VALID** | Produced fresh in this session, fixture-scale only, documented in §7. |

## 10. Readiness for Phase 2 (CKKS → BFV/BGV)

The direct-addition path is now the simplest possible target for a scheme migration:

- **What would need to change**: `src/fairlend/crypto/ckks.py`/`secure_compute/ckks.py` (context construction: `ts.SCHEME_TYPE.CKKS` → `BFV`, plaintext-modulus parameter instead of `global_scale`), `IdentityProvider`'s one-hot encoding (`ts.ckks_vector` → `ts.bfv_vector`, still a 2-slot integer vector), and `compute_encrypted_audit`'s zero-initialisation (`ts.ckks_vector(ctx, [0.0, 0.0])` → the BFV equivalent). That is the entire diff — `compute_encrypted_audit`'s control flow (which stat gets incremented under which condition) does not change at all, since it was already addition-only.
- **What would NOT need to change**: `fairlend.audit.reconstruction`, `fairlend.audit.fairness`, the plaintext audit path, the alpha1/seed sensitivity sweep, matching-fidelity evaluation (a separate CKKS-based concern, unaffected by an aggregation-path scheme change), and every downstream consumer of `DecryptedAuditPacket` — none of them know or care which HE scheme produced the packet they're decrypting.
- **Experiments that would need rerunning**: only the cryptographic/runtime ones — `run_benchmarks.py` (once updated to target BFV), the encrypted-fidelity equivalence check (`run_compsim_removal_equivalence_check.py`, trivially adaptable), and eventually the real-data encrypted aggregation (`run_primary_policy_encrypted_audit.py`, once migrated off the legacy CKKS-compSim path). The plaintext fairness pipeline (proxy AUC, DP/EO sensitivity sweep) would **not** need rerunning (§9's reasoning applies identically).
- **Not started in this phase**: no BFV/BGV code, context, or experiment exists anywhere in the repository as of this report. This is deliberate, per the task's explicit constraint.
- **Recommended before Phase 2**: migrate `run_primary_policy_encrypted_audit.py` and `run_benchmarks.py` off the legacy path first (both are currently zero-risk `as`-aliased pointers to the legacy functions, not blocked by anything — see §5's classification), so that Phase 2's "before" state is the direct-addition CKKS path measured on real data, not the legacy compSim path. This is smaller, lower-risk work than the scheme migration itself and should happen before it, not during it.
