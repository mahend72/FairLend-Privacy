# Phase 3A: BFV Real-Data Migration — Blocked at the Data-Availability Gate

Scope: migrate the real-data encrypted evaluation workflow to BFV and execute the pre-declared 9-configuration encrypted-fidelity subset (`alpha1 ∈ {0.0, 0.7, 1.3} × seed ∈ {0, 5, 9}`, logistic regression only). No manuscript edits. No NIZKP work. No historical CKKS artifacts overwritten. No plaintext-model or fairness-definition changes. No dataset-split changes. No tests weakened.

---

## Executive conclusion

- **The 9 real-data configurations did NOT run. 0 of 9 completed.** Per this phase's own explicit instruction ("If the raw dataset is absent or does not match the manifest, STOP the real-data run and report the precise blocker"), execution stopped at the mandatory pre-flight data-availability check (task item 4), before any credential, model, or encryption call.
- **The precise blocker**: `data/raw/` contains no LendingClub CSV in this checkout (only `.gitkeep`; confirmed by direct filesystem inspection, and independently corroborated by this repository's own pre-existing `data/README.md`, which already states "As of this checkpoint, no LendingClub file has been located in this environment"). The tracked provenance metadata (`results/metadata/dataset_manifest.json`) expects the file at `data/raw/accepted_2007_to_2018Q4.csv` with SHA-256 `3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a` (2,260,701 raw rows) — none of which could be verified because the file itself is absent.
- **No substitute dataset was used.** No download was attempted, and no configuration or dataset was silently substituted, per the task's explicit constraint.
- **Consequently**: no BFV-vs-plaintext count comparison, no DP/EO reconstruction figure, and no runtime number for the real 177k-row TEST population exists from this phase. **This is honestly reported as zero evidence, not approximated, estimated, or borrowed from the fixture-scale rehearsal.**
- **What WAS completed, and is real, validated, reusable work**: a full audit of the historical CKKS real-data runner (task item 2); a mechanically-migrated, fixture-scale-validated BFV real-data runner (`evaluation/run_primary_policy_encrypted_audit_bfv.py`); a 9-configuration orchestrator with a working, independently-tested stop-guard (`evaluation/run_bfv_9config_encrypted_fidelity.py`) — **verified, right now, against this repository's actual current state, to correctly refuse to proceed** (exit code 3, no side effects); 12 new regression tests; and a cross-check confirming the pre-declared 9-configuration subset already exists, unmodified, in the repository's committed plaintext sensitivity sweep.
- **The experiment is NOT manuscript-ready.** It cannot be, because it did not run. What is manuscript-ready is the *architecture* (established in Phases 1-2) and the *protocol documentation* below — not a number claiming to be a real-data BFV encrypted-fidelity result.

---

## Experimental protocol (as it WOULD run, once unblocked — frozen, not altered)

| | |
|---|---|
| alpha1 values | {0.0, 0.7, 1.3} (pre-declared subset, `docs/MANUSCRIPT_EVIDENCE_STATUS.md`) |
| Seeds | {0, 5, 9} (pre-declared subset) |
| Model | logistic_regression only (pre-declared subset explicitly scopes LR-only, reasoning: "the aggregation MECHANISM does not depend on which model produced y_pred") |
| Frozen split | 70/10/20 train/validation/test, `split_seed=42` (unchanged; this phase reads, never regenerates, `data/processed/{train,validation,test}_index.parquet`) |
| Frozen threshold policy | `validation_balanced_accuracy_max`, tau=0.80 for LR (the primary policy established in Phase 9 of the prior evaluation) |
| Frozen predictions | `results/evaluation/model_predictions.parquet` (read-only; this phase's BFV runner never calls `.fit()`/`.predict()` again — confirmed by source inspection in the new regression tests) |
| Test population (from the last real run of this exact protocol) | 177,489 (`test_dp`) |
| Resolved-outcome population | 165,872 (`test_eo`) |
| EO coverage fraction | 165,872 / 177,489 = **93.45%** |
| BFV parameters (Phase 2, unchanged) | `poly_modulus_degree=8192`, `plain_modulus=33,832,961`, `max_safe_count=16,916,480` |
| Safety factor at the real population scale | 16,916,480 / 177,489 ≈ **95.3×** headroom |

None of the population/resolved-outcome/EO-coverage figures above are new measurements from this phase — they are read from the already-committed `results/evaluation/split_summary.json` (established before this session), reproduced here only to state the frozen protocol precisely, per this report's own template. **No new real-data number was produced in Phase 3A.**

---

## Task item 2: audit of the historical CKKS real-data runner

`evaluation/run_primary_policy_encrypted_audit.py` (left completely untouched in this phase) is tied to CKKS/compSim/reference vectors/CKKS context creation in exactly these places, and **nowhere else**:

| Line(s) | Tied to | Nature of the tie |
|---|---|---|
| 90-97 | Legacy compSim aggregation | Imports `compute_encrypted_audit_legacy_compsim`/`build_encrypted_aggregate_packet_legacy_compsim`/`decrypt_audit_packet_for_diagnostics_legacy_compsim`, aliased to the bare canonical names (a Phase 1 decision, unchanged). |
| 100-101 | CKKS context creation | `from fairlend.core.config import CKKSConfig`; `from fairlend.crypto.ckks import build_fla_context, context_can_decrypt, derive_lpu_context`. |
| 103 | Legacy reference vectors | `from fairlend.audit.similarity import generate_encrypted_references, load_reference_vectors`. |
| 106 | CKKS-specific Identity Provider | `from fairlend.roles.identity_provider import IdentityProvider` (issues CKKS ciphertexts). |
| 160-165 | CKKS-specific provenance serialization | `_ckks_config_dict(config: CKKSConfig)` — builds the `ckks_config` field of the run metadata. |
| 362-367 | Core CKKS+reference-vector setup | `build_fla_context()`, `derive_lpu_context()`, `IdentityProvider(lpu_context)`, `generate_encrypted_references(fla_context)`, `load_reference_vectors(...)`. |
| 375 | Legacy 5-arg call signature | `compute_encrypted_audit(lazy_records, ip.public_key, references, lpu_context, model_name=...)` — the `references` positional argument has no BFV/direct-addition counterpart at all. |
| 380-386 | Legacy 12-ciphertext, male/female-nested packet shape + reference-vector fingerprinting | `packet.male.C, ..., packet.female.FP` field-access pattern; `reference_fingerprint = sha256_hex(references_bytes.male_reference_bytes + references_bytes.female_reference_bytes)` — this concept **does not exist** in either the CKKS-direct or BFV direct-addition architectures (Phase 1 removed reference vectors entirely). |

**NOT tied to CKKS at all** (verified by reading, not assumed):
- **Matching-threshold (delta*) logic**: absent from this script entirely. The only mention of `run_matching_fidelity.py` in the file is an unrelated docstring cross-reference to a memory-management precedent (`_LazyEncryptedRecords`'s OOM-avoidance design). This script recomputes the *decision* threshold `tau` (`y_proba >= tau`), which is a different concept from the *matching* threshold `delta*` used by `comp_sim`'s argmax classification in `fairlend.audit.matching` — the two have never been connected in this script.
- **CKKS-specific reconstruction diagnostics**: `fairlend.audit.reconstruction.compute_aggregate_reconstruction`/`compute_fairness_reconstruction` contain zero `tenseal`/`ts.*` imports (confirmed by direct source inspection) — they operate purely on the scheme-agnostic `DecryptedAuditPacket`/`DecryptedGroupAuditCounts` shape that CKKS, CKKS-direct, and BFV all produce identically (this was already established and relied upon in Phase 2). The field *names* `dp_raw_ckks`/`eo_raw_ckks` are a historical naming artifact (documented, not hidden, in the new BFV runner's docstring) — not a functional CKKS dependency.
- Plaintext oracle computation (`build_audit_frame`, `compute_plaintext_audit`, `compute_demographic_parity`, `compute_equalised_odds`), tau/threshold-policy handling, frozen-prediction reading, and all `stamp_data_scope`/atomic-write plumbing are 100% scheme-agnostic.

**Minimum mechanical changes** (not a blind search-and-replace): swap the four import groups above for their BFV/`fairlend.crypto.bfv`/`IdentityProviderBFV` counterparts; delete the reference-vector setup and fingerprint entirely (no replacement concept exists); change the 5-arg legacy call to the 4-arg BFV signature; change the packet field-access pattern from `packet.male.C`/`packet.female.C` (12 nested fields) to `packet.C`/`packet.A`/... (6 flat fields); add an explicit, logged overflow-guard check before the long aggregation loop (in addition to the guard `compute_encrypted_audit` already enforces internally). Everything else carries over unchanged. This is exactly what `evaluation/run_primary_policy_encrypted_audit_bfv.py` (below) does.

---

## Task item 5: the new BFV real-data path

Per this phase's own "preferred approach" instruction, the historical script was **not modified**. A new, explicitly-named sibling was created instead:

- **`evaluation/run_primary_policy_encrypted_audit_bfv.py`** — per-configuration BFV runner. Mechanically migrated per the audit above; every provenance field is renamed/added to be unambiguous (`"scheme": "bfv"`, `bfv_config`, `bfv_safe_bound`, `bfv_safety_factor` — no `ckks_config`, no `reference_fingerprint`). Internally asserts BFV decryption is exact (raises if a decrypted value is ever non-integer) and that reconstruction error is exactly `0.0` (raises otherwise) — no invented tolerance anywhere.
- **`evaluation/run_bfv_9config_encrypted_fidelity.py`** — the 9-configuration orchestrator. Its **first** action, before touching any credential/model/encryption, is `verify_raw_dataset_provenance()` against the tracked manifest; only if that passes does it loop over the 9 `(alpha1, seed)` pairs, regenerating synthetic-gender labels via the unmodified `evaluation/generate_synthetic_gender.py` and calling the BFV runner once per configuration.

Both scripts were validated at **fixture scale** (`tests/fixtures/lendingclub_sample.csv`, 200 rows → 38-row TEST population after filtering) — proving the mechanics are correct — and the orchestrator's stop-guard was additionally validated **against this repository's actual, current, real state** (see next section), which is the one part of this phase that a fixture cannot substitute for, since the real question ("is the real dataset here?") has a real, checkable answer right now.

---

## Task item 4/6: raw-data availability check and preflight — BLOCKED

```
$ python evaluation/run_bfv_9config_encrypted_fidelity.py
BLOCKED: raw LendingClub CSV not found at .../data/raw/accepted_2007_to_2018Q4.csv.
The tracked manifest (.../results/metadata/dataset_manifest.json) expects
the file at 'data/raw/accepted_2007_to_2018Q4.csv' with SHA-256
3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a
(2260701 raw rows). This checkpoint's own data/README.md already
documents that no LendingClub file has been located in this environment.
Per task constraints, this script does NOT download or substitute an
alternative file -- obtain the exact dataset described in data/README.md
and place it at the expected path before re-running this script.
STOPPING before any configuration is run. No credential, model, or
encryption call was made.
$ echo $?
3
```

This is a **real invocation against the real repository state**, not a simulated/mocked test — the exit code (3), the message, and the "no side effect" claim are all directly observed, not asserted from a fixture. `data/processed/` is likewise empty (gitignored), so even the frozen split/prediction artifacts referenced in the "Experimental protocol" table above would themselves need regenerating from the raw file first — a second, consequential reason nothing further could proceed.

**Because this phase never reached a data-verified state, task item 6's preflight configuration (alpha1=0.7, seed=0, real data) also did NOT run.** The closest available substitute — the SAME code path exercised at fixture scale — did run and passed every check the preflight would have checked (population counts, exact 12-count agreement, exact DP/EO agreement, no per-record decryption, no secret key at the LPU, correct BFV-parameter metadata) — see "Configuration-level results" below for exactly what that fixture rehearsal showed. **This must not be read as if it were the real preflight** — it used 38 TEST records, not 177,489, and a different, deliberately small `tau`/threshold policy for test convenience, not the frozen `tau=0.80` primary policy.

---

## Configuration-level results

**No table of 9 real configurations exists, because 0 of 9 ran.** The columns the task template requests (alpha1, seed, N, resolved N, proxy AUC, DP plain, DP BFV, ΔDP, EO plain, EO BFV, ΔEO, max count error, runtime) have no real-data values to report from this phase.

What follows instead is the one thing that IS real and available without new data: the **pre-declared 9-row cross-check against the already-committed plaintext sensitivity sweep** (task item 12), confirming the subset itself is exactly reproducible from existing artifacts and ready to be the "plaintext" column the moment real BFV numbers exist:

| alpha1 | seed | model | female_fraction | proxy_auc | DP (plaintext) | EO (plaintext) |
|---|---|---|---|---|---|---|
| 0.0 | 0 | logistic_regression | 0.500377 | 0.499324 | 0.000303 | 0.003041 |
| 0.0 | 5 | logistic_regression | 0.499594 | 0.499964 | 0.001179 | 0.002034 |
| 0.0 | 9 | logistic_regression | 0.500627 | 0.499520 | 0.002510 | 0.003361 |
| 0.7 | 0 | logistic_regression | 0.503790 | 0.682543 | 0.000630 | 0.004220 |
| 0.7 | 5 | logistic_regression | 0.503916 | 0.682780 | 0.000841 | 0.001572 |
| 0.7 | 9 | logistic_regression | 0.504273 | 0.683197 | 0.001848 | 0.004906 |
| 1.3 | 0 | logistic_regression | 0.507031 | 0.792343 | 0.005544 | 0.011245 |
| 1.3 | 5 | logistic_regression | 0.507441 | 0.793203 | 0.003727 | 0.009355 |
| 1.3 | 9 | logistic_regression | 0.506974 | 0.792309 | 0.006354 | 0.011094 |

Source: `results/evaluation/alpha1_seed_sensitivity_runs.csv` (a pre-existing, already-committed artifact — queried, not regenerated, in this phase). Exactly 9 rows match `alpha1 ∈ {0.0,0.7,1.3} ∧ seed ∈ {0,5,9} ∧ model="logistic_regression"` — confirming the pre-declared subset is well-defined and already has a plaintext-side anchor. As a sanity cross-check against the previously-established real-data primary-policy result (a different threshold policy, `validation_balanced_accuracy_max`/tau=0.80, vs. this sweep's own tau): the alpha1=0.7, seed=0 row's DP≈0.00063/EO≈0.00422 is consistent with the already-committed `results/evaluation/primary_policy_results.csv`'s LR row (DP=0.0006298858929396633, EO=0.0042204779429118044) — no disagreement found, nothing to investigate further.

**Fixture-scale rehearsal** (NOT one of the 9 configurations; a mechanics check only), alpha1=0.7, seed=0, LR, 38-record TEST population, tau=0.5 (test-only threshold, not the frozen 0.80):

| Statistic | Plaintext | BFV | Match |
|---|---|---|---|
| C_m / C_f | 19 / 19 | 19.0 / 19.0 | ✓ |
| A_m / A_f | 19 / 19 | 19.0 / 19.0 | ✓ |
| P_m / P_f | 7 / 9 | 7.0 / 9.0 | ✓ |
| TP_m / TP_f | 7 / 9 | 7.0 / 9.0 | ✓ |
| N_m / N_f | 4 / 5 | 4.0 / 5.0 | ✓ |
| FP_m / FP_f | 4 / 5 | 4.0 / 5.0 | ✓ |
| DP (plain / BFV) | 0.0 | 0.0 | ✓ (ΔDP = 0.0) |
| EO (plain / BFV) | 0.0 | 0.0 | ✓ (ΔEO = 0.0) |

12/12 exact matches, `max_absolute_error = 0.0`, `e_DP = e_EO = 0.0`, `bfv_safety_factor ≈ 445,171×` (38 records against a 16,916,480 safe bound). Runtime: 0.9s total for 38 records (~42 rec/s) — not comparable to the real 177k-record run and not claimed to be.

---

## Aggregate fidelity summary

**From the 9-configuration real-data experiment: N/A — 0 configurations ran, 0 count comparisons exist.** The task's own worked example (9 × 2 × 6 = 108 comparisons) describes what the denominator WOULD be once real data is available and the orchestrator (which already computes this exact count automatically via `evaluation/run_bfv_9config_encrypted_fidelity.py`'s `n_count_comparisons = len(stats_df)`) is actually run — 108 is the correct expected denominator for LR-only at 9 configs × 2 groups × 6 statistics, verified by reading the orchestrator's own consolidation logic, not assumed.

**From the fixture-scale rehearsal** (12 comparisons, 1 configuration, clearly not the 9-config claim): 12/12 exact matches, max/mean absolute count error = 0.0, max DP/EO reconstruction difference = 0.0.

---

## Provenance

| | |
|---|---|
| Git commit (this phase's work) | Committed on branch `phase3a-bfv-realdata-prep`, based on `phase2-validated-checkpoint` (`b093365`) |
| Git dirty state at time of writing | Working tree clean except this phase's own new files at time of each test run |
| Dataset SHA-256 (expected, per tracked manifest) | `3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a` — **could not be verified against an actual file**, because no file exists |
| Result paths | None under `results/evaluation/bfv_*` exist yet — **no file was created under any of the item-11-suggested names**, since fabricating them without a real run would violate this task's "do not invent" constraint. The only new artifacts from this phase are code + tests (below) |
| Environment | Same as Phase 2 (Intel i7-10610U, WSL2/Linux, Python 3.13.5, TenSEAL 0.3.17) — unchanged, not re-collected, since no real run occurred to attach it to |

---

## Security regression

| Check | Result |
|---|---|
| Overflow guard | Active and logged in both the fixture rehearsal (`bfv_safety_factor ≈ 445,171×`) and, independently, in 3 new unit tests exercising `verify_raw_dataset_provenance`/the guard's integration; the BFV runner raises `BFVOverflowError` (exit code 2) if the guard ever fails, before any encryption. |
| Key separation | `lpu_ever_held_secret_key: False` confirmed in the fixture rehearsal's own audit-report JSON, and asserted in a dedicated regression test (`test_bfv_audit_no_secret_key_ever_held_by_lpu`). |
| No per-record decryption | `any_per_record_decryption_occurred: False`, same source. |
| Packet secrecy / scheme identification | New regression test confirms the audit report contains `"scheme": "bfv"` and a `bfv_config` block, and contains **neither** `ckks_config` **nor** `reference_fingerprint` (the latter having no BFV meaning at all). |
| Legacy script untouched | New regression test confirms `run_primary_policy_encrypted_audit.py` still imports the `_legacy_compsim`-aliased functions and `fairlend.crypto.ckks`, unchanged. |
| BFV runner cannot silently fall back to CKKS | New regression test (AST-based import inspection, not substring matching) confirms the BFV runner's actual import statements reference only `fairlend.crypto.bfv`/`IdentityProviderBFV`/`BFVConfig`, never `fairlend.crypto.ckks`/`IdentityProvider`/`CKKSConfig`/`fairlend.audit.similarity`. |
| Full test suite | **555 passed, 2 skipped, 0 failed** (346.24s) — up from the Phase 2 baseline of 543 passed. The +12 is exactly the new `tests/integration/test_run_primary_policy_encrypted_audit_bfv_script.py` file; no other test count changed; the same 2 tests remain skipped for the same pre-existing, gitignored-data reason. No test was weakened, relaxed, or had an expected value silently changed. |

---

## Comparison with earlier CKKS evidence

Kept strictly distinguished, per this phase's explicit instruction, never combined:

| Evidence tier | What exists | Scale |
|---|---|---|
| **Historical CKKS+compSim** (Phase 5/legacy) | Real-data artifacts `results/evaluation/{lr,rf}_balanced_accuracy_{encrypted_audit,fairness_reconstruction}.json`, produced by the UNTOUCHED `run_primary_policy_encrypted_audit.py` | Full real TEST population (177,489), single configuration (alpha1=0.7, seed=0) |
| **CKKS-direct** (Phase 1 baseline) | Fixture-scale equivalence only (`results/fixture_validation/evaluation/compsim_removal_equivalence.csv`); no real-data run exists for this specific variant | 38-row fixture |
| **BFV** (Phase 2 + this phase) | Phase 2: fixture-scale differential vs. CKKS-direct and plaintext (exact). This phase (3A): fixture-scale rehearsal of the REAL-DATA SCRIPT PATH (not the real data itself) | 38-row fixture only — **no real-data BFV run exists anywhere in this repository as of this report** |

No number from any of these three tiers has been averaged, blended, or presented as interchangeable with another anywhere in this report.

---

## Manuscript-ready facts

**None from this phase's own execution**, because this phase produced no new real-data measurement. Facts that remain manuscript-ready from EARLIER phases (unchanged, re-stated here only for completeness, each with its exact source):

| Fact | Source artifact |
|---|---|
| BFV reproduces exact integer counts and exact DP/EO on a controlled fixture, vs. both plaintext and the CKKS-direct baseline | `results/fixture_validation/evaluation/ckks_vs_bfv_equivalence.csv` / `..._summary.json` (Phase 2) |
| EO coverage for the real (CKKS-evaluated) TEST population is 93.45% | `results/evaluation/split_summary.json` (pre-existing) |
| The pre-declared 9-configuration subset's plaintext-side values are already computed and committed | `results/evaluation/alpha1_seed_sensitivity_runs.csv` (pre-existing; re-queried, not regenerated, in this phase) |
| A real-data BFV encrypted-fidelity number, at any of the 9 configurations | **Does not exist.** Do not insert a number here until Phase 3A is actually re-run with the raw dataset present. |

---

## Remaining Reviewer #2 gaps

1. **The 9-configuration real-data BFV encrypted-fidelity subset itself** — 0 of 9 complete. Blocked solely on raw-data availability, not on any architectural or implementation gap: `evaluation/run_bfv_9config_encrypted_fidelity.py --raw-csv <path-to-the-real-file>` (with `--predictions`/`--split-dir` pointed at the already-established real-data artifacts once `data/raw/`/`data/processed/` are populated) is the exact, ready-to-run command. Obtaining the dataset (per `data/README.md`) is a prerequisite this report cannot satisfy on its own.
2. **Concrete NIZKP implementation and benchmarks** — as established in every prior phase's report, still completely unimplemented (`src/fairlend/nizkp/relations.py` remains a 17-line docstring, no `prove()`/`verify()`). This phase did not touch it, per its own constraints, and it is expected to be the largest remaining Reviewer #2 item once (1) is unblocked.
3. **Migrating `run_matching_fidelity.py`/matching-fidelity evaluation to BFV or dropping it**, per Reviewer #2's original point 1 argument that this evaluation "has no object" once compSim is justified/removed — this is a manuscript-text and evaluation-design decision (flagged in the original Phase 0 audit), not something this phase's scope covers.
4. **Re-running the real-data primary-policy encrypted audit for RF** (not just LR) under BFV, and eventually reconciling the historical CKKS Fig. 3/4 figures — both explicitly deferred (per this phase's own constraints and the pre-declared subset's LR-only scope), not blocked by anything this phase discovered beyond gap (1).
