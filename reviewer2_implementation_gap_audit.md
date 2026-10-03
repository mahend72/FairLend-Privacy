# Reviewer #2 Implementation-Gap Audit

Audit date: 2026-09-26. Scope: `src/fairlend`, `evaluation/`, `tests/`, `results/`, `docs/`, `legacy/`, and `manucript.tex`. This report inspects the **executable implementation and its result artifacts**, not the manuscript prose (already audited separately; see `docs/MANUSCRIPT_IMPLEMENTATION_AUDIT.md` and the prior conversation turn). No manuscript edits were made. No code was changed. No new measurements were invented; every number below is either read from a tracked result artifact or produced by re-running an existing, already-tracked test in this session.

Git state at audit time: `HEAD=b367abf`, only untracked change is `manucript.tex` (git status confirmed clean otherwise). The tracked result artifacts (`results/**`) were produced at commit `fc62c4d4` with `git_dirty=true` (recorded in their own metadata fields) — i.e. they predate and are not literally regenerable byte-for-byte from the exact current commit, though the same scripts/config would reproduce them (see Section G).

---

## Executive conclusion

**1. Already implemented and can be incorporated into the manuscript immediately (as text, not as new experiments):**
- The exact selective-label / equalised-odds coverage fraction (Reviewer point E): **165,872 / 177,489 = 93.45%** of the TEST audit population has a resolved outcome. Source: `results/evaluation/split_summary.json` (`resolved_test` / `test_audit_population`), produced by `evaluation/split_dataset.py`.
- The real, measured serialized-object sizes that contradict Table 8's analytical estimates and explain the Table 8 vs. Fig. 3b mismatch (Reviewer point 4, bullet 3): `results/benchmarks/serialization_measured.csv` / `serialization_analytical.csv`.
- The real reconstruction-error numbers that show `2.1×10⁻⁵` is unsupported (Reviewer point 3): `results/evaluation/{lr,rf}_balanced_accuracy_fairness_reconstruction.json`.
- Confirmation that only two decision models were ever evaluated (Reviewer point F): `results/evaluation/model_metrics.csv`, `primary_policy_results.csv` — no third model exists anywhere in the codebase or results.
- The ten-seed × five-alpha1 proxy-AUC/DP/EO sensitivity table (part of Reviewer point 3's "cheap remedies"): `results/evaluation/alpha1_seed_sensitivity_summary.csv` — real, already computed, 100 rows.
- Real runtime and communication benchmarks with hardware/environment provenance: `results/benchmarks/runtime_{raw,summary}.csv`, `communication_summary.csv`, `results/metadata/benchmark_environment.json`.

**2. Exists experimentally but needs rerunning/validation before being cited as-is:**
- All of the above real-data artifacts were produced with `git_dirty=true` at a commit one step behind `HEAD`. Before citing exact figures in a revision, rerun the pipeline at a clean, tagged commit (the scripts and config are deterministic and would reproduce the same figures — see Section G — but "dirty" provenance should not be the citation of record for a journal submission).
- The primary encrypted-fidelity result (matching + LR + RF encrypted aggregation) exists for **exactly one** configuration (`alpha1=0.7, seed=0`). The 9-configuration encrypted-fidelity subset the codebase's own docs propose (`docs/MANUSCRIPT_EVIDENCE_STATUS.md`, "Proposed encrypted-fidelity subset") was **never executed** (estimated ≈33–47 hours of runtime). This is real, needed work, not already-done work.
- `data/raw/` is empty in this checkout (`.gitignore`d, only `.gitkeep` present) — none of the real-LendingClub-scale artifacts above can be regenerated from this checkout alone; the raw CSV must be re-obtained.

**3. Requires genuinely new implementation:**
- Any concrete NIZKP instantiation (`R_acc`, `R_score`, `R_bind`) — **zero code exists**, not even placeholder dataclasses (`src/fairlend/nizkp/relations.py` is a docstring only, 17 lines, no class, no `prove`/`verify`). This is the one item in Reviewer point 3 that cannot be satisfied from existing artifacts.
- Any noise-flooding/smudging mechanism for CKKS to address the IND-CPA vs. IND-CPA^D gap (Reviewer point 2) — not implemented anywhere.
- Any >2-category / packed multi-attribute extension of compSim, if the authors choose to justify-and-extend rather than remove (Reviewer point 1) — not implemented; current code is hard-coded to exactly 2 groups (`GROUP_MALE`, `GROUP_FEMALE`, `GENDER_VECTOR_SIZE = 2`).

**4. Should be removed/replaced because the reviewer identified a genuine construction flaw:**
- **`compSim` is mathematically confirmed redundant in the implemented code**, exactly as Reviewer #2 claims. See Section "Critical architecture findings" below for the proof and the exact lines that could be replaced by a plain ciphertext addition. **Not changed in this audit — the user's task instructions explicitly prohibit doing so here.**

---

## Reviewer comment matrix

| Reviewer request | Manuscript status | Implementation status | Evidence/source file | Existing quantitative result | Action required | Effort |
|---|---|---|---|---|---|---|
| 1. Justify or remove compSim (degenerate at depth 0/1) | Unchanged; Sec. 4.8/6.1.2/6.4 still present as originally written | **Confirmed redundant** — `compSim(HE.g_i, HE.r_m)` is provably `HE(g_i,m)` given the implemented one-hot representation (see below) | `src/fairlend/audit/similarity.py:1-16,239-288`, `src/fairlend/roles/identity_provider.py:38-39,95-96` | None claimed as a fidelity result beyond the already-existing MAE/max-error fixture numbers (`tests/scientific/test_similarity_numerical_fidelity.py`) | Either (a) rewrite 4.8/6.1.2/6.4 around plain encrypted-additive aggregation and drop compSim, or (b) justify compSim explicitly as groundwork for a not-yet-built multi-category extension and say so in text | Small (text) / Moderate (if multi-category code is added instead) |
| 2. CKKS vs. BFV/BGV/Paillier; IND-CPA vs. IND-CPA^D; smudging | Unchanged; Theorem 1 (Sec. 5.2) still invokes plain IND-CPA | CKKS is used throughout; all released quantities are rounded integer counts; **no smudging/noise-flooding code exists anywhere** (`grep` found zero hits) | `src/fairlend/crypto/ckks.py`, `src/fairlend/audit/aggregation.py:583-606` (`Round(HE.Dec(...))`) | Aggregate reconstruction is **exact** after rounding (`e_DP=e_EO=0.0`, see Section C) — supports "BFV/BGV would give exact counts with no approximation-error discussion" as a *valid* alternative, since the current CKKS noise is already negligible relative to rounding | Either add smudging (crypto work) or justify CKKS choice in text and restate Theorem 1 to exclude decryption-exposed settings, or migrate the aggregation path to BFV/BGV (see Critical Findings) | Moderate (text) / Major (scheme migration) |
| 3a. Proxy-inference AUC | Sec. 6.1.3 still disclaims a specific value | **Implemented and measured** across all 5 alpha1 values × 10 seeds | `results/evaluation/alpha1_seed_sensitivity_summary.csv` | e.g. alpha1=0.7: proxy AUC = 0.6830 ± 0.0010 (n=10 seeds) | Insert existing table into manuscript | Trivial |
| 3b. Reconstruction error over seeds/alpha1 | Sec. 6.5.4 still disclaims, then contradicts with `2.1e-5` | Plaintext-side DP/EO sensitivity fully computed for all 50 configs; **encrypted-side** reconstruction error computed for exactly 1 config (alpha1=0.7, seed=0) | `results/evaluation/alpha1_seed_sensitivity_{runs,summary}.csv` (plaintext); `results/evaluation/{lr,rf}_balanced_accuracy_fairness_reconstruction.json` (encrypted, 1 config) | e_DP = e_EO = 0.0 for both models at the one encrypted config measured; **no measured value anywhere in the repository equals or resembles `2.1×10⁻⁵`** | Cite the real e_DP/e_EO=0.0 result now; run the pre-declared 9-config encrypted-fidelity subset (docs/MANUSCRIPT_EVIDENCE_STATUS.md) for seed/alpha1 coverage of the encrypted path, or explicitly scope the claim to the single measured configuration | Small (cite existing) / Major (9-config rerun, ~33-47h compute) |
| 3c. Measured serialised sizes | Table 8 still says "analytical estimates"; text (Sec. 6.1.5) still claims "actual serialised objects" | **Measured**, real byte counts from the actual TenSEAL objects | `results/benchmarks/serialization_measured.csv` | Application packet (Bank+CA+IP, canonical-JSON) = 662,932 B; complete aggregate audit packet = 5,642,620 B; single packed protected-attribute ciphertext = 331,060 B (see Critical Findings for why this differs from Table 8's 786,560 B two-ciphertext assumption) | Replace Table 8's analytical column with these measured values, or add both columns side by side as the codebase's own `serialization_analytical.csv`/`serialization_measured.csv` already do | Small |
| 3d. NIZKP instantiation with constraint counts/timings | Sec. 6.4/6.7/7/Table 9 still say "not implemented" | **Not implemented** — confirmed by exhaustive repo-wide search (Groth16/PLONK/Halo2/Circom/R1CS/Arkworks/Bellman/SnarkJS: zero hits outside documentation) | `src/fairlend/nizkp/relations.py` (17-line docstring, no code), `docs/NIZKP_SCOPE.md` | None; cannot be fabricated | Implement at least one concrete instantiation (Setup/Prove/Verify) for at least one relation, or make the manuscript's "future work" framing explicit and consistent everywhere (Table 9 already partially says this) | Major (real crypto implementation) |
| 4a. 6.5.4 contradiction (disclaim then assert `2.1e-5`; "three" vs. two models) | **Still present verbatim** in `manucript.tex` (lines 2204, 2215-2217) | N/A (text-only issue) | `manucript.tex:2204-2219` | `results/evaluation/model_metrics.csv` confirms only 2 models (`logistic_regression`, `random_forest`) exist anywhere | Delete the `2.1e-5`/"three models" sentence, or replace it with the real e_DP=e_EO=0.0 (two-model) result | Trivial |
| 4b. 6.1.5/Table 8 measured-vs-estimate contradiction | Still present verbatim (lines 1927, 1937 vs. 1943, 2007) | N/A (text-only) | `manucript.tex:1924-1943` | Real measured CSVs exist (see 3c) to resolve this by actually reporting measured values | Pick one framing and make Table 8 match it (ideally: report measured, as the codebase now can) | Trivial once 3c is incorporated |
| 4c. Table 8 (~787 kB) vs. Fig. 3b (~21 kB/100 borrowers) | Fig. 3/4 images unchanged, not tracked in this repo at all | Table 8's 787,100 B figure derives from the manuscript's **own** analytical formula assuming **two separate** ciphertexts (786,432 B) for the protected attribute; the actual implementation packs both one-hot coordinates into **one** 2-slot ciphertext (331,060 B measured) — the manuscript's own architecture assumption differs from what was (later) built | `manucript.tex:2007-2015` (formula); `src/fairlend/roles/identity_provider.py:38-39,95-96` (single `ts.ckks_vector(ctx, [g_m, g_f])` call); `results/benchmarks/serialization_measured.csv` | Measured packet ≈662.9 kB vs. Table 8's ≈787.1 kB estimate (−15.8%); Fig. 3b's ≈21 kB/100 borrowers is **not traceable** — no source data or script for `communication-cost.png` exists anywhere in this repository (image itself is also untracked/absent) | Regenerate Fig. 3/4 from `results/benchmarks/communication_summary.csv`, or remove the figure and cite the CSV directly | Small (data exists) but requires new plotting |
| 4d. 6.1.1 promises ten-seed stats; 6.1.4 says not included | Still present verbatim (lines 1878 vs. 1892) | **Ten-seed plaintext results exist** (does not resolve the contradiction on its own — 6.1.4's specific disclaimer is about the encrypted-matching-F1/reconstruction columns of that promised table, which are still mostly single-config) | `results/evaluation/alpha1_seed_sensitivity_summary.csv` | Female proportion, proxy AUC, DP, EO: all present for 10 seeds × 5 alpha1. Encrypted matching-F1/reconstruction-error columns: only 1 of 50 configs measured | Either report the plaintext columns now (available) and explicitly scope the encrypted columns to the single measured config, or run the 9-config encrypted subset first | Small (plaintext) / Major (encrypted) |
| 4e. Duplicate aggregate-error definitions in 6.5.4 | Still duplicated verbatim (lines 2204, 2209) | N/A (text-only) | `manucript.tex:2204-2209` | — | Delete the duplicate block | Trivial |
| Minor: IP holds plaintext gender; Sec. 3.5 should say so plainly | Table 5 (leakage profile) already states it; Sec. 3.5 prose does not | Confirmed accurate: `IdentityProvider.issue_credential` is the only code that ever sees a plaintext gender label before encrypting it | `src/fairlend/roles/identity_provider.py`, `manucript.tex:1710-1717` (Table 5 row) | — | Add one sentence to Sec. 3.5 stating the IP is a trusted third party that necessarily observes plaintext gender before encryption | Trivial |
| Minor: Figure 1 typo / gratuitous example | Typo fixed ("minorty"→"minority"); example content unchanged | N/A | `manucript.tex:367` | — | Optionally trim the example list per reviewer's "gratuitous" comment | Trivial |
| Minor: self-citations [13]-[15] tangential | Still present, still tangential (healthcare/cyber-physical/cloud-auditing topics) | N/A | `manucript.tex:332,469` (`kumar2020secure`, `kumar2025securing`, `kumar2023efficient`) | — | Remove or better justify relevance | Trivial |
| Minor: funding statement vs. title-footnote grants | Still mismatched (4 EPSRC grants in footnote vs. Gates Foundation in Funding statement) | N/A | `manucript.tex:41` vs. `2372-2373` | — | Reconcile with the actual funder(s) | Trivial (needs author input on which is correct) |
| Minor: pagination "Page 26 of 25"; Algorithm 6 line 43 truncation | **Cannot verify — no LaTeX toolchain in this environment** (`pdflatex`/`bibtex`/`latexmk`/`tectonic` all absent; no TeX Live packages installed) | N/A | — | — | Compile in the authors' own LaTeX environment (Overleaf) and re-check | Trivial (once compiled) |
| Minor: selective-label EO population fraction | Not stated anywhere in text | **Computed, real** | `results/evaluation/split_summary.json` | **165,872 / 177,489 = 93.45%** of TEST population has a resolved outcome (11,617 unresolved) | Add one sentence with this figure to Sec. 6.5.3 | Trivial |
| Model-count inconsistency ("three evaluated decision models") | Still says "three" (line 2216) vs. "two" elsewhere (line 2154) | **Confirmed: exactly two models ever evaluated anywhere** (`logistic_regression`, `random_forest`); no third model in code, config, or results | `results/evaluation/model_metrics.csv`, `configs/evaluation.yaml`, repo-wide grep for xgboost/svm/neural/gradient-boosting: zero hits | — | Fix "three" to "two" (or add and evaluate a genuine third model, but nothing suggests one was ever intended) | Trivial |

---

## Critical architecture findings

### Is compSim redundant? — Yes, mathematically confirmed for the implemented code.

The implementation's own module docstring (`src/fairlend/audit/similarity.py:1-16`) already states the representation precisely:

```
HE.g_i = (HE.Enc(g_i,m), HE.Enc(g_i,f))   -- ONE CKKS ciphertext, 2 SIMD slots
HE.r_m = (HE.Enc(1), HE.Enc(0))
HE.r_f = (HE.Enc(0), HE.Enc(1))
compSim(HE.g_i, HE.r_k) = sum_j HE(g_i,j) (x) HE(r_k,j)
```

For `k = m`: `compSim(HE.g_i, HE.r_m) = HE(g_i,m)·HE(1) + HE(g_i,f)·HE(0) = HE(g_i,m) + 0 = Enc(g_i,m)`.
For `k = f`: `compSim(HE.g_i, HE.r_f) = HE(g_i,m)·HE(0) + HE(g_i,f)·HE(1) = Enc(g_i,f)`.

This is an algebraic identity given the reference vectors' definition — it holds regardless of CKKS noise, and is exactly Reviewer #2's claim. The code performs two real ciphertext-ciphertext multiplications and one addition per call (`male_score = g_i.dot(references.male)`, `similarity.py:286-287`) to recover a value (`g_i,m`, `g_i,f`) that is already sitting in the credential's own ciphertext slots before any multiplication. `fairlend.audit.aggregation.compute_encrypted_audit` (`aggregation.py:436-453`) then homomorphically **adds** that recovered value into six group accumulators per group — i.e., the entire pipeline downstream of compSim is plain encrypted-additive aggregation, exactly as the reviewer states.

**Precise code that establishes this is redundant** (not changed in this audit): `src/fairlend/audit/similarity.py::comp_sim` (lines 239-288) and its two call sites in `src/fairlend/audit/aggregation.py::compute_encrypted_audit` (line 437: `pair = comp_sim(...)`). A functionally equivalent replacement would accumulate the credential's own 2-slot ciphertext directly (`accumulator["C"] += g_i` as a single 2-slot running sum, decrypted once at the end into `(C_m, C_f)`), which is a ciphertext-ciphertext **addition only** — multiplicative depth 0, no relinearisation, no rescale, and no reference vectors needed at all.

**Multiplicative depth actually measured**: exactly 1 (confirmed empirically in the codebase's own docstring, `similarity.py:50-56`, and consistent with the manuscript's Sec. 4.8 claim) — this depth exists *only* because of the unnecessary compSim multiplication, not because the underlying aggregation needs it.

**Does the implementation support >2 categories or packed multi-attribute vectors?** No. `GENDER_VECTOR_SIZE = 2` (`similarity.py:110`), `GROUPS = (GROUP_MALE, GROUP_FEMALE)` (`aggregation.py:114`) are hard-coded throughout; `MALE_ONE_HOT`/`FEMALE_ONE_HOT` (`identity_provider.py:38-39`) are the only two encodings the IP ever issues. Extending to >2 categories would require new code, not a configuration change.

**Recommendation (evidence-based, not a redesign)**: Reviewer #2's second suggested remedy — "if retained, plaintext reference masks would avoid relinearisation and one level" — is *also* achievable with less change than a full rewrite: replacing `HE.r_m`/`HE.r_f` (currently CKKS-**encrypted** vectors, `similarity.py:182-183`, `ts.ckks_vector(fla_context, list(MALE_REFERENCE))`) with **plaintext** vectors would turn the ciphertext-ciphertext multiply into a ciphertext-plaintext multiply, which still needs the plaintext masking machinery but drops one operand's ciphertext status — this is a smaller change than removing compSim altogether, and would be the natural implementation companion to a "removed one level" manuscript claim if the authors choose that path over outright removal. Neither option was implemented in this audit, per instructions.

### Is CKKS technically necessary for any operation currently performed?

No operation in the *actually executed* pipeline requires CKKS's approximate/real-number arithmetic:
- The protected-attribute payload is always exactly `0.0` or `1.0` (one-hot).
- Every released quantity is an integer count (`C, A, P, TP, N, FP`), rounded after decryption (`aggregation.py:547-548`, `Round()` in the manuscript's Algorithm 7).
- The only real-valued outputs anywhere are the raw (unrounded) CKKS diagnostic values (`DP_raw_ckks`, `EO_raw_ckks` in the JSON results above), which exist purely to measure CKKS's own approximation error — i.e. they are evidence CKKS's real-number capability is not being used for anything the protocol needs, only incurred as overhead.

**Can every encrypted quantity be represented as an integer count under BFV/BGV?** Yes, based on the evidence above: one-hot slots, additive accumulation, and integer-count outputs are exactly BFV/BGV's native domain (batched integer arithmetic mod a plaintext modulus), and would eliminate the entire "rounding after decryption" step and the associated approximation-error discussion Reviewer #2 flags in point 2. No BFV/BGV branch or experiment exists anywhere in this repository (`grep` for `SCHEME_TYPE.BFV`/`BGV`: zero hits) — this would be new work, not a rerun.

**Would switching to BFV/BGV alter the scientific contribution?** No. The *architecture* (LPU/FLA split, credential issuance, aggregate-only disclosure, DP/EO computation) is scheme-agnostic; only `src/fairlend/crypto/ckks.py`, `secure_compute/ckks.py`, and the `comp_sim`/aggregation ciphertext calls would need a different TenSEAL/SEAL context type. The fairness/matching/reconstruction *logic* is unchanged.

**Would it require rerunning all experiments, or only cryptographic/runtime ones?** Only cryptographic and runtime/serialization experiments would need rerunning: the CKKS-specific numbers (compSim timing, serialization sizes, aggregate-decryption runtime, the raw-CKKS-error diagnostic) would all change under BFV/BGV. The *plaintext* experiments (proxy AUC, DP/EO sensitivity sweep, model training/selection, matching-fidelity ground truth) are entirely independent of the HE scheme and would **not** need rerunning — they never call any `fairlend.crypto`/`fairlend.secure_compute` code (confirmed: `evaluation/run_alpha1_seed_sensitivity.py` and `fairlend.audit.alpha_seed_sensitivity` never import `tenseal`).

---

## Existing-result inventory

All paths relative to repo root. None of these were modified or overwritten during this audit.

| Result | Path |
|---|---|
| Dataset provenance (SHA-256, row/column counts, period filter) | `results/evaluation/dataset_summary.json`, `results/metadata/dataset_manifest.json` |
| Train/validation/test split, resolved/unresolved counts | `results/evaluation/split_summary.json` |
| Model hyperparameters, VALIDATION-selected threshold (both policies) | `results/evaluation/model_metrics.csv`, `threshold_policy_sensitivity.csv` |
| Frozen predictions (default + primary policy) | `results/evaluation/model_predictions.parquet`, `{lr,rf}_balanced_accuracy_predictions.parquet` |
| Primary-policy plaintext fairness results (DP/EO, full C/A/P/TP/N/FP) | `results/evaluation/primary_policy_results.{csv,json}` |
| Encrypted-audit per-stat reconstruction (12/12 exact, both models) | `results/evaluation/{lr,rf}_balanced_accuracy_encrypted_audit.json` + `_run_meta.json` |
| Fairness reconstruction (e_DP, e_EO, raw-CKKS diagnostic) | `results/evaluation/{lr,rf}_balanced_accuracy_fairness_reconstruction.json` |
| Matching fidelity (delta*, accuracy, macro-F1, MAE) — real data, 1 realisation | `results/evaluation/matching_fidelity_{runs,summary}.csv`, `matching_threshold.json` |
| Alpha1 × seed sensitivity — 50 configs × 2 models, plaintext only | `results/evaluation/alpha1_seed_sensitivity_{runs,summary}.csv` |
| Runtime — raw + summary (1,320 observations, batch 1-1000) | `results/benchmarks/runtime_{raw,summary}.csv` |
| Serialization — measured (16 objects) and analytical (2 formulas) | `results/benchmarks/serialization_{measured,analytical}.csv` |
| Communication paths + derived projections | `results/benchmarks/communication_summary.csv` |
| Benchmark hardware/software environment | `results/metadata/benchmark_environment.json` |
| Fixture-scale (38-row) cross-check of all of the above | `results/fixture_validation/evaluation/*` |
| Structural privacy/security guarantees (test-verified, not asserted) | `tests/scientific/test_{key_separation,key_ownership,encrypted_aggregation,encrypted_aggregation_privacy,no_leakage,gender_exclusion}.py` |

Re-running a targeted subset directly relevant to this audit (`test_similarity.py`, `test_encrypted_aggregation.py`, `test_encrypted_aggregation_privacy.py`, `test_key_separation.py`) in this session: **60 passed, 2 skipped, 0 failed** (46.4s). The **full test suite** (`tests/`, all unit + scientific + integration tests) was also run in this session: **489 passed, 2 skipped, 0 failed, 243.03s** (`PYTHONPATH=src python3 -m pytest tests/ -q`). This confirms every structural/privacy/fidelity guarantee the codebase claims to test (key separation, no per-record decryption, packet field enumeration, leakage checks, threshold-policy determinism, primary-policy provenance, alpha/seed-sensitivity invariants) currently holds on this checkout. The 2 skipped tests were not investigated further (not required for this audit's conclusions).

---

## Missing experiments (minimum needed to fully satisfy Reviewer #2)

1. **NIZKP instantiation** — pick one concrete proof system (e.g. Groth16 over BN254 via `arkworks` or `snarkjs`/`circom`) and implement `Setup`/`Prove`/`Verify` for at least `R_acc` (simplest relation: knowledge of an opening of a hash/Pedersen commitment). Report constraint count, proof size, setup/proving/verification time. This is the only item with zero existing partial evidence.
2. **Encrypted-fidelity sensitivity subset** — execute the already-pre-declared 9-configuration subset (`alpha1 ∈ {0.0, 0.7, 1.3} × seed ∈ {0, 5, 9}`, LR only, per `docs/MANUSCRIPT_EVIDENCE_STATUS.md`'s own plan) to extend the single-configuration encrypted reconstruction result to a real robustness claim. Estimated ≈33 hours compute (LR-only) at this environment's measured throughput.
3. **CKKS vs. BFV/BGV comparison run** (if the authors choose migration over justification-only) — reimplement `fairlend.crypto.ckks`/`secure_compute.ckks` and the two call sites in `similarity.py`/`aggregation.py` for BFV or BGV, then re-measure compSim/aggregation runtime and serialization sizes only (plaintext experiments are unaffected, per Critical Findings above).
4. **Figure 3/4 regeneration** — no source script for `Computation-cost.png`/`communication-cost.png` exists in this repo; regenerate both from `results/benchmarks/runtime_summary.csv` and `communication_summary.csv` (data already exists; only the plotting step is missing).
5. **Re-run at a clean commit** — the current tracked real-data results were produced with `git_dirty=true`; before citing exact figures in a submitted revision, reproduce them at a tagged, clean commit so the provenance metadata (`git_commit`, `git_dirty`) in each JSON is citable as-is.

---

## Recommended revision sequence (minimises unnecessary reimplementation)

1. **Text-only fixes first (trivial effort, zero new experiments)**: fix the "three"→"two" models inconsistency, delete the duplicate 6.5.4 error-definition block, reconcile the funding statement, trim/justify the self-citations, add the Sec. 3.5 IP-plaintext-gender sentence, add the EO-coverage fraction (93.45%) to Sec. 6.5.3.
2. **Incorporate already-existing numeric results (trivial-to-small effort)**: replace Sec. 6.1.2/6.1.3/6.5.4's "we do not report..." disclaimers with the real proxy-AUC and alpha1/seed sensitivity table (`alpha1_seed_sensitivity_summary.csv`), and the real e_DP=e_EO=0.0 reconstruction result, explicitly scoped to the one measured encrypted configuration. Replace Table 8 with the measured serialization CSV, and regenerate Fig. 3/4 from the runtime/communication CSVs.
3. **Decide compSim's fate (small-to-moderate effort, no new crypto)**: this is a writing decision informed by Section "Critical architecture findings" above — either rewrite 4.8/6.1.2/6.4 around plain encrypted-additive aggregation (recommended given the math above shows no loss of generality for the binary case), or commit to a multi-category extension and schedule it as new implementation work (item 3 below).
4. **Run the pre-declared 9-config encrypted-fidelity subset (major effort, compute-bound, no design work)**: this directly answers Reviewer point 3's "repeated-seed" request for the *encrypted* path (the plaintext path is already done) and requires no new code.
5. **NIZKP instantiation (major effort, new implementation)**: the one item that cannot be shortcut by reusing existing artifacts. Do this last, and independently of 1-4, since it does not block any of the other fixes.
6. **CKKS→BFV/BGV migration (major effort, optional)**: only pursue if the authors want to eliminate the approximation-error discussion entirely rather than justify CKKS's use with smudging/IND-CPA^D language; per the Critical Findings, this only requires rerunning cryptographic/runtime experiments, not the plaintext fairness pipeline.
7. **Compile and proofread (blocked in this environment)**: verify pagination, Algorithm 6 rendering, and the guard-condition logic (`v_acc ∧ v_score ∧ v_bind ∧ v_gender ≠ 1`) in the authors' own LaTeX environment — no `pdflatex`/`bibtex`/`tectonic`/TeX Live is installed here, so this could not be checked in this audit. Note: the executable code has **no corresponding composite guard at all** — `LoanProcessingUnit` exposes only three independent `verify_*_credential` methods (`src/fairlend/roles/lpu.py:104-138`), each called separately in `evaluation/run_benchmarks.py:182-192`; there is no code path that ANDs all four checks together the way Algorithm 6 does, so the pseudocode's exact intended precedence cannot be cross-checked against a running implementation and must be resolved by the authors directly (most likely intended reading: `¬(v_acc ∧ v_score ∧ v_bind ∧ v_gender)`, i.e. reject unless all four hold).
