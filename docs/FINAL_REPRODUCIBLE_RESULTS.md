# FairLend: Final Reproducible Results

**Evidence mode: IMPLEMENTATION-FIRST.** Every number in this document is
an OBSERVED RESULT from the rebuilt `src/fairlend` implementation, its
tests, and its tracked result artifacts (see
`docs/RESULT_ARTIFACT_INDEX.md` for the exact source file behind every
figure below) — not a manuscript value, and not tuned or selected to
approximate one. Where a rebuilt measurement disagrees with the original
manuscript, the rebuilt measurement is what is reported here; manuscript
comparisons live separately in `docs/MANUSCRIPT_EVIDENCE_STATUS.md` as
audit metadata, not as a target this document tries to hit.

Every claim below is tagged as one of:

- **Observed result** — a number produced by running the implementation.
- **Implementation choice** — a decision made in this codebase where the
  manuscript does not specify a concrete value/algorithm (documented in
  full in `docs/MANUSCRIPT_EVIDENCE_STATUS.md`).
- **Security guarantee** — a structural property enforced and verified by
  code/tests, not merely asserted in prose.
- **Limitation** — something this evidence base does NOT yet establish.

---

## 1. Dataset, Version, Hash

| | |
|---|---|
| Source | LendingClub Loan Data, `accepted_2007_to_2018Q4.csv` |
| **Dataset SHA-256** | `3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a` |
| Raw rows / columns | 2,260,701 / 151 |
| Manuscript period filter (2007–2015) applied | *Implementation choice* (Sec. 6.1.1 names the period; the exact filter mechanics are this codebase's own, see `fairlend.data.lendingclub_schema.filter_to_issue_year_range`) |
| **Cleaned/audit-eligible population** | **887,440** — *Observed result* (manuscript states "approximately 890,000"; not forced to match) |
| Model-eligible (resolved-outcome) population | 829,355 — *Observed result* |
| Unresolved-outcome population | 58,085 — *Observed result* |

## 2. Experimental Configuration

| | |
|---|---|
| Split | 70% train / 10% validation / 20% test, seed=42 — *Implementation choice* |
| Train (audit) / Validation / Test population | 621,207 / 88,744 / 177,489 — *Observed result* |
| Resolved / unresolved TEST | 165,872 / 11,617 — *Observed result* |
| Protected attribute | SYNTHETIC (never observed gender), `alpha0=0.0`, primary `alpha1=0.7`, `seed=0` — *Implementation choice* per manuscript Sec. 6.1.1's framework |
| Primary threshold policy | `validation_balanced_accuracy_max` — *Implementation choice* (manuscript specifies the decision rule shape `Y-hat=I[s>=tau]` but not a tau-selection algorithm; this policy was chosen for being standard, class-imbalance-robust, and VALIDATION-only — never because it produced a larger fairness gap) |
| CKKS configuration | `poly_modulus_degree=8192`, `coeff_mod_bit_sizes=[60,40,40,60]`, `global_scale=2^40` — *Implementation choice matching the manuscript's stated parameters* |

## 3. Model Settings

| Model | Hyperparameters | Selection | Frozen tau (primary policy) |
|---|---|---|---|
| Logistic Regression | `{"C": 0.01}` | VALIDATION ROC-AUC | **0.80** |
| Random Forest | `{"max_depth": 8, "n_estimators": 100}` | VALIDATION ROC-AUC | **0.80** |

*Implementation choice*: feature list is `fairlend.data.credit_features.CREDIT_MODEL_FEATURES` (dti, emp_length_years, home_ownership_indicator, log1p_annual_inc, south_region_indicator) — not a manuscript enumeration. Both models were fit ONCE and never refit for any downstream stage (Stages 2–4, Phase 10 all reuse the same frozen `y_proba`).

## 4. Primary Fairness Results — *Observed result*

| | Logistic Regression | Random Forest |
|---|---|---|
| tau | 0.80 | 0.80 |
| Approval count / rate | 116,998 / 0.6591845128430495 | 117,481 / 0.6619058082472716 |
| C_m / C_f | 88,203 / 89,286 | 88,203 / 89,286 |
| A_m / A_f | 58,170 / 58,828 | 58,824 / 58,657 |
| P_m / P_f | 67,790 / 67,469 | 67,790 / 67,469 |
| TP_m / TP_f | 46,309 / 46,363 | 46,867 / 46,214 |
| N_m / N_f | 15,219 / 15,394 | 15,219 / 15,394 |
| FP_m / FP_f | 8,607 / 8,641 | 8,706 / 8,598 |
| **DP (plaintext)** | **0.0006298858929396633** | **0.009959793549564666** |
| **EO (plaintext)** | **0.0042204779429118044** | **0.013518800643769757** |

No manuscript figure (e.g. the `2.1e-5` reconstruction-error claim) was
targeted, approximated, or used to select these values — they are exactly
what the frozen models/thresholds produce on the real held-out TEST
population.

## 5. Matching Fidelity — *Observed result*

| | |
|---|---|
| delta* (selected from VALIDATION only) | 0.95 |
| Validation / Test population | 88,744 / 177,489 |
| **Accuracy** | **1.0** |
| **Macro-F1** | **1.0** |
| **Unmatched rate** | **0.0** |
| Expected-1 MAE / max abs error | 2.257295e-07 / 2.543669e-07 |
| Expected-0 MAE / max abs error | 3.604238e-07 / 3.857790e-07 |
| Runtime | 7819.66 s (34.05 rec/s, one cryptographic realisation, `run_id=cd08706ed9b4428fb232b89a7ac9d1b1`) |

## 6. Encrypted Reconstruction Results — *Observed result*

**24 of 24** rounded decrypted aggregate counts (12 per model × 2 models) equal their plaintext counterparts exactly — independently re-verified in Stage 4's consolidation, not merely asserted once.

| | Logistic Regression | Random Forest |
|---|---|---|
| DP encrypted (rounded-count path) | 0.0006298858929396633 | 0.009959793549564666 |
| **e_DP** | **0.0** | **0.0** |
| EO encrypted (rounded-count path) | 0.0042204779429118044 | 0.013518800643769757 |
| **e_EO** | **0.0** | **0.0** |
| DP_raw_ckks (unrounded diagnostic, NOT the production value) | 0.0006298858984409295 | 0.009959788873538211 |
| EO_raw_ckks (unrounded diagnostic) | 0.004220477964846814 | 0.013518794321547123 |
| Max / mean aggregate abs error (pre-rounding) | 0.011686 / 0.006217 | 0.053588 / 0.028708 |
| Rounding safety margin (0.5 − max abs error) | 0.488314 | 0.446412 |
| Runtime | 5273.05 s (33.66 rec/s) | 5641.28 s (31.46 rec/s) |

**Security guarantees, verified structurally (not merely documented):**
- LPU never possessed `sk_HE` (`context_can_decrypt(lpu_context) == False`, checked at every encrypted-computation call site).
- No per-record decryption ever occurred — only ONE final aggregate packet was decrypted, by the FLA, per model.
- `EncryptedAuditPacket` carries no per-record field of any kind (exhaustively enumerated by `tests/scientific/test_encrypted_aggregation_privacy.py`).

## 7. Sensitivity Results (alpha1 × seed) — *Observed result*

50 configurations (alpha1 ∈ {0.0, 0.4, 0.7, 1.0, 1.3} × seed ∈ {0..9}) × 2 models = 100 plaintext rows, computed in 80.57s. No CKKS anywhere in this sweep; no mean/std was adjusted toward any external target.

| alpha1 | proxy AUC (mean±std) | LR DP (mean±std) | LR EO (mean±std) | RF DP (mean±std) | RF EO (mean±std) |
|---|---|---|---|---|---|
| 0.0 | 0.5005 ± 0.0009 | 0.001810 ± 0.001452 | 0.004815 ± 0.005459 | 0.001913 ± 0.001525 | 0.005282 ± 0.005703 |
| 0.4 | 0.6101 ± 0.0012 | 0.002224 ± 0.001642 | 0.006239 ± 0.004559 | 0.005566 ± 0.002168 | 0.007390 ± 0.003804 |
| 0.7 | 0.6830 ± 0.0010 | 0.002042 ± 0.001395 | 0.006948 ± 0.003392 | 0.009087 ± 0.001830 | 0.012500 ± 0.004640 |
| 1.0 | 0.7440 ± 0.0009 | 0.002975 ± 0.002068 | 0.008808 ± 0.002539 | 0.011040 ± 0.001873 | 0.016099 ± 0.005555 |
| 1.3 | 0.7927 ± 0.0007 | 0.005822 ± 0.001983 | 0.011070 ± 0.001822 | 0.011488 ± 0.002205 | 0.017804 ± 0.005712 |

**alpha1=0 negative control** (*Observed result*): `probability_female == 0.5` exactly for every one of 887,440 records (verified at generation time, not merely observed after). Proxy AUC 0.5005±0.0009 (chance-level). Small nonzero DP/EO at alpha1=0 are finite-sample noise, not a discovered signal.

**Regression check** (*Observed result*): the `alpha1=0.7, seed=0` configuration independently reproduced Section 4's primary DP/EO values bit-for-bit for both models — verified programmatically, not asserted.

**Seed variability** (*Observed result*): protected-group balance is highly stable across seeds (`female_fraction` std ≤ 0.0005 at every alpha1); DP/EO are considerably less stable, especially at low alpha1 (e.g. LR EO at alpha1=0.0 has std larger than its own mean) — a single-seed DP/EO reading should not be treated as a stable per-model constant.

## 8. Runtime Benchmark — *Observed result* (MEASURED, not manuscript-derived)

Full real-data application runs (NOT rerun for benchmarking — reported separately from the controlled microbenchmarks below):

| Full real-data run | Runtime | Records | Throughput |
|---|---|---|---|
| Matching fidelity | 7819.66 s | 266,233 | 34.05 rec/s |
| LR encrypted aggregation | 5273.05 s | 177,489 | 33.66 rec/s |
| RF encrypted aggregation | 5641.28 s | 177,489 | 31.46 rec/s |

Controlled microbenchmarks (batch=1 mean, `time.perf_counter_ns()`, 30 repeats after warm-up; full batch-size grid 1–1000 in the raw/summary CSVs):

| Operation | Mean (batch=1) |
|---|---|
| FLA context generation | 173.2 ms |
| LPU context derivation | 174.9 ms |
| Encrypted reference generation | 12.8 ms |
| Bank / CA credential issuance | 0.045 ms / 0.044 ms |
| IP protected-attribute credential issuance | 6.92 ms |
| compSim | 12.70 ms |
| Aggregate ciphertext update (12 adds/record) | 56.78 ms |
| Aggregate packet serialization | 7.19 ms |
| FLA aggregate deserialization (12 ciphertexts) | 5.00 ms |
| Aggregate decryption (12 ciphertexts) | 17.61 ms |
| DP / EO calculation | 5.75 µs / 6.56 µs |

## 9. Serialization / Communication Measurements

**MEASURED** (actual `len()` on real serialized bytes — *Observed result*):

| Object | Measured bytes |
|---|---|
| Fresh CKKS scalar (full 4-modulus chain) | 331,540 |
| IP protected-attribute ciphertext (packed one-hot pair) | 331,060 |
| One EncryptedSimilarityPair | 470,187 |
| Complete EncryptedAuditPacket (12 ciphertexts + metadata) | 5,642,620 (canonical-JSON, hex-encoded) / ~2,821,330 (raw ciphertext-byte sum) |
| LPU public/evaluation context | 35,291,733 |
| Galois key material (isolated) | 33,432,117 |
| Ed25519 public key | 32 |

**ANALYTICAL** (formula over CKKS parameters ONLY — never adjusted to match measured — *Implementation choice of estimation method*): fresh ciphertext, full 4-modulus chain = 425,984 bytes (vs. measured 331,540 — a disclosed -22.2% gap from omitted SEAL/TenSEAL container overhead, not an error to reconcile).

**DERIVED** (communication projections, serialized-payload-size arithmetic — NEVER a network measurement):

| n applications | Projected total bytes |
|---|---|
| 1 | 42,922,305 |
| 100 | 174,136,905 |
| 1,000 | 1,366,996,905 |
| 10,000 | 13,295,596,905 |
| 100,000 | 132,581,596,905 |

## 10. Limitations

- **One cryptographic realisation per encrypted stage** on real data — Stages 2/3/matching each ran once, not repeated for a systematic CKKS-error distribution (Stage 1's fixture-scale 10-realisation diagnostic is the only repeated-realisation evidence in this codebase).
- **No encrypted-fidelity coverage across the alpha1×seed grid** — the 50-configuration sensitivity sweep (Sec. 7) is plaintext-only; a predeclared 9-configuration encrypted subset was proposed (alpha1∈{0,0.7,1.3}×seed∈{0,5,9}, estimated ≈32.7 hours) but explicitly NOT executed.
- **NIZKP relations are not implemented** — no `prove()`/`verify_nizkp()` exists; "loan-application packet construction" and per-application proving/verification costs have no measured or implemented counterpart.
- **No operational-encryption layer** — Bank/CA credentials are SIGNED, not encrypted; any manuscript figure describing an "operational ciphertext" has no implementation counterpart to measure.
- **`fairness.minimum_cell_size`** (a production disclosure/suppression policy) remains unconfigured (`None`) by design — no minimum-cell-size recommendation is made here.
- **No network transmission was measured** — every communication figure is a serialized-payload byte count, never a latency/bandwidth measurement.
- **The manuscript's `2.1e-5` fairness-reconstruction-error figure is neither confirmed nor contradicted** — this implementation's production reconstruction error is exactly 0.0 (a different quantity: exact rounded-count agreement, not a continuous approximation error), and its raw-CKKS diagnostic error is a per-run-randomised quantity, not comparable to a single fixed constant without repeated independent runs (see Limitation above).
