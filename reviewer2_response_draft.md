# Response to Reviewer #2 (DRAFT — NOT FINAL)

**Status of this draft: incomplete by design.** One subsection (the repeated-seed BFV encrypted reconstruction over the nine pre-declared real-data configurations) carries an explicit internal placeholder, `[INSERT 9-CONFIG BFV REAL-DATA RESULTS AFTER DATASET RUN]`, because that experiment has not been run — the raw LendingClub CSV is not present in the evaluation environment. This draft must not be sent to the reviewer, and the manuscript must not be described as "submission ready," until (1) that experiment is run and its real numbers replace the placeholder, (2) the authors confirm the correct funding source(s), and (3) the manuscript is compiled to a final PDF and its pagination/Algorithm 6 rendering is checked. See `reviewer2_final_readiness.md` for the full status breakdown.

Classification legend used throughout: **FULLY ADDRESSED** / **PARTIALLY ADDRESSED — WAITING FOR BFV 9-CONFIG RUN** / **AUTHOR ACTION REQUIRED** / **FINAL PDF CHECK REQUIRED** / **NOT REQUIRED FOR REVIEWER SATISFACTION**.

---

We thank Reviewer #2 for a careful and constructive second-round review. The review correctly identified that our previous revision had resolved overclaiming by withdrawing evidence rather than strengthening it, and — more importantly — that the compSim construction the earlier revision's depth analysis was built around is mathematically redundant. Both observations are correct, and this revision responds to them directly rather than defensively: we have removed compSim from the active protocol, migrated the active protected-attribute aggregation path from CKKS to BFV, restored a coherent quantitative evaluation using only real, traceable measurements, and implemented and benchmarked a concrete NIZKP instantiation. We address each point below.

---

## Comment 1 — compSim is degenerate

> "With the reference vectors defined as HE.r_m = (Enc(1), Enc(0)) and HE.r_f = (Enc(0), Enc(1)) (Algorithm 1), the inner product returns Enc(g_i,m) and Enc(g_i,f) - the coordinates of the one-hot ciphertext the LPU already holds. Accumulating HE.g_i directly in Algorithm 6 gives identical results at depth zero. [...] Please justify the similarity computation [...] or remove it and rewrite Sections 4.8, 6.1.2 and 6.4 around the aggregation. If retained, plaintext reference masks would avoid relinearisation and one level."

**Status: FULLY ADDRESSED**

**Response.** The reviewer is correct, and we thank them for the precise algebraic argument. We independently re-derived the identity `compSim(HE.g_i, HE.r_m) = HE(g_i,m)` and confirmed it holds unconditionally given our one-hot representation, exactly as the reviewer states. We chose the reviewer's first option — remove compSim and rewrite the affected sections around direct encrypted-additive aggregation — rather than the "plaintext reference mask" alternative also offered, because removing compSim eliminates *all* multiplicative-depth cost and *all* reference-vector material (not merely relinearisation), and no part of our aggregation logic requires anything more than ciphertext addition. Encrypted additive aggregation is now presented as exactly what it is, with no similarity computation, no reference vectors, no matching threshold, and no matching-fidelity claim anywhere in the active protocol.

**Changes in manuscript.**
- Former Algorithm 1 (Initialisation): no longer generates or transmits `HE.r_m`/`HE.r_f` (Section "Initialisation", `subsec:init`).
- Former Algorithm 6 (Secure Loan Processing): rewritten to accumulate `HE.g_i` directly into six flat aggregates (`HE.C, HE.A, HE.P, HE.TP, HE.N, HE.FP`), each a single BFV ciphertext with two SIMD slots; no reference-vector comparison anywhere (Algorithm "Secure Loan Processing and Encrypted Audit Aggregation").
- Former Section 4.8: renamed "Protected-Attribute Encoding and a Superseded Similarity Design"; contains the exact degeneracy identity the reviewer states, and explicitly marks compSim, the similarity threshold `delta`, and the matched/unmatched classification as *not part of the active protocol*.
- Former Section 6.1.2: renamed "Encrypted Protected-Attribute Reconstruction Criteria"; replaces the similarity-based matching criteria with the active BFV exactness criterion `e(S_k) = |S_k^BFV - S_k^plain|`, no epsilon tolerance.
- Former Section 6.4: renamed "Encrypted Protected-Attribute Matching Fidelity (Superseded compSim Design)"; retained only as historical evaluation context for the removed design, with an explicit statement that it has no counterpart in the active protocol.
- New subsection "Three Evaluated Aggregation Architectures" makes the legacy CKKS+compSim / CKKS-direct / BFV-direct distinction explicit throughout the paper, so no claim is ever ambiguous about which construction produced it.

**Evidence.** `src/fairlend/audit/aggregation.py` (`compute_encrypted_audit`, direct ciphertext addition, no `comp_sim` call in the active path); `tests/scientific/test_encrypted_aggregation_direct.py` (22 tests) and `test_encrypted_aggregation_bfv.py` (32 tests), all exact-equality; `reviewer2_phase1_compsim_removal_report.md`, `reviewer2_phase2_bfv_migration_report.md`.

---

## Comment 2 — Use of CKKS

> "All aggregated quantities are integer counts, rounded after decryption (Algorithm 7); BFV/BGV or Paillier would give exact counts and remove the approximation-error discussion. Relatedly, Theorem 1 invokes IND-CPA, but the FLA decrypts and releases aggregates and Section 6.4 decrypts per-record similarities. The applicable notion is IND-CPA^D [...]. Please justify the scheme choice, and either add smudging [...] or restate the theorem so it excludes settings where decryptions are exposed."

**Status: FULLY ADDRESSED**

**Response.** We agree that CKKS was the wrong scheme for a workload whose every aggregated quantity is an integer count with no legitimate use for real-number approximation. We migrated the active protected-attribute aggregation path to BFV. Aggregate decryption is now exact, with no rounding step, which removes the approximation-error discussion the reviewer's IND-CPA$^D$ concern was about — not by adding smudging to CKKS, but by removing the source of approximation entirely. We also restated Theorem 1 narrowly, as the reviewer's second option invites: it now covers only the LPU's view (which, under the active construction, never decrypts anything derived from the protected attribute and therefore needs only standard IND-CPA), and we added a dedicated discussion of why the FLA's aggregate-decryption role — the one the reviewer specifically flagged — is a materially different situation, addressed on its own terms rather than folded into Theorem 1's LPU-facing claim.

**Changes in manuscript.**
- Active protocol migrated to BFV throughout Section 4 (Initialisation, Algorithm 6, Algorithm 7/Fairness Audit); BFV parameters justified from the workload (not copied) in the new "BFV Parameters" subsection, including the signed-decoding safe-count bound we verified empirically ($[0, 16{,}916{,}480]$, half of the naive unsigned range).
- Theorem 1 ("Protected-Attribute Confidentiality Claim") rewritten: covers LPU-facing confidentiality only, explicitly does not claim IP confidentiality, "aggregates reveal nothing," or collusion resistance; proof sketch explains the LPU never decrypts (plain IND-CPA suffices) and cross-references the separate FLA-facing discussion.
- New subsection on IND-CPA/IND-CPA$^D$ (within "Composition, Disclosure, and Collusion Limits"): explains the CKKS-specific approximate-decryption concern the reviewer raised, explains why BFV's exactness removes this *specific* side channel (no approximation-error pattern to leak, because decryption is exact), and explicitly states this does **not** mean BFV eliminates the aggregate disclosure itself — the FLA still learns exactly the six released statistics by design, which is intentional, not a side effect.
- Section "Encrypted Protected-Attribute Matching Fidelity" (former Section 6.4), where the reviewer's "decrypts per-record similarities" concern originated, is now explicitly scoped as describing only the superseded compSim design; the active protocol never decrypts a per-record value of any kind.

**Evidence.** `src/fairlend/crypto/bfv.py`, `src/fairlend/core/config.py` (`BFVConfig.max_safe_count`); `tests/scientific/test_encrypted_aggregation_bfv.py::test_count_at_exactly_the_safety_bound_decrypts_as_itself`; `reviewer2_phase2_bfv_migration_report.md`.

---

## Comment 3 — Evaluation withdrawn, not corrected

> "Tables 5-7 are gone and Section 6 now disclaims numerical results for matching fidelity, proxy AUC, robustness and reconstruction; the only surviving measurement, Figure 3, is unchanged from the original submission. [...] Cheap remedies: the proxy-inference AUC of Section 6.1.3; the reconstruction errors of Section 6.5.4 over the seeds and alpha_1 values already specified in Section 6.1.1; measured rather than estimated serialised sizes; and at least one concrete NIZKP instantiation with constraint counts and proving/verification times, without which the integrity layer and Table 9 remain unvalidated."

**Response.** We agree the previous revision under-corrected by withdrawing evidence. This revision restores a coherent, quantitative evaluation, built entirely from real, traceable measurements — no number in the revised manuscript is invented, estimated in place of a measurement, or borrowed from an architecture other than the one it is attributed to. We address the reviewer's four specific "cheap remedies" in turn, plus the underlying request for a validated NIZKP integrity layer.

### 3a. Proxy-inference AUC

**Status: FULLY ADDRESSED**

Measured test AUC of a proxy classifier trained on only the non-sensitive proxy features, evaluated at all five specified $\alpha_1$ values and averaged over ten seeds, is now reported (e.g., $0.6830\pm0.0010$ at the primary setting $\alpha_1=0.7$). Source: `results/evaluation/alpha1_seed_sensitivity_summary.csv`; manuscript Table "Plaintext demographic-parity/equalised-odds sensitivity..." and the "Proxy-Discrimination Diagnostic" subsubsection.

### 3b. Reconstruction errors over seeds and $\alpha_1$

**Status: PARTIALLY ADDRESSED — WAITING FOR BFV 9-CONFIG RUN**

The plaintext side of this request is fully satisfied: demographic-parity and equalised-odds gaps are reported for both evaluated decision models across all $5\times10=50$ $(\alpha_1,\text{seed})$ configurations (Table "Plaintext demographic-parity/equalised-odds sensitivity..."), independent of the encryption scheme.

The *encrypted* reconstruction side is satisfied at one real-data configuration and at fixture scale, but not yet at the full pre-declared 9-configuration subset ($\alpha_1\in\{0.0,0.7,1.3\}\times\text{seed}\in\{0,5,9\}$) under the active BFV construction:
- At controlled/fixture scale, BFV reconstruction is exact ($e(S_k)=0$ for all 24 measured (group, statistic) combinations, both models).
- At real-data scale (177,489-record TEST population), one configuration ($\alpha_1=0.7$, seed 0, $\tau=0.80$) has been evaluated end-to-end, under the *superseded* legacy CKKS+compSim construction (predating this revision's BFV migration): the maximum raw CKKS decryption error was 0.0117 (LR)/0.0537 (RF), several orders of magnitude below the 0.5 rounding boundary, giving exact reconstruction ($e_{\mathrm{DP}}=e_{\mathrm{EO}}=0.0$) after rounding, for both models.
- The nine-configuration real-data experiment under the *active* BFV construction is specified, its orchestrator implemented and tested, and blocked solely on the absence of the raw LendingClub CSV in our current evaluation environment. It has not been run, and no number is fabricated to fill the gap:

  `[INSERT 9-CONFIG BFV REAL-DATA RESULTS AFTER DATASET RUN]`

  This placeholder is removed and replaced with real measured values (or, if a discrepancy is found, an honest account of it) as soon as the dataset is restored and `evaluation/run_bfv_9config_encrypted_fidelity.py` completes.

Source: `results/evaluation/alpha1_seed_sensitivity_{runs,summary}.csv` (plaintext, 50 configs); `results/evaluation/primary_policy_results.csv` (1 real-data config, legacy CKKS); `results/fixture_validation/evaluation/ckks_vs_bfv_equivalence.csv` (BFV, fixture scale).

### 3c. Measured (not estimated) serialised sizes

**Status: FULLY ADDRESSED**

Figures 3 and 4 are regenerated from real measured artifacts (`figures/generate_manuscript_figures.py`, reading only tracked CSVs), reporting application-packet and aggregate-audit-packet sizes on a consistent raw-ciphertext-byte basis across all three architectures (legacy CKKS+compSim, CKKS-direct, active BFV-direct). The previous analytical-estimate table is retained for historical continuity but now carries an explicit statement that it describes only the superseded legacy construction and should not be read as characterising the active protocol; the active protocol's real, measured sizes are in Figure 4 and the accompanying prose.

Source: `results/benchmarks/serialization_measured.csv`, `serialization_ckks_direct_vs_bfv.csv`.

### 3d. At least one concrete NIZKP instantiation

**Status: FULLY ADDRESSED** (see also the dedicated NIZKP-wording verification below)

We implemented a full Groth16 Setup/Prove/Verify for $R_{\mathrm{acc}}$ (account-credential validity), the simplest of the three formalised relations, using circuit-compatible substitutes for the manuscript's generic signature and commitment primitives (EdDSA-Poseidon and a Poseidon-hash commitment, both explicitly flagged as substitutions, not the original unspecified primitives implemented unchanged). Measured: 4,708 non-linear constraints, 4,713 wires; one-time setup 210.9 s (explicitly a local, single-contribution Powers-of-Tau, not a production ceremony); witness generation 0.336 s; proving 5.00 s; verification 3.17 s (mean of 10 runs); proof size 805 B; proving key 2.88 MB; verification key 3.5 kB. The verifier correctly rejects tampered witnesses, tampered commitments, replayed proofs, and malformed proof objects. $R_{\mathrm{score}}$ and $R_{\mathrm{bind}}$ remain formalised only (see the "NIZKP wording" note below) — the reviewer's request was for *at least one* concrete instantiation with constraint counts and timings, which is now satisfied.

Source: `results/nizkp/nizkp_{benchmark_summary,constraint_summary,sizes,environment}.{csv,json}`; `src/fairlend/nizkp/r_acc.py`, `groth16_toolchain.py`; `reviewer2_phase3b_nizkp_instantiation_report.md`.

---

## Comment 4 — Inconsistencies to resolve

> "- Section 6.5.4 disclaims reconstruction values, then reports 2.1e-5 across 'three evaluated decision models'; Section 6.5.2 describes two.
> - Section 6.1.5 claims measured serialised sizes; Table 8 states they are analytical estimates.
> - Table 8 gives an application packet of about 787 kB; Figure 3b shows about 21 kB for 100 borrowers. Figure 3b appears to predate the corrected ciphertext sizes and should be regenerated or removed.
> - Section 6.1.1 promises ten-seed statistics; Section 6.1.4 says they are not included.
> - The aggregate-count error definitions appear twice in Section 6.5.4."

**Status: FULLY ADDRESSED (all five)**

We thank the reviewer for the precise line-level detail here; each was independently confirmed against the codebase before correction, and none of the underlying data supported a $2.1\times10^{-5}$ figure or a third model anywhere.

1. **6.5.4 contradiction / "three" vs. "two" models.** The unsupported $2.1\times10^{-5}$ claim has been deleted outright — no measured artifact in this codebase ever produced that value. In its place, the real measured reconstruction result (exactly $e_{\mathrm{DP}}=e_{\mathrm{EO}}=0.0$ at the one available real-data configuration, both models) is reported, with "three" corrected to "both" throughout (exactly two decision models — logistic regression and random forest — exist anywhere in this codebase). Location: "Fairness-Metric Reconstruction Criteria" subsubsection.
2. **6.1.5 vs. Table 8 measured/estimate contradiction.** Table 8 (the legacy analytical-estimate table) now carries an explicit preceding paragraph stating it is a superseded, analytical-only artifact, and pointing to Figure 4 for the active construction's real measured values. The two claims no longer coexist without qualification.
3. **Table 8 vs. Figure 3b untraceable mismatch.** Figures 3 and 4 are regenerated end-to-end by a new, checked-in, reproducible script (`figures/generate_manuscript_figures.py`) reading only tracked CSVs; the figure caption cites the exact source files. No image in the manuscript is untraceable to its generating data any longer.
4. **6.1.1 promises ten-seed stats; 6.1.4 disclaims.** The full 50-configuration plaintext sweep is now reported in-text and in a table; where the encrypted-side columns are still limited to fewer configurations, this is stated explicitly (see Comment 3b above) rather than left as an unresolved contradiction.
5. **Duplicate aggregate-count error-definition block.** The duplicate block in "Fairness-Metric Reconstruction Criteria" has been removed; the formulas are now defined exactly once.

**Evidence.** `results/evaluation/model_metrics.csv` (confirms exactly two models exist); `results/evaluation/primary_policy_results.csv`; `results/benchmarks/serialization_measured.csv`; `figures/generate_manuscript_figures.py`.

---

## Minor comments

> "The IP holds plaintext gender, builds the ciphertext and signs the digest (Table 5) - the guarantee is relocated to a trusted third party, which Section 3.5 should state plainly."

**Status: FULLY ADDRESSED.** Added directly to "Scope of Privacy and Fairness Guarantees": "This guarantee is achieved by relocating trust, not by eliminating it. The trusted Identity Provider necessarily observes the borrower's plaintext protected attribute before encrypting it..."

> "Figure 1's example (sexual orientation, religious belief, minority status; typo 'minorty') is gratuitous in a fairness paper."

**Status: FULLY ADDRESSED.** Figure 1 replaced with a simple architecture diagram (operational-feature path vs. protected-attribute path); the sensitive-category example list and the typo are both gone.

> "Self-citations [13]-[15] are only tangentially related."

**Status: FULLY ADDRESSED.** Two of the three self-citations were removed from the sentence the reviewer flagged; the third is retained only where it directly supports an architectural-separation claim the paper makes.

> "The funding statement does not match the grants in the title-page footnote."

**Status: AUTHOR ACTION REQUIRED.** This is a factual question only the authors can answer. Both the title-page footnote and the Funding statement section now carry an explicit `AUTHOR CONFIRMATION REQUIRED` marker; neither was silently corrected or deleted. We will state the confirmed funder(s) in the next revision.

> "Pagination reads 'Page 26 of 25'; Algorithm 6 line 43 is truncated."

**Status: FINAL PDF CHECK REQUIRED.** No LaTeX compiler is available in the environment this revision was prepared in, so pagination and line-rendering cannot be checked directly here. In its place we ran a full structural consistency check of the `.tex` source (brace/environment balance, every cross-reference resolves to a label, no duplicate labels) and it passes; the authors will compile the final PDF (e.g., on Overleaf) before resubmission and confirm pagination and Algorithm 6's rendering directly. This audit also found an unrelated, pre-existing issue in the same category: an unbalanced `\color{red}`/`\color{black}` revision-highlighting pattern that, left as-is, would render roughly 1,100 lines of body text in red. This is flagged in `reviewer2_final_readiness.md` and must be corrected before the final PDF is produced.

> "Given the selective-label problem, state what fraction of the audit population supports the equalised-odds gap."

**Status: FULLY ADDRESSED.** Stated explicitly: $165{,}872/177{,}489 = 93.45\%$ of the TEST population has a resolved outcome ($11{,}617$ unresolved), with an added caveat that this coverage fraction is itself a lower bound on the underlying selective-label problem, since the dataset contains only loans LendingClub chose to originate. Location: "Group Fairness Evaluation."

---

## A note on $R_{\mathrm{score}}$ and $R_{\mathrm{bind}}$

The reviewer's Comment 3 asked for "at least one concrete NIZKP instantiation," which $R_{\mathrm{acc}}$ now provides in full, with real constraint counts and proving/verification times. $R_{\mathrm{score}}$ and $R_{\mathrm{bind}}$ remain formalised at the protocol level only; we do not believe the review requires their concrete instantiation, and we present this as an explicitly scoped limitation and direction for future work (Table "NIZKP relation implementation status"; Limitations) rather than as an outstanding reviewer request. We would, of course, revisit this if the reviewer's intent was broader than the letter of Comment 3.

---

## Closing

> "A publishable paper is reachable from here, but it requires justifying or discarding compSim, implementing at least one NIZKP instantiation, and restoring a coherent evaluation."

We believe this revision accomplishes all three: compSim has been discarded (with the justification the reviewer's own argument supplied), one concrete NIZKP instantiation is implemented and benchmarked, and the evaluation has been restored with real, traceable measurements throughout. The one substantive piece of evidence still missing — the nine-configuration real-data BFV encrypted-fidelity result — is blocked on external dataset availability rather than on any remaining design or implementation gap, and we have marked it honestly rather than approximating it. We will complete that run, confirm the funding statement, and compile and proofread the final PDF before this response is finalised for submission.
