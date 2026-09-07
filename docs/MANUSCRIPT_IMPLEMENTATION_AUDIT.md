# Manuscript Implementation Audit

**Manuscript:** "FairLend: Privacy-Preserving Gender-Fairness Auditing for Loan Processing" (`manuscript.tex`, added to repo root, not yet tracked in a prior commit)
**Repository:** `FairLend-Privacy-Preserving-Fair-Loan-Processing` (GitHub public repo)
**Audit date:** 2026-09-05

## Headline Finding

**The repository code predates the manuscript by roughly two years and implements a different system.** Every source file under `source code/` and the entire content of `SecureLoan.ipynb` were added on **2023-12-25** (`git log --diff-filter=A`), under the project name *"Secure Loan Verification and Approval System"* (see the notebook's own Colab badge URL and `User Guide.md`, which still instructs cloning `github.com/mahend72/Secure-Loan-Verififaction-and-Approval-system`). The manuscript cites 2025 sources and describes a materially different architecture (LPU/FLA separation, Bank/CA/IP signature credentials, binary CKKS one-hot gender matching, NIZKP relations, encrypted aggregate fairness statistics, a LendingClub-based evaluation). None of these appear in the code. Only the `README.md` prose has been edited recently (5 commits, all wording-only) to describe the new FairLend framing; the underlying code was not touched.

Concretely, the repository implements a single-script, single-party demo that:
- encrypts identity/financial fields with RSA-OAEP (not signatures) between "Customer," "Bank," and "CIBIL" (credit-bureau) roles;
- runs a toy, broken discrete-log "NIZKP" (`Account open.py::NIZKP`) that checks four unrelated attributes against **one shared** commitment/challenge pair — a construction that does not satisfy the algebraic relation it purports to verify;
- encrypts *five* protected/sensitive categories (gender **and** caste, religion, sexual orientation, ethnicity) as small CKKS tensors (not the manuscript's binary one-hot gender pair) and multiplies an applicant's encrypted answer against an encrypted "reference" record to check eligibility for a government benefit scheme — i.e. it uses encrypted protected attributes as a decision **input** (opposite of the manuscript's audit-only goal), not to produce demographic-parity/equalised-odds statistics;
- has no LPU/FLA role split, no Bank/CA/IP signature keys, no NIZKP relations `R_acc`/`R_score`/`R_bind`, no aggregate counts `C_k/A_k/P_k/TP_k/N_k/FP_k`, no fairness-metric computation, no LendingClub data pipeline, no synthetic-gender generator, and no benchmark/measurement scripts corresponding to Figures 3–4 or Table 7 of the manuscript.
- has **no tests** (`find . -iname "*test*"` returns nothing) and the tracked notebook output includes a saved `TypeError` from a prior run (cell 54), i.e. the notebook does not even execute cleanly top-to-bottom as committed.

The remainder of this document and its companions (`MANUSCRIPT_TO_CODE_TRACEABILITY.md`, `IMPLEMENTATION_GAPS.md`) itemise this finding component-by-component per the requested methodology, distinguishing manuscript claims that are formalised-only or explicitly future work (which are *not* repository defects) from manuscript claims of an implemented prototype that have no repository counterpart at all (which are).

---

## Manuscript Scope

Classification is based strictly on the manuscript's own wording (Sections 4, 6, "Limitations," "Conclusion"), independent of the repository.

| Component | Manuscript classification | Manuscript evidence |
|---|---|---|
| Operational loan-processing prototype (LPU decrypts authorised acc/score, applies τ) | **IMPLEMENTED IN PROTOTYPE** | §4.7 Algorithm 5; §6.4.1 phase timings |
| Public-key encryption/decryption (Bank, CA, LPU, borrower) | **IMPLEMENTED IN PROTOTYPE** | §6.1.4: "Operational public-key encryption and digital signatures are implemented" |
| Digital signatures (σ_b,i, σ_c,i, σ_g,i) | **IMPLEMENTED IN PROTOTYPE** (claimed) | §6.1.4, same sentence — explicitly claims signatures are implemented, not merely specified |
| CKKS protected-attribute encryption (binary one-hot) | **IMPLEMENTED IN PROTOTYPE** | §4.3, §4.6; explicit CKKS params (N=8192, moduli [60,40,40,60], scale 2^40) reported as used |
| Encrypted one-hot protected-attribute representation g_i∈{(1,0),(0,1)} | **IMPLEMENTED IN PROTOTYPE** | §4.6 |
| Encrypted reference vectors HE.r_m, HE.r_f | **IMPLEMENTED IN PROTOTYPE** | Algorithm 1 (Initialisation), §4.6 |
| Encrypted inner-product / compSim (depth-1) | **IMPLEMENTED IN PROTOTYPE** | §4.6, with explicit depth-1 argument and rescale/relinearise description |
| Encrypted aggregate group counts C_k, A_k | **IMPLEMENTED IN PROTOTYPE** | Algorithm 5; §6.4.1 reports "aggregate fairness-statistic processing" timings (0.122→12.2 ms) |
| Encrypted approval counts A_k | **IMPLEMENTED IN PROTOTYPE** | Algorithm 5 |
| Retrospective encrypted outcome counts P_k, TP_k, N_k, FP_k | **IMPLEMENTED IN PROTOTYPE** (claimed, algorithmic) / measurement not itemised separately | Algorithm 5; only one combined "fairness-statistic processing" timing is reported, not broken out per statistic |
| FLA aggregate decryption | **IMPLEMENTED IN PROTOTYPE** | Algorithm 6; §6.2 analytical complexity ("FLA decrypts at most twelve aggregate ciphertexts") |
| Demographic parity computation | **IMPLEMENTED IN PROTOTYPE** (claimed) but **numerically contradicted**, see Consistency Findings below | Algorithm 6; §6.6 claims a measured reconstruction error exists after also disclaiming one |
| Equalised odds computation | Same as above | Same |
| Phase-level computation measurements (Fig. 3) | **IMPLEMENTED IN PROTOTYPE**, measured | §6.4.1, concrete ms figures for batch 1→100 |
| Phase-level communication measurements (Fig. 4, Table 7) | **MIXED** — Fig. 4 phase scaling claimed measured; Table 7 byte sizes are explicitly **analytical/configuration-based estimates**, and the manuscript **also** contradicts itself by saying (§6.1.4 opening) they come from "actual serialised objects" | §6.1.4 (two conflicting statements), Table 7 caption, §6.1.4 closing paragraph |
| NIZKP Setup | **FORMALISED ONLY** | §4.5.1 ("These relations are specified at the protocol and arithmetic-constraint level"); §6 "concrete proof-generation... costs are outside the current prototype" |
| NIZKP Prove | **FORMALISED ONLY** | Same |
| NIZKP Verify | **FORMALISED ONLY** | Same |
| R_acc (account-validity circuit) | **FORMALISED ONLY** | §4.5.1 |
| R_score (credit-score authenticity circuit) | **FORMALISED ONLY** | §4.5.1 |
| R_bind (application-binding circuit) | **FORMALISED ONLY** | §4.5.1 |
| Concrete proof sizes / constraint counts / proving & verification time | **NOT IMPLEMENTED / FUTURE WORK** | Table 7 ("One NIZKP proof — Not implemented"); §7 Conclusion: "Future work will instantiate and benchmark the NIZKP relations" |
| Ten-seed synthetic protected-attribute robustness sweep | **EVALUATION PROTOCOL ONLY (not executed)** | §6.1.1/§6.5.3: protocol defined, "we do not report numerical robustness results" |
| α1 sensitivity sweep {0.0,0.4,0.7,1.0,1.3} | **EVALUATION PROTOCOL ONLY (not executed)** | Same |
| Reproduced proxy-inference AUC | **EVALUATION PROTOCOL ONLY (not executed)** | §6.5.2: "we do not claim a specific proxy-inference AUC" |
| Repeated encrypted-matching accuracy/macro-F1 | **EVALUATION PROTOCOL ONLY (not executed)** | §6.5.1(criteria)/§6.7: "we do not report specific numerical fidelity values" |
| Full plaintext-to-encrypted reconstruction experiment | **CONTRADICTORY** — protocol defined as not-yet-executed in one paragraph, then a specific number (2.1×10⁻⁵) is asserted two paragraphs later | §6.9 (Fairness-Metric Reconstruction Criteria) vs. §6.9 (paragraph after Table comparison) |
| Concrete NIZKP benchmarking | **NOT IMPLEMENTED / FUTURE WORK** | §6.4 "Implementation boundary"; §7 |
| LendingClub data pipeline, split, preprocessing | **EVALUATION PROTOCOL ONLY (described, not shown as code)** | §6.1; manuscript describes exact preprocessing but presents no code/artifact, only prose specification |

**Note on the user's proposed pre-classification (from the task prompt):** it is essentially correct in bucketing NIZKP concretisation and the ten-seed/α1/AUC/matching-fidelity/reconstruction sweeps as "not concretely implemented / evaluation design only." The one correction is that **phase-level communication-size figures (Table 7) are internally inconsistent** in the manuscript itself — one passage calls them measured, the surrounding text and the table caption call them analytical estimates — so they should not be filed simply under "implemented" without flagging that contradiction (see below).

---

## Manuscript Pipeline → Repository Mapping

```
Borrower → Identity Provider → encrypted protected-attribute credential (HE.g_i, σ_g,i)
        → Bank → account credential (acc_i, σ_b,i)
        → Credit Agency → credit-score credential (creditScore_i, σ_c,i)
        → Loan Application (Enc.acc_i, Enc.s_i, HE.g_i, σ_g,i, commitments, π_acc, π_score, π_bind)
        → LPU: verify NIZKPs + σ_g,i → decrypt acc/score → Ŷ_i=I[s_i≥τ]
              → compSim(HE.g_i,HE.r_m), compSim(HE.g_i,HE.r_f)
              → update HE.C_k, HE.A_k, HE.P_k, HE.TP_k, HE.N_k, HE.FP_k
        → FLA: HE.Dec(sk_HE, ·) on the 12 aggregate ciphertexts only
              → minimum-cell-size check → Δ_DP, Δ_EO
```

| Stage | Repository counterpart | Verdict |
|---|---|---|
| Identity Provider issuing signed encrypted gender credential | None. No IP entity, no `sk_IP_sig`, no `d_g,i` digest, no `σ_g,i`. `Third_party` keys are generated (`Key_generation.py`) but never used for signing anything. | **NOT IMPLEMENTED** |
| Bank account credential + signature | `Account open.py` only RSA-**encrypts/decrypts** PII fields; account number is a deterministic hash of PII (`generate_account_number`), never signed. | **NOT IMPLEMENTED** (encryption exists; signature does not) |
| Credit Agency credit-score credential + signature | `Apply_loan.py`: `CIBIL_score = 550` — a **hardcoded constant**, not computed from `employmentStatus/salary/creditHistory`; encrypted with RSA-OAEP; never signed. | **NOT IMPLEMENTED / IMPLEMENTED DIFFERENTLY** |
| Loan application packet with 3 NIZKPs + commitments | No commitments (`Com`), no `C_app,i`, no NIZKP proofs of any of the three relations. | **NOT IMPLEMENTED** |
| LPU: verify credentials, decrypt score, threshold decision | No verification step at all (nothing checks `NIZKP()`'s return value before proceeding in `Account open.py`, and its one call site's result variable is even ignored downstream in the credit-score flow). No `τ` threshold and no `Ŷ_i=I[s_i≥τ]` anywhere in the code. | **NOT IMPLEMENTED** |
| compSim(HE.g_i, HE.r_k) inner product on 2-dim one-hot | `Loan_approval.py` multiplies a 4-length (gender) / 6-length (caste) / 8-length (religion) / 6-length (orientation) / 10-length (ethnicity) encrypted tensor against another encrypted tensor and sums — same *shape* of operation (ciphertext×ciphertext, then homomorphic sum) but on the wrong-dimension vectors, for the wrong purpose (identity match, not group-reference match), and it is **decrypted immediately in the same script that makes the decision** rather than aggregated for a separate FLA. | **IMPLEMENTED DIFFERENTLY / CRITICAL PRIVACY-BOUNDARY DEVIATION** — see Section 3 below |
| Encrypted aggregate C_k/A_k/P_k/TP_k/N_k/FP_k | None. No accumulation loop, no per-group running ciphertext totals, no batch/audit-period concept at all — the notebook only ever processes one applicant at a time. | **NOT IMPLEMENTED** |
| FLA: decrypt aggregates, min-cell-size suppression, Δ_DP, Δ_EO | No FLA role, no `sk_HE` custody boundary (the same script/context that encrypts also decrypts — see Key Ownership below), no demographic-parity or equalised-odds formula anywhere in the codebase. | **NOT IMPLEMENTED** |

---

## Manuscript Internal Consistency Findings

| # | Issue | Location(s) | Classification |
|---|---|---|---|
| 1 | **Fairness-reconstruction-error contradiction.** §6.9 states, in one paragraph: *"Because direct measured reconstruction values are not included in the present manuscript, we do not claim a particular maximum reconstruction error."* Two paragraphs later, in the same subsection: *"Across the three evaluated decision models, the maximum fairness-metric reconstruction error was 2.1×10⁻⁵."* These cannot both be true. | manuscript.tex lines ~2204 and ~2216 | **MANUSCRIPT CONTRADICTION** |
| 2 | **Communication-size measurement-vs-estimate contradiction.** §6.1.4 opens by stating serialised-object sizes "are obtained from the actual serialised objects generated by the implementation," then the very next paragraph and the Table 7 caption state the same figures "are analytical estimates rather than direct measurements from TenSEAL or Microsoft SEAL serialisation," and this is repeated a third time after the table ("configuration-based uncompressed estimates rather than direct implementation measurements"). | manuscript.tex lines ~1924–1930 vs. ~1943 and ~2007 | **MANUSCRIPT CONTRADICTION** |
| 3 | **"Three evaluated decision models" vs. two named models.** §6.8 names only logistic regression and random forest as "representative plaintext decision models," but §6.9's disputed sentence (issue #1) refers to "the three evaluated decision models." A third model is never introduced. | manuscript.tex ~2154 vs. ~2216 | **MANUSCRIPT CONTRADICTION** (compounds issue #1) |
| 4 | **Repository evidence for either reconstruction-error claim or the Table 7 byte estimates.** No code in the repository computes CKKS ciphertext sizes, runs LendingClub data, computes DP/EO, or reconstructs anything against a plaintext baseline. | — | **MISSING EVIDENCE** (repository cannot support either side of contradictions #1–#2) |
| 5 | **Phase-level computation timings (Fig. 3 numbers, e.g. 8.887 ms→571.9 ms account opening).** Internally the manuscript is consistent about these being measured (single, unretracted claim, with hardware described in §6.1.4). Whether they are *reproducible* is a separate question (addressed in the traceability matrix / gap report) — as a manuscript-internal statement it is not self-contradictory. | manuscript.tex ~2072 | **SUPPORTED CLAIM** (internally consistent; reproducibility from this repo is a separate, negative, finding) |
| 6 | **NIZKP non-implementation.** The manuscript consistently and repeatedly (abstract, §2.2, §4.5.1, §6.4, §7) states NIZKP concretisation is out of scope for the current prototype. This is internally consistent throughout. | multiple | **SUPPORTED CLAIM** |

**Do not resolve issues #1–#3 by picking a side.** Both the "no reconstruction error is claimed" and "2.1×10⁻⁵" statements, and both the "measured" and "estimated" statements about Table 7, are presented as manuscript fact. This is a defect in the manuscript text, not something the repository can confirm or refute, and it should be corrected editorially before the paper is finalised or before the repository is cited as its supporting artifact.
