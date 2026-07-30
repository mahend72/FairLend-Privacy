# Reviewer #2: Remaining Blockers After Phase 4A

Scope: everything that is still open after the Phase 4A manuscript revision, why it is open, and exactly what would close it. Nothing here was worked around by fabrication, estimation, or silent substitution.

---

## 1. Real-data BFV encrypted-fidelity 9-configuration experiment (blocked on data availability)

**What's missing.** The pre-declared subset ($\alpha_1\in\{0.0,0.7,1.3\}\times\text{seed}\in\{0,5,9\}$, logistic regression, full LendingClub-scale population, active BFV-direct construction) has never been executed. 0 of 9 configurations have a result.

**Why it's blocked.** `data/raw/` contains no LendingClub CSV in this environment (only `.gitkeep`). The tracked manifest (`results/metadata/dataset_manifest.json`) expects the file at `data/raw/accepted_2007_to_2018Q4.csv` with SHA-256 `3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a`. This repository's own `data/README.md` already documented this gap before Phase 3A; Phase 3A independently re-confirmed it by direct filesystem inspection and a real (non-mocked) invocation of the orchestrator, which exits with status 3 and a diagnostic message before touching any credential, model, or encryption call.

**What closes it.** Obtain the exact dataset described in `data/README.md`, place it at the expected path, then run:
```
evaluation/run_bfv_9config_encrypted_fidelity.py --raw-csv <path-to-the-real-file>
```
This regenerates the frozen split/predictions if needed and executes all 9 configurations under the active BFV-direct construction, producing a real DP/BFV, EO/BFV, and per-count reconstruction-error table directly comparable to the already-committed plaintext columns (`results/evaluation/alpha1_seed_sensitivity_runs.csv`). The manuscript marks the exact insertion point with a LaTeX comment (`% BLOCKED_RESULT: insert 9-config BFV LendingClub encrypted-fidelity result after exact raw dataset is restored`, in `subsec:blocked_experiment`).

**What is NOT blocked, and already substitutes as far as it honestly can.** The real 177,489-record TEST population has one existing real-data configuration ($\alpha_1=0.7$, seed 0, $\tau=0.80$) evaluated end-to-end under the *superseded legacy CKKS+compSim* construction, reported in Section `subsec:group_fairness_eval`/`subsec:fairness_reconstruction`, with exact reconstruction ($e_{\mathrm{DP}}=e_{\mathrm{EO}}=0.0$). This is real evidence, clearly labelled as belonging to the superseded architecture, not presented as BFV evidence.

---

## 2. $R_{\mathrm{score}}$ and $R_{\mathrm{bind}}$ NIZKP relations (not implemented)

**What's missing.** Only $R_{\mathrm{acc}}$ has a concrete Groth16 `Setup`/`Prove`/`Verify`. `R_{\mathrm{score}}$ and $R_{\mathrm{bind}}$ remain formalised at the arithmetic-constraint level only (Table `tab:nizkp_status`).

**Why it's blocked.** $R_{\mathrm{score}}$ is a straightforward extension of the same circuit shape and was deprioritised, per the Phase 3B task's explicit "prefer one rigorous relation over three superficial ones" instruction, in favour of fully validating $R_{\mathrm{acc}}$. $R_{\mathrm{bind}}$ additionally requires an in-circuit representation of the manuscript's unspecified generic `Enc` primitive and a hash-chain over serialised ciphertext bytes — genuinely new circuit-design work, not a mechanical repetition of the `R_acc` circuit.

**What closes it.** Implement `r_score.circom`/`r_bind.circom` following the same `groth16_toolchain.py` orchestration pattern already built and validated for `R_acc`, and re-run `evaluation/run_nizkp_benchmarks.py` to produce comparable constraint-count and timing rows for Table `tab:nizkp_status`.

---

## 3. Funding statement / title-footnote mismatch (author decision, not an implementation gap)

**What's missing.** The title-page footnote (`\tnotetext[1]`) lists four EPSRC grants; the `Funding statement` section names the Bill & Melinda Gates Foundation (INV-001309). These cannot both be the sole funder of this specific work without further explanation.

**Why it's blocked.** This is factual information only the authors have; guessing which is correct (or that both apply, and if so how) risks stating something false in a published paper.

**What closes it.** An author confirms the correct funding source(s) and either statement is corrected or both are reconciled (e.g., "supported in part by X and in part by Y"). Both locations in `manucript.tex` currently carry an explicit `% AUTHOR CONFIRMATION REQUIRED` comment marking this open item; neither was silently deleted or chosen.

---

## 4. Final LaTeX compilation and pagination check (tooling gap, not a content gap)

**What's missing.** No `pdflatex`, `bibtex`, `latexmk`, or `tectonic` is installed in this environment; this was checked again in this phase and remains absent. No `.bib` file exists anywhere in this repository checkout (a pre-existing condition, confirmed in the original Phase 0 audit and unaffected by this revision), so every citation in the document is currently unresolvable by any compiler until the authors supply their actual bibliography file.

**Why it's blocked.** Environment limitation, not a manuscript-content issue. In place of compiling, this phase verified: all `\begin`/`\end` environment pairs balance; overall brace depth returns to 0; every `\ref` has a matching `\label` (zero unresolved); no duplicate labels; `\[`/`\]` and inline `$...$` math delimiters balance. These checks catch most structural breakage a missing/extra brace or label would cause, but they cannot catch layout-only issues (page breaks, column overflow, image scaling).

**What closes it.** Compile `manucript.tex` in the authors' own LaTeX environment (e.g. Overleaf, using the `cas-dc` class this document already assumes) with the actual `.bib` file supplied, and specifically check: final page count (the reviewer's original "Page 26 of 25" comment), whether Algorithm 6 (`alg:loan_processing`) renders without truncation given its length, and whether the new TikZ Figure 1 and the two regenerated PNG figures (`figures/Computation-cost.png`, `figures/communication-cost.png`) place, scale, and caption correctly at print size.

---

## Summary table

| # | Blocker | Kind | Unblocks with |
|---|---|---|---|
| 1 | Real-data BFV 9-config encrypted-fidelity experiment | Missing external data | Raw LendingClub CSV placed at `data/raw/accepted_2007_to_2018Q4.csv`, then `evaluation/run_bfv_9config_encrypted_fidelity.py --raw-csv <path>` |
| 2 | $R_{\mathrm{score}}$/$R_{\mathrm{bind}}$ concrete instantiation | Missing implementation | New circuits + `groth16_toolchain.py` reuse + `run_nizkp_benchmarks.py` re-run |
| 3 | Funding statement vs. title-footnote mismatch | Author-only fact | Author confirms correct funder(s) |
| 4 | LaTeX compilation / pagination / bibliography | Missing tooling + missing `.bib` | Compile on Overleaf/local TeX Live with the real `.bib` file |

No item above was closed by inventing a number, borrowing a result from the wrong architecture, or silently picking an answer to an author-only question.
