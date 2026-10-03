# Reviewer #2: Remaining Blockers After Phase 4A

Scope: everything that is still open after the Phase 4A manuscript revision, why it is open, and exactly what would close it. Nothing here was worked around by fabrication, estimation, or silent substitution.

---

## 1. Real-data BFV encrypted reconstruction: CLOSED

Completed over the full 5 alpha1 x 10 seed grid (logistic regression): 50/50 configurations, 600/600 counts exact, e_DP = e_EO = 0. See `results/evaluation/bfv_encrypted_fidelity_50config_*` and manuscript `subsec:bfv_realdata_fidelity`. Random forest was not evaluated under BFV.

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

**Also found during this final audit pass (new item, same "needs a compile to see" category):** the document has an unbalanced `\color{red}`/`\color{black}` pattern (5 red calls vs. 4 black calls; predates this revision). Because `\color` is not brace-scoped, this currently colors essentially the entire span from the Formal NIZKP Statements subsection through the start of Security Analysis (roughly 1,100 lines) red in the rendered PDF. This was not introduced by Phase 4A and was not something the brace/label consistency checks in this session could catch, since `\color` doesn't open a delimited scope. It must be resolved (remove the leftover highlighting, or correct it to mark only the intended spans) before the final PDF is produced.

---

## Summary table

| # | Blocker | Kind | Unblocks with |
|---|---|---|---|
| 1 | Real-data BFV encrypted reconstruction (50 configs, LR) | CLOSED | Raw LendingClub CSV placed at `data/raw/accepted_2007_to_2018Q4.csv`, then `evaluation/run_bfv_9config_encrypted_fidelity.py --raw-csv <path>` |
| 2 | $R_{\mathrm{score}}$/$R_{\mathrm{bind}}$ concrete instantiation | Missing implementation | New circuits + `groth16_toolchain.py` reuse + `run_nizkp_benchmarks.py` re-run |
| 3 | Funding statement vs. title-footnote mismatch | Author-only fact | Author confirms correct funder(s) |
| 4 | LaTeX compilation / pagination / bibliography | Missing tooling + missing `.bib` | Compile on Overleaf/local TeX Live with the real `.bib` file |

No item above was closed by inventing a number, borrowing a result from the wrong architecture, or silently picking an answer to an author-only question.
