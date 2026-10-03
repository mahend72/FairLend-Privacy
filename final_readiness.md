# Reviewer #2: Final Readiness Report

This report gives the definitive status of every Reviewer #2 point after Phase 4A's manuscript revision and this final evidence-consistency audit. It distinguishes **reviewer blockers** (things the reviewer's own text requires before the paper is acceptable) from **non-blocking limitations** (things that are honestly incomplete but that the reviewer's text does not require to be complete). The manuscript is **not** described as submission-ready anywhere in this report — three items below (one scientific, one factual, one production) must close first.

---

## Fully resolved reviewer issues

| # | Reviewer point | Manuscript location | Evidence |
|---|---|---|---|
| 1 | compSim is degenerate; justify or remove and rewrite Secs. 4.8/6.1.2/6.4 | `subsec:init` (Algorithm 1), Algorithm "Secure Loan Processing..." (`alg:loan_processing`), `subsec:compsim`, `subsec:matching_criteria`, `subsec:gender_matching`, new `subsec:evaluation_scheme_comparison` | `src/fairlend/audit/aggregation.py`; `tests/scientific/test_encrypted_aggregation_direct.py` (22), `test_encrypted_aggregation_bfv.py` (32); `reviewer2_phase1_compsim_removal_report.md` |
| 2 | CKKS/IND-CPA vs IND-CPA$^D$; justify scheme choice or restate theorem | `subsec:init`, `subsec:bfv_parameters`, `subsec:confidentiality_theorem` (Theorem 1), `subsec:composition_limits`, `subsec:ind_cpa_d` | `src/fairlend/crypto/bfv.py`, `src/fairlend/core/config.py::BFVConfig`; `reviewer2_phase2_bfv_migration_report.md` |
| 3a | Report proxy-inference AUC | `subsec:sensitivity_protocol` ("Proxy-Discrimination Diagnostic"), Table `tab:alpha_seed_sensitivity` | `results/evaluation/alpha1_seed_sensitivity_summary.csv` |
| 3c | Report measured (not estimated) serialised sizes | Table `tab:serialized_sizes` preamble (reframed as legacy-only), Figure 4 + Communication Cost prose | `results/benchmarks/serialization_measured.csv`, `serialization_ckks_direct_vs_bfv.csv`; `figures/generate_manuscript_figures.py` |
| 3d | At least one concrete NIZKP instantiation with constraint counts and timings | `subsec:nizkp_formal`, Table `tab:nizkp_status` | `results/nizkp/*`; `src/fairlend/nizkp/r_acc.py`, `groth16_toolchain.py`; `reviewer2_phase3b_nizkp_instantiation_report.md` |
| 4.1 | 6.5.4 disclaim-then-assert $2.1\times10^{-5}$; "three" vs. "two" models | `subsec:fairness_reconstruction` | `results/evaluation/primary_policy_results.csv`, `model_metrics.csv` |
| 4.2 | 6.1.5 vs. Table 8 measured/estimate contradiction | Table `tab:serialized_sizes` preamble paragraph | same as 3c |
| 4.3 | Table 8 vs. Fig. 3b untraceable mismatch | Figures 3/4 regenerated; new caption cites sources | `figures/generate_manuscript_figures.py`, `figures/Computation-cost.png`, `figures/communication-cost.png` |
| 4.4 | 6.1.1 promises ten-seed stats; 6.1.4 disclaims | `subsec:sensitivity_protocol`, `subsec:fixture_scale_note`/`subsec:blocked_experiment` | `results/evaluation/alpha1_seed_sensitivity_{runs,summary}.csv` |
| 4.5 | Duplicate aggregate-error definition block | `subsec:fairness_reconstruction` | — (structural fix) |
| Minor | IP trusted-third-party statement | `subsec:scope_guarantees` | `src/fairlend/roles/identity_provider.py` |
| Minor | Figure 1 gratuitous example / typo | Figure 1 (TikZ diagram) | — |
| Minor | Self-citations [13]-[15] tangential | Contributions section | — |
| Minor | Selective-label EO coverage fraction | `subsec:group_fairness_eval` | `results/evaluation/split_summary.json` |
| Minor | Algorithm 6 ambiguous guard condition | `alg:loan_processing`, line ~1540 | — (structural fix, verified present) |

**Also fully resolved (found and fixed during this final audit, not previously reported as a distinct fix):** a residual "disclaim, then assert" contradiction in "Fairness-Metric Reconstruction Criteria" — one sentence still said "we do not claim a particular maximum reconstruction error" and "direct measured reconstruction values are not included," immediately before the paragraph that reports the real measured value. This is exactly the pattern of Comment 4's first bullet, reintroduced locally by the Phase 4A edit itself. It has been corrected in this pass: the disclaimer sentence now reads as a forward reference to the measured values that immediately follow, rather than a contradiction of them.

---

## Remaining scientific blocker

**BFV 9-config LendingClub encrypted-fidelity run.**

The pre-declared nine-configuration real-data encrypted-fidelity subset ($\alpha_1\in\{0.0,0.7,1.3\}\times\text{seed}\in\{0,5,9\}$, logistic regression, active BFV-direct construction) has not been executed. It is blocked solely on the absence of the raw LendingClub CSV in the current evaluation environment (`data/raw/` contains only `.gitkeep`; the tracked manifest's expected SHA-256 could not be verified against any file). The orchestrator (`evaluation/run_bfv_9config_encrypted_fidelity.py`) is implemented, tested, and — as of this audit — confirmed to correctly refuse to proceed (exit code 3, no side effects) rather than silently substituting a different dataset or configuration.

This is classified as a **reviewer blocker**, not a limitation, because Reviewer #2's Comment 3 explicitly asks for reconstruction errors "over the seeds and alpha_1 values already specified in Section 6.1.1," and this is the one piece of that request not yet satisfied on the encrypted side (the plaintext side is fully satisfied; a single real-data configuration and the fixture-scale BFV result are satisfied; the full nine-configuration BFV real-data sweep is not).

**Closes with:** raw LendingClub CSV placed at `data/raw/accepted_2007_to_2018Q4.csv` (SHA-256 `3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a`), then `evaluation/run_bfv_9config_encrypted_fidelity.py --raw-csv <path>`.

---

## Author actions

**Funding statement confirmation.**

The title-page footnote lists four EPSRC grants; the Funding statement section names the Bill & Melinda Gates Foundation (INV-001309). This is a factual question only the authors can answer and has not been guessed at or silently resolved. Both locations in `manucript.tex` carry an explicit `% AUTHOR CONFIRMATION REQUIRED` comment.

Classified as: **AUTHOR ACTION REQUIRED.**

---

## Final production checks

**Compile PDF, pagination, Algorithm 6 rendering.**

No LaTeX compiler (`pdflatex`/`bibtex`/`latexmk`/`tectonic`) is available in this environment, and no `.bib` file exists anywhere in this repository checkout (a pre-existing condition, not introduced by this revision). In place of compiling, this audit re-verified the following structural properties of `manucript.tex` directly:
- Every `\begin{env}`/`\end{env}` pair balances.
- Overall brace depth returns to exactly 0, never negative.
- Every `\ref{...}` resolves to an existing `\label{...}` (zero unresolved references, including after this audit's additional edits).
- No duplicate `\label{...}` definitions.
- `\[`/`\]` and inline `$...$` math delimiters balance.

These checks reduce, but do not eliminate, compilation risk. They cannot detect: final page count (the reviewer's "Page 26 of 25" observation), whether Algorithm 6 renders without truncation at the `cas-dc` class's column width (the reviewer's specific "line 43" observation), whether the new TikZ Figure 1 or the two regenerated PNG figures place/scale correctly, or whether any citation key resolves once the authors' actual `.bib` file is supplied.

**Newly found in this audit pass, also only checkable by compiling:** the document contains five `\color{red}` calls (lines ~164, 444, 712, 1476, 1705) against only four `\color{black}` calls (lines ~185, 484, 1812, 2452) -- a leftover revision-highlighting convention from an earlier response round. Two pairs are self-contained (164/185, 444/484), but the three remaining `\color{red}` calls (712, 1476, 1705) are followed by only one `\color{black}` (1812), so `\color` state (which is not brace-scoped and persists until changed) renders **all body text from line 712 to line 1811 in red** -- roughly the entire Formal NIZKP Statements subsection, Initialisation, Protected-Attribute/Account/Score credential issuance, Loan Application, Secure Loan Processing (Algorithm 6), the compSim section, Secure Gender-Fairness Analysis, Algorithm 7, and the start of Security Analysis. This is very unlikely to be the intended final appearance and was not introduced by this revision (these `\color` commands predate Phase 4A); it was not caught by the brace/label/environment checks above because `\color` does not open a brace-delimited scope. Not fixed here because it is a presentation choice the authors may have deliberately left in place to show reviewers what changed in an earlier round -- but it must be resolved (either removed entirely for a clean final submission, or corrected to color only the actually-new spans) before the PDF is finalised.

Classified as: **FINAL PDF CHECK REQUIRED.**

---

## Non-blocking limitations

These are honestly disclosed in the manuscript's Limitations section but are **not** reviewer blockers — either because Reviewer #2's text does not require them, or because they describe a scope decision the review does not contest.

- **$R_{\mathrm{score}}$ not concretely instantiated.** Reviewer #2 asked for "at least one concrete NIZKP instantiation," which $R_{\mathrm{acc}}$ satisfies. $R_{\mathrm{score}}$ is structurally identical to $R_{\mathrm{acc}}$ and is presented as scoped future work, not an open reviewer request.
- **$R_{\mathrm{bind}}$ not concretely instantiated.** Requires new circuit work (an in-circuit encryption relation for the manuscript's generic `Enc`, plus a hash-chain over serialised ciphertext bytes) beyond a mechanical repetition of the `R_acc` circuit. Presented as scoped future work for the same reason as above.
- **Binary protected-group representation.** The one-hot encoding is limited to two groups; multi-category/intersectional auditing is out of scope for this revision and stated as a limitation, not something Reviewer #2's comments asked for.
- **Trusted Identity Provider assumption.** The protocol relocates trust to the IP rather than eliminating it; this is now stated plainly (directly responding to the reviewer's minor comment on this point) and is an acknowledged, not a hidden, design boundary.

**Classification used for all four above: NOT REQUIRED FOR REVIEWER SATISFACTION** (in the sense that Reviewer #2's own text does not demand their resolution) while still being **honestly disclosed** as real limitations of the current work.

---

## Summary

| Status | Count | Items |
|---|---|---|
| FULLY ADDRESSED | 15 | See "Fully resolved reviewer issues" table above |
| PARTIALLY ADDRESSED — WAITING FOR BFV 9-CONFIG RUN | 1 | Repeated-seed encrypted reconstruction (Comment 3b) |
| AUTHOR ACTION REQUIRED | 1 | Funding statement mismatch |
| FINAL PDF CHECK REQUIRED | 1 | Compile, pagination, Algorithm 6 rendering |
| NOT REQUIRED FOR REVIEWER SATISFACTION (disclosed as limitations) | 4 | $R_{\mathrm{score}}$, $R_{\mathrm{bind}}$, binary protected-group representation, trusted IP assumption |

**This manuscript is not yet submission-ready.** It becomes submission-ready only once: (1) the nine-configuration BFV real-data run is completed and its real results (or an honest account of any discrepancy) replace the placeholder in `reviewer2_response_draft.md` and the corresponding manuscript section; (2) the authors confirm the correct funding source(s); and (3) the manuscript is compiled to a final PDF with pagination and Algorithm 6's rendering verified directly. Until all three are done, do not represent this response letter or the manuscript as complete to the reviewer or the editor.
