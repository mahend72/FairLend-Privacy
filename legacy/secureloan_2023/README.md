# Secure Loan Verification and Approval System (2023 predecessor)

**This directory contains the historical predecessor prototype and does not
implement the current FairLend manuscript architecture.**

## What this is

This code was added to the repository on 2023-12-25 under the project name
*"Secure Loan Verification and Approval System"* (see the Colab badge in
`SecureLoan.ipynb` and the clone URL in `User Guide.md`, both of which still
point at `github.com/mahend72/Secure-Loan-Verififaction-and-Approval-system`).
It predates, and is architecturally unrelated to, the paper
*"FairLend: Privacy-Preserving Gender-Fairness Auditing for Loan Processing"*
now checked in at the repository root as `manuscript.tex`.

Concretely, this prototype:

- has no Loan Processing Unit (LPU) / Fair Lending Auditor (FLA) role
  separation — one linear script sequence plays Customer/Bank/CIBIL/Third-party;
- encrypts *five* sensitive categories (gender, caste, religion, sexual
  orientation, ethnicity) as small CKKS tensors and uses the encrypted match
  result to decide **eligibility for a government benefit scheme**, not to
  audit gender-disaggregated approval-rate fairness;
- decrypts the encrypted protected-attribute match result directly in the
  same script that feeds the eligibility decision (`source_code/Loan_approval.py`);
- has no Bank/CA/IP digital-signature credentialing (only RSA **encryption**
  key pairs exist; the sole `.sign()` call in the tree references an
  undefined variable and targets an unrelated file);
- has no NIZKP relations corresponding to the manuscript's `R_acc`,
  `R_score`, or `R_bind` — `source_code/Account open.py::NIZKP()` is an
  unrelated, and independently broken, discrete-log toy construction over
  PII fields (it reuses one commitment/challenge pair across four
  independent secrets);
- has no encrypted aggregate statistics, demographic-parity or
  equalised-odds computation, LendingClub data pipeline, or synthetic
  protected-attribute generator.

A full component-by-component audit against the manuscript is in
`../../docs/MANUSCRIPT_TO_CODE_TRACEABILITY.md` and
`../../docs/IMPLEMENTATION_GAPS.md`.

## Why it is kept

The code and results here document the project's history and are kept for
provenance. **It is not imported by, and must not be imported by, the new
`src/fairlend/` package.** Do not port this code into the new architecture —
the new implementation is being built from the manuscript as the sole
source of truth (see the repository root `README.md` and `docs/ARCHITECTURE.md`
once written).

## Contents

- `source_code/` — original Python scripts (originally `source code/`,
  renamed only to avoid a space in the path; file contents are unchanged)
- `SecureLoan.ipynb` — original Colab notebook (content-identical to
  `source_code/`)
- `User Guide.md` — original install/run instructions for this 2023 prototype
- `Results/` — original screenshots of the eligibility-check demo
- `image/` — original architecture/sequence diagrams for this 2023 prototype
- `Public_private_key_pairs/` — original demo RSA `.pem` key material
  (demo-only keys committed to the repository; **do not reuse these keys for
  anything real**)
- `user information/` — original sample PII/financial/sensitive-attribute
  input files used by the demo
- `HE_configuration.txt`, `database_configuration.txt` — original setup notes
