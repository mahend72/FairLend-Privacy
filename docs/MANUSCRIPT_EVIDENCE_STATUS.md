# Manuscript Evidence Status

This document tracks, as the phased `src/fairlend` rebuild proceeds, which
numeric/experimental choices are **manuscript-specified** versus
**implementation choices made in this codebase because the manuscript does
not specify a concrete value**. It is referenced from
`src/fairlend/data/loader.py`, `data/README.md`, and
`tests/scientific/test_no_leakage.py`.

A choice documented here is not "wrong" -- it is simply not a manuscript
figure, so it must never be presented (in a paper, a plot, or an
argument) as if the manuscript specified it. Any of these choices can be
revisited; if one changes, update this file in the same change.

## Dataset status

No real LendingClub comparison is recorded here yet. `data/raw/` is
`.gitignore`d and the real-dataset evaluation has been explicitly deferred
pending completion of the fixture pipeline (see
`docs/IMPLEMENTATION_GAPS.md`). This section will be filled in once a real
run is deliberately performed and reviewed -- not before.

## Phase G (credit-decision models): implementation choices

### 1. Credit-model feature list

`fairlend.data.credit_features.CREDIT_MODEL_FEATURES`:

```
dti
emp_length_years
home_ownership_indicator
log1p_annual_inc
south_region_indicator
```

**Status: an explicit choice made in this codebase, not a manuscript
enumeration.** The manuscript's LendingClub evaluation section (Sec.
6.1.1) names the *proxy-feature* set used to construct the synthetic
protected attribute (income, employment length, DTI, home ownership,
region) but does not separately enumerate a credit-decision-model feature
list. This codebase reuses the same five raw, credit-relevant fields
(deliberately *not* winsorised/standardised the way the proxy score is --
see `fairlend.data.proxy_features.raw_credit_features`) as the
credit-decision model's input, on the grounds that they are ordinary
credit-relevant financial features in their own right (Sec. 6.1.1's own
framing) -- but this is this codebase's decision, documented here rather
than left implicit. It is provisional and will be extended (not silently
replaced) if a later phase adds further LendingClub-specific risk features
(grade, revol_util, fico range, etc.) -- see
`fairlend.data.credit_features`'s module docstring.

### 2. Decision threshold tau

`Y-hat_i = I[s_i >= tau]` (manuscript's stated decision rule; Table 1).

**Status: tau's value is a documented implementation choice, not a
manuscript figure.** The manuscript defines the decision rule's *shape*
but never states tau's numeric value (see
`docs/IMPLEMENTATION_GAPS.md`, item A.4: "No credit-score threshold tau ...
exists" in the pre-rebuild legacy code). This codebase's Phase G
(`fairlend.models.credit_models.select_decision_threshold`) selects tau,
separately per model, by maximising F1 over a fixed candidate grid
(`THRESHOLD_GRID = round(linspace(0.05, 0.95, 19), 2)`) evaluated on the
VALIDATION partition only, after hyperparameter selection (also
VALIDATION-only; see `select_best_logistic_regression` /
`select_best_random_forest`). TEST is never used for either selection
step. This is one reasonable, reviewable choice among several a
reader could substitute (e.g. a fixed target approval rate, a
cost-weighted threshold) -- it must not be described as "the manuscript's
threshold."

## How this file is used downstream

`evaluation/run_plaintext_audit.py` (Phase 2) computes DP/EO from
predictions produced under the tau above; any DP/EO number reported from
this pipeline is conditional on the two choices in this file, not on a
manuscript-specified operating point. Encrypted-audit reconstruction
(Phases 5-8) will audit the SAME frozen predictions, so this conditionality
applies identically to both audit paths.

## Phase 3 (credential cryptography): implementation status and choices

### IMPLEMENTED

- Real Bank digital-signature account credential
  (`fairlend.credentials.account`, `fairlend.roles.bank.Bank`):
  `sigma_b_i = Sign(sk_b_sig, uid_i || acc_i)`.
- Real Credit-Agency digital-signature score credential
  (`fairlend.credentials.score`, `fairlend.roles.credit_agency.CreditAgency`):
  `sigma_c_i = Sign(sk_c_sig, uid_i || s_i)`.
- Real IP-signed CKKS protected-attribute credential
  (`fairlend.credentials.protected_attribute`,
  `fairlend.roles.identity_provider.IdentityProvider`):
  `HE.g_i = Enc(pk_HE, one_hot(gender))`, `d_g_i = SHA256(Serialize(HE.g_i))`,
  `sigma_g_i = Sign(sk_IP_sig, uid_i || d_g_i)`; binary one-hot only
  (male=(1,0), female=(0,1)).
- LPU-side verification of all three credential types
  (`fairlend.roles.lpu.LoanProcessingUnit.verify_account_credential` /
  `verify_score_credential` / `verify_protected_attribute_credential`),
  without the LPU ever holding `sk_HE` (unchanged Phase 4 boundary) and
  without decrypting anything to verify the protected-attribute credential.
- Real cryptographic primitives throughout: Ed25519 signatures
  (`fairlend.crypto.signatures`), SHA-256 hashing
  (`fairlend.crypto.hashing`), canonical JSON message encoding
  (`fairlend.crypto.serialization`). No SHA-256-as-authentication, no
  HMAC-as-public-verification, no boolean "verified" flag not backed by
  an actual `cryptography`-library signature check.

### NOT YET IMPLEMENTED

- Concrete NIZKP relations (`R_acc`, `R_score`, `R_bind`) -- see
  `docs/NIZKP_SCOPE.md`. No `prove()`/`verify_nizkp()` function exists
  anywhere in this package.
- Application-binding proof (`C_app_i` construction/verification) --
  `fairlend.crypto.commitments` remains unimplemented.
- Encrypted audit aggregation (compSim, `HE.C_k`/`HE.A_k`/etc.) --
  `fairlend.audit.similarity`/`aggregation`'s ENCRYPTED path remains
  unimplemented (the PLAINTEXT audit aggregation from Phase 2,
  `fairlend.audit.aggregation.compute_plaintext_audit`, is unrelated and
  already implemented).

### Implementation choices NOT prescribed by the manuscript

1. **Signature scheme: Ed25519** (RFC 8032, via `cryptography`'s
   `hazmat.primitives.asymmetric.ed25519`). The manuscript specifies only
   the abstract `Sign`/`VerifySig` interface (Sec. 3.3, Sec. 4.3), never a
   concrete algorithm. Ed25519 was chosen over RSA-PSS for its fixed-size
   keys/signatures and lack of padding/salt parameters to misconfigure --
   see `fairlend.crypto.signatures`'s module docstring for the full
   rationale. This choice can be revisited; if it changes, every issued
   credential's `credential_version` should also change (see below).
2. **Canonical serialization format: deterministic UTF-8 JSON**
   (`json.dumps(..., sort_keys=True, separators=(",", ":"))`, with
   `bytes` values hex-encoded under an `"__bytes_hex__"` wrapper key) --
   see `fairlend.crypto.serialization.canonical_encode`. The manuscript
   specifies `uid_i || acc_i`-style concatenation notation abstractly; it
   does not mandate a concrete serialization. JSON was chosen over a
   length-delimited binary format for auditability (human-readable,
   directly inspectable in tests/logs) at the cost of being slightly
   larger on the wire -- a reasonable tradeoff for a reference
   implementation, not a performance-critical choice.
3. **Domain-separation tags** (`"domain": "fairlend/account/v1"`,
   `"fairlend/score/v1"`, `"fairlend/protected-attribute/v1"`) included in
   every signed message. This is an implementation-hardening choice, not
   a manuscript mechanism: it prevents a signature valid for one
   credential type/version from ever being replayed as valid for a
   different type or a future incompatible version. The manuscript does
   not require, and does not preclude, this.
4. **Credential dataclasses carry an explicit `credential_version` field**
   (currently `1` for all three types), independent of the domain tag
   embedded in the signed message, so a future schema change to a
   credential's non-cryptographic representation (e.g. adding a field)
   can be distinguished from a change to what was actually signed.

## Phase 4 (compSim): implementation status and TenSEAL behaviour

### IMPLEMENTED

- Binary encrypted reference vectors `HE.r_m = Enc(1,0)`, `HE.r_f =
  Enc(0,1)` (`fairlend.audit.similarity.generate_encrypted_references`,
  `EncryptedReferenceVectors`), generated once by the FLA during setup and
  reused unchanged across every borrower (verified by test, not merely
  asserted).
- The manuscript's compSim inner product,
  `s_i,k = sum_j HE(g_i,j) (x) HE(r_k,j)` for `k in {m, f}`
  (`fairlend.audit.similarity.comp_sim`), implemented via TenSEAL's
  `CKKSVector.dot()` — confirmed to be exactly ciphertext-ciphertext
  multiply-then-sum, not an approximation.
- LPU-side evaluation without `sk_HE`: `comp_sim` runs entirely on the
  LPU's public context (which retains the FLA's already-generated public
  Galois/relin keys) and structurally refuses a context that holds
  `sk_HE`.
- Diagnostic FLA-side decryption
  (`decrypt_similarity_pair_for_diagnostics`), a function distinct by name
  and by required key material from the LPU production path, never called
  from it.
- Measured CKKS numerical error on a 200-encryption deterministic fixture
  (100 male + 100 female, independently randomised CKKS encryptions): MAE
  ≈ 2.7e-7 (expected-1 scores) / ≈ 4.1e-7 (expected-0 scores), max
  absolute error < 5e-7 for both — see
  `tests/scientific/test_similarity_numerical_fidelity.py` for the exact
  reproducible numbers (run with `pytest -s` to see them printed).

### NOT YET IMPLEMENTED

- Encrypted C/A/P/TP/N/FP aggregation (`HE.C_k` etc.) — explicitly out of
  scope for this phase.
- delta*/argmax matching classification — `comp_sim` returns encrypted
  scores only; classification is a later, separate evaluation layer (see
  `tests/scientific/test_similarity_numerical_fidelity.py::
  test_expected_one_and_expected_zero_score_ranges_do_not_overlap` for a
  raw-score separability sanity check that stops short of choosing
  delta*).

### TenSEAL-specific behaviour (verified empirically, not assumed from the manuscript's prose)

All of the following were confirmed by running the actual library against
this codebase's exact CKKS configuration (`poly_modulus_degree=8192`,
`coeff_mod_bit_sizes=[60,40,40,60]`, `global_scale=2**40`), not inferred
from documentation or the manuscript text:

1. **Relinearisation, rescaling, and modulus-switching are fully
   automatic.** `ts.Context.auto_relin`, `.auto_rescale`, and
   `.auto_mod_switch` are all `True` by default on every context this
   codebase creates, and `CKKSVector` exposes no manual relinearise/
   rescale method to call. This codebase implements no manual handling
   for any of these because TenSEAL's Python API leaves nothing to
   manually handle.
2. **`CKKSVector.dot()` works directly for ciphertext x ciphertext**, not
   only ciphertext x plaintext, and was confirmed to produce the
   identical result to a manual `(a * b).sum()` on this codebase's
   context.
3. **`.dot()`'s internal sum-reduction uses ciphertext rotations**
   (rotate-and-add), which consume Galois keys, not an extra
   multiplicative level. The LPU's derived public context retains the
   FLA's already-generated (public) Galois and relinearisation keys —
   `derive_lpu_context(...).has_galois_keys()` and `.has_relin_keys()`
   are both `True` despite `.has_secret_key()` being `False` — which is
   exactly why compSim can run entirely on the LPU's public context
   without any additional key exchange.
4. **Effective multiplicative depth for compSim is one**: one
   ciphertext-ciphertext multiplication per reference vector, and the two
   references' multiplications are independent of each other (not
   chained) — this matches the manuscript's claim, verified by executing
   the operation, not by copying the claim.
5. **TenSEAL does NOT reliably reject a ciphertext-slot-count mismatch.**
   A size-1 ciphertext `.dot()`-ed against a size-2 one was observed to
   silently return a wrong-but-not-erroring result (apparent broadcasting)
   rather than raising; only a size-0 (empty) ciphertext raised
   (`ValueError: can't compute on vectors of different sizes`). This is a
   real gap in the library's own input validation for this use case, not
   a manuscript concern — `fairlend.audit.similarity` closes it with its
   own explicit `_assert_expected_size` check before any homomorphic
   operation, rather than relying on TenSEAL to catch a malformed or
   substituted ciphertext's shape. This finding was made by deliberately
   probing the library during implementation, not assumed.

### Implementation choice not prescribed by the manuscript

- **`comp_sim` verifies the IP's signature over the
  `ProtectedAttributeCredential` before performing any homomorphic
  operation**, and refuses (raising `CredentialVerificationError`) on
  failure. The manuscript describes compSim as a similarity computation
  over `HE.g_i`/`HE.r_k`; it does not specify exactly where in the
  pipeline credential verification must occur relative to that
  computation. Gating compSim itself on verification (rather than trusting
  a caller to have verified first) is this codebase's choice, made so
  that "verify before compute" is structural rather than a convention a
  future caller could forget.

## Phase 5 (encrypted audit aggregation): implementation status

### IMPLEMENTED

- Encrypted C/A/P/TP/N/FP construction
  (`fairlend.audit.aggregation.compute_encrypted_audit`): for every TEST
  record, a real IP-issued/LPU-verified `ProtectedAttributeCredential` is
  run through `comp_sim` (never bypassed, never constructed ad hoc inside
  aggregation code), and the resulting similarity ciphertext is
  homomorphically added into every aggregate the row's PLAINTEXT
  decision/outcome make it eligible for (C always; A iff approved; P/N/TP/
  FP only over resolved outcomes) — via plain Python conditionals on
  `y_pred`/`y_true`, never an extra ciphertext-plaintext multiplication by
  a 0/1 indicator.
- Aggregate-only LPU→FLA packet (`EncryptedAuditPacket`,
  `build_encrypted_aggregate_packet`): exactly 7 top-level fields (two
  per-group ciphertext bundles of 6 statistics each, plus
  model/population-count/protocol-version metadata) — no uid, row_index,
  plaintext gender, account/score value, or per-record y_true/y_pred/
  similarity anywhere, verified by exhaustive field enumeration (see
  `tests/scientific/test_encrypted_aggregation_privacy.py`), not by
  convention.
- Public-only LPU execution: `compute_encrypted_audit` and
  `build_encrypted_aggregate_packet` structurally refuse a context
  holding `sk_HE` and were verified (via a `CKKSVector.decrypt`
  monkeypatch that fails the test if triggered) to never decrypt
  anything.
- Aggregate decryption by FLA
  (`decrypt_audit_packet_for_diagnostics`) — a diagnostic-only function
  distinct by name and required key material from the LPU production
  path.
- Fixture count reconstruction: on the deterministic 38-row TEST fixture,
  every one of the 12 rounded encrypted aggregates (6 statistics x 2
  groups) reconstructs the Phase 2 plaintext audit's count EXACTLY, for
  both logistic regression and random forest — see this session's Phase 5
  report for the full per-statistic table, raw values, and error
  measurements.

### NOT YET IMPLEMENTED

- DP/EO encrypted fairness calculation — `decrypt_audit_packet_for_
  diagnostics` reports raw/rounded aggregate values only; no gap formula
  is computed on them in this phase.
- Fairness reconstruction error (`e_DP`, `e_EO` — plaintext-vs-encrypted
  comparison of the FAIRNESS METRICS, as opposed to the raw aggregate
  counts already compared here) — a later, separate phase.
- Full LendingClub-scale encrypted evaluation — this phase's evidence is
  the 38-row fixture only; no real-data encrypted run has been performed.

### Implementation choices not prescribed by the manuscript

1. **Encrypted-zero initialisation via a fresh top-level ciphertext**,
   relying on TenSEAL's `auto_mod_switch` to reconcile the level
   difference against post-`comp_sim` (one-multiplication-deep)
   ciphertexts, verified empirically (see
   `fairlend.audit.aggregation`'s module docstring for the exact
   experiment). The manuscript does not specify an initialisation
   strategy at this level of implementation detail; an equally valid
   alternative (seeding each accumulator from the first contributing
   ciphertext instead of a fresh zero) was considered and documented as
   rejected in favour of the simpler, verified-working fresh-zero
   approach.
2. **`EncryptedTestRecord.row_index`** exists only as intermediate
   join/validation metadata for constructing the encrypted-record list
   (`evaluation/run_encrypted_audit.py`) and is never copied into
   `EncryptedAuditPacket` — an implementation convenience for correctness
   testing, not a manuscript-specified field.
3. **`protocol_version` string** (`"fairlend/encrypted-audit/v1"`) on
   `EncryptedAuditPacket`, matching Phase 3's credential domain-separation
   pattern — an implementation-hardening choice, not a manuscript
   mechanism.

## Phase 6 (fairness reconstruction): implementation status

### IMPLEMENTED AND FIXTURE-VERIFIED

- Encrypted aggregate decryption feeding fairness computation
  (`fairlend.audit.reconstruction.encrypted_result_from_rounded_packet`,
  reusing Phase 5's `decrypt_audit_packet_for_diagnostics` unchanged).
- DP from encrypted aggregate counts and EO from encrypted aggregate
  counts — both computed by calling `fairlend.audit.fairness.
  compute_demographic_parity`/`compute_equalised_odds` (the SAME
  functions the Phase 2 plaintext audit uses) on the rounded-encrypted
  `PlaintextAuditResult`; no second formula exists anywhere in
  `fairlend.audit.reconstruction` or `evaluation/run_fairness_
  reconstruction.py`.
- Plaintext/encrypted fairness reconstruction, fixture-verified: on the
  38-row TEST fixture, for BOTH logistic regression and random forest,
  `DP_encrypted == DP_plain` and `EO_encrypted == EO_plain` EXACTLY
  (`e_DP = e_EO = 0.0`, not merely within a tolerance) — see this
  session's Phase 6 report for the full per-model table. This matches
  task Sec. 9's expectation exactly and required no tolerance to achieve.
- Reconstruction error measurement (`e_DP`, `e_EO`) and a separately-
  labelled raw-CKKS diagnostic (`DP_raw_ckks`/`EO_raw_ckks`, computed from
  unrounded decrypted values, clipped only enough to satisfy
  `GroupAuditCounts`'s structural invariants against real observed CKKS
  noise — see `fairlend.audit.reconstruction`'s module docstring for the
  exact clipping rationale and the noise magnitude that motivated it).
- Independently re-derived (task Sec. 17): DP/EO recomputed from the
  script's own reported rounded counts using plain Python arithmetic,
  entirely outside `fairlend.audit.reconstruction`, matched the module's
  own output bit-for-bit.

### NOT YET CLAIMED

- Any LendingClub-scale (real-data) reconstruction result — this phase's
  evidence is the 38-row fixture only.
- The manuscript's own `2.1e-5` maximum-fairness-reconstruction-error
  figure (Sec. 6.9) is **not** reproduced, confirmed, or referenced by
  this phase's `e_DP`/`e_EO` values, and must not be read as validating
  it — see "Manuscript contradiction" below.
- A repeated-seed (alpha1/seed sweep) sensitivity result — this phase
  used only the primary fixture setting (alpha1=0.7, seed=0), matching
  the frozen predictions from Phase 1/2/5.
- A final production disclosure policy — `minimum_cell_size` remains
  unconfigured (`None`) by default; this phase adds tests proving
  encrypted/plaintext release-status AGREEMENT once a `k_min` is
  configured, but does not itself choose or recommend one.

### Manuscript contradiction (task Sec. 19 — recorded, not resolved)

`docs/MANUSCRIPT_IMPLEMENTATION_AUDIT.md`'s Consistency Finding #1
already identifies that the manuscript (Sec. 6.9) contradicts itself:
one paragraph states no particular maximum reconstruction error is
claimed, a later paragraph states it was `2.1×10⁻⁵`. This phase's fixture
result (`e_DP = e_EO = 0.0` exactly, on a 38-row synthetic fixture) does
**not** resolve, confirm, or reproduce that manuscript figure in either
direction — the two numbers are not comparable (different dataset scale,
different — indeed here exact rather than approximate — reconstruction
outcome). Per the task's explicit instruction, the manuscript text is not
modified here. Status, plainly stated:

> **The manuscript's `2.1×10⁻⁵` maximum fairness-reconstruction-error
> figure remains unverified on real LendingClub data.**

This repository has not run, and this phase does not run, any encrypted
evaluation against real LendingClub data (`data/raw/` is `.gitignore`d;
see "Dataset status" above and `docs/IMPLEMENTATION_GAPS.md`).

## Phase 7 (matching fidelity / delta*): implementation status

### IMPLEMENTED AND FIXTURE-VERIFIED

- Validation-selected delta* (`fairlend.audit.matching.select_delta_star`)
  — chosen from `DELTA_STAR_GRID` using VALIDATION pairs only; TEST data
  has no parameter through which it could reach this function (structural
  guarantee, not just a convention — see
  `tests/scientific/test_matching_fidelity.py`).
- Matching accuracy, macro-F1, and unmatched rate on TEST, computed via
  the real IP → LPU-verified compSim → FLA/evaluator-diagnostic-decryption
  path (`fairlend.audit.matching.compute_paired_scores`, which calls
  `fairlend.audit.similarity.comp_sim`/`decrypt_similarity_pair_for_
  diagnostics` unmodified — no raw encrypted one-hot value is ever
  constructed inside the matching module or its evaluation script).
- CKKS similarity numerical error (expected-1 / expected-0 score
  distributions, un-rounded, with MAE and max absolute error) — see this
  session's Phase 7 report for the measured fixture values.
- Repeated cryptographic-realisation robustness: 10 independent runs
  (fresh CKKS keys + fresh randomised credential encryption each time),
  each with its own `run_id`/`reference_fingerprint`, summarised as
  mean±std — see `results/fixture_validation/evaluation/
  matching_fidelity_runs.csv` / `matching_fidelity_summary.csv`.

### NOT YET VERIFIED

- Real LendingClub matching fidelity — this phase's evidence is the
  38-row TEST / 18-row VALIDATION fixture partitions only.
- The manuscript's alpha1 × seed sensitivity sweep (Sec. 6.1.1) — this
  phase always uses the single frozen alpha1=0.7, seed=0 synthetic-gender
  assignment; the "10 independent cryptographic runs" here vary ONLY the
  CKKS encryption randomness, not alpha1/seed. Do not confuse the two —
  see `evaluation/run_matching_fidelity.py`'s module docstring.

### Delta* selection rule (implementation choice, not manuscript-prescribed)

The manuscript specifies the argmax/delta* matching RULE (Sec. 4.6:
`predicted_group = argmax(scores)`, unmatched iff both scores fall below
delta*) but does not prescribe how delta* itself should be chosen. This
codebase's choice (`fairlend.audit.matching.select_delta_star`): pick the
LARGEST threshold in `DELTA_STAR_GRID` (19 values, 0.05–0.95, matching
`fairlend.models.credit_models.THRESHOLD_GRID`'s granularity) that
achieves the MAXIMUM matching accuracy on VALIDATION. Preferring the
largest such threshold is deliberately conservative — it widens the
"unmatched" rejection zone for low-confidence/potentially-corrupted score
pairs as far as possible without sacrificing any validation accuracy.
This is one reasonable, auditable criterion among several a reader could
substitute (e.g. a fixed target unmatched rate, a cost-weighted
threshold) — it must not be described as "the manuscript's threshold."

### Terminology note (task Sec. 11)

Every result artifact and this document use "synthetic protected-
attribute label" (or "expected group") for the value matching is scored
against — never "observed gender" — since it is the controlled
experimental label from `fairlend.data.synthetic_gender`, not an observed
demographic attribute (see that module's own docstring for the same
distinction).

## Phase 8 real-data run: threshold-policy sensitivity audit

### Finding

On real LendingClub data, the pre-existing default threshold policy
(`validation_f1_max`, `fairlend.models.credit_models.
select_decision_threshold`, unchanged) selects tau=0.05 for BOTH logistic
regression and random forest, which approves **100% of all 177,489 TEST
applicants** for both models — mechanically forcing `DP_plain =
EO_plain = 0.0` for both. This is mathematically correct given the
implementation, not a bug, but it is a degenerate decision policy: with
this dataset's ~82% positive base rate, F1 is maximised (or tied for
maximal) by approving nearly everyone (full recall, precision ≈ base
rate), and the existing tie-break (smallest threshold wins) lands on the
grid's minimum, 0.05.

### Manuscript alignment: IMPLEMENTATION CHOICE, not manuscript-specified

The manuscript defines the decision rule's shape only (`Y-hat_i =
I[s_i >= tau]`, Table 1: "Public credit-score threshold used by the
threshold-based lending decision rule") and states the VALIDATION
partition's general purpose ("reserved for hyperparameter selection and
selection of the diagnostic matching threshold delta*") — it never states
a metric or algorithm for choosing tau itself, for any of the models
evaluated. **Every threshold-selection policy discussed here — including
the pre-existing `validation_f1_max` default — is therefore an
IMPLEMENTATION CHOICE**, confirmed by reading the manuscript's `tau`
passages (Table 1's row and the decision-rule equation) directly; there
is no ambiguity to report — the manuscript is simply silent on the
selection algorithm.

### Alternative VALIDATION-only policies evaluated (real data; no TEST inspection during selection)

Policy E (a target-approval-rate policy) was **not implemented**: no
scientifically justified target approval rate exists for this evaluation
(no manuscript figure, no external regulatory quota to anchor it), and
inventing one solely to manufacture a non-zero or "more interesting"
fairness gap is exactly the outcome-shopping this audit exists to rule
out.

| Policy | LR tau | RF tau | LR TEST approval | RF TEST approval | LR DP/EO | RF DP/EO |
|---|---|---|---|---|---|---|
| `validation_f1_max` (existing default) | 0.05 | 0.05 | 100.00% | 100.00% | 0 / 0 | 0 / 0 |
| `fixed_probability_0.50` | 0.50 | 0.50 | 99.999% | 100.00% | 2.2e-5 / 1.5e-5 | 0 / 0 |
| `validation_balanced_accuracy_max` | 0.80 | 0.80 | 65.92% | 66.19% | 6.3e-4 / 4.22e-3 | 9.96e-3 / 1.35e-2 |
| `validation_youden_j` | 0.80 | 0.80 | 65.92% | 66.19% | 6.3e-4 / 4.22e-3 | 9.96e-3 / 1.35e-2 |

**Verified mathematical fact** (not merely observed): `validation_balanced_accuracy_max`
and `validation_youden_j` always select the IDENTICAL tau for any input,
since Youden's J = 2×balanced_accuracy − 1 is a strictly increasing
function of balanced accuracy — confirmed both by a closed-form argument
and by property-based unit tests
(`tests/unit/test_threshold_policies.py::
test_balanced_accuracy_and_youden_j_always_select_the_same_tau`), and
observed identically on this real-data run (both rows above are bit-for-bit
the same).

### Interpretation

- `validation_f1_max` genuinely produces an all-positive (or
  effectively-all-positive) classifier on this dataset — confirmed, not
  assumed: TEST approval rate is exactly 1.0 for both models.
- `fixed_probability_0.50` is very nearly as degenerate here (99.999–100%
  approval) — this dataset's predicted-probability distributions are
  concentrated well above 0.5 for both models, so a fixed midpoint
  threshold does not meaningfully change the decision policy.
- `validation_balanced_accuracy_max`/`validation_youden_j` DO produce a
  non-degenerate decision policy (~66% approval for both models) using a
  VALIDATION-only, methodologically standard criterion designed
  specifically to be robust to class imbalance (unlike F1) — and this
  policy reveals small but non-zero, real fairness gaps (0.06%–1.35%
  across the two models), a materially different and more informative
  starting point for encrypted reconstruction than the degenerate
  default.
- The classifiers' ranking ability is weak regardless of threshold
  policy (ROC-AUC ≈ 0.59 for both models under every policy above, since
  ROC-AUC does not depend on tau at all) — no threshold policy can turn a
  weak ranker into a strong one; what changes across policies is only
  where on that weak ranking curve the decision is drawn.

### Recommendation

**`validation_balanced_accuracy_max`** (equivalently `validation_youden_j`)
is recommended as the more methodologically defensible PRIMARY policy for
the encrypted evaluation going forward, chosen because it is a standard,
class-imbalance-robust selection criterion evaluated using VALIDATION
only — not because it produces a larger or "more interesting" fairness
gap (a materially larger DP/EO was an observed consequence of this
choice, not the reason for it). `validation_f1_max` is retained,
unmodified, as a documented alternative variant — its results are
preserved in `results/evaluation/model_metrics.csv`/`plaintext_audit.csv`
and were not overwritten. Full per-model/per-policy VALIDATION and TEST
metrics (accuracy, precision, recall, F1, ROC-AUC, balanced accuracy,
TPR, FPR, and the full C/A/P/TP/N/FP/DP/EO breakdown) are in
`results/evaluation/threshold_policy_sensitivity.csv`.

## Phase 9 (real-data primary-policy encrypted evaluation): Stages 1-4 results

This section records the FIRST full real-LendingClub-scale run of the
entire encrypted pipeline (matching fidelity through fairness
reconstruction) under the PRIMARY policy
(`validation_balanced_accuracy_max`, LR tau=RF tau=0.80; see the
Recommendation above). Every number below is measured, not asserted —
see `results/evaluation/primary_policy_results.{csv,json}` (produced by
`evaluation/build_primary_policy_results.py`, which performs no
cryptography itself and only consolidates the already-completed artifacts
listed per-claim below) for full machine-readable provenance.

| Claim | Evidence | Status |
|---|---|---|
| 2007-2015 cleaned population | 887,440 cleaned rows (`results/evaluation/dataset_summary.json`) | SUPPORTED / approximately matches manuscript's ~890k (Sec. 6.1.1) |
| Encrypted protected-attribute matching (real data) | accuracy=1.0, macro-F1=1.0, unmatched=0 (`results/evaluation/matching_fidelity_runs.csv`, run_id `cd08706ed9b4428fb232b89a7ac9d1b1`, full 88,744-validation/177,489-test partitions, delta*=0.95 selected from VALIDATION only) | SUPPORTED ON PRIMARY REAL-DATA RUN |
| Aggregate encrypted reconstruction (real data) | 24/24 rounded decrypted counts (12 LR + 12 RF) exactly equal their plaintext counterparts (`results/evaluation/lr_balanced_accuracy_encrypted_audit.json`, `rf_balanced_accuracy_encrypted_audit.json`, independently re-verified by `fairlend.audit.primary_policy.verify_aggregate_reconstruction`) | SUPPORTED |
| Fairness reconstruction (real data) | LR e_DP=e_EO=0.0; RF e_DP=e_EO=0.0 (`results/evaluation/lr_balanced_accuracy_fairness_reconstruction.json`, `rf_balanced_accuracy_fairness_reconstruction.json`) | SUPPORTED FOR PRIMARY REAL-DATA RUN |
| Manuscript's maximum reconstruction error = 2.1e-5 (Sec. 6.9) | This run's rounded-count DP/EO reconstruction error is exactly 0.0 for both models — a DIFFERENT quantity than the manuscript's figure, not a confirmation or contradiction of it | **DO NOT MARK SUPPORTED** from this run alone — remains **UNVERIFIED / NEEDS RECONCILIATION** (see below) |

### Why the manuscript's `2.1e-5` figure is NOT marked supported

This run's production reconstruction error (`e_DP`/`e_EO`, computed from
the FLA's ROUNDED decrypted aggregate counts — see
`fairlend.audit.reconstruction`'s rounding rule) is **exactly zero** for
both models, not `2.1e-5` and not merely "close to" it. Separately, this
run's RAW (unrounded) CKKS diagnostic error — `DP_raw_ckks`/`EO_raw_ckks`
minus `DP_plain`/`EO_plain` — is on the order of `1e-11` to `1e-12` for
LR/RF here, also not `2.1e-5`. Neither of these is the manuscript's
figure, and they should not be reported as if either "reproduces" it,
because:

1. **The rounded-count production error is a discrete quantity** (it is
   either exactly 0, because rounding recovers the true integer count, or
   some enumerable nonzero value if rounding fails) — it is not a
   continuous approximation-error measurement the way `2.1e-5` reads as
   one.
2. **The raw CKKS diagnostic error is randomised per cryptographic
   realisation** (fresh keys, fresh randomised encryption every run — see
   `evaluation/run_primary_policy_encrypted_audit.py`'s module
   docstring) — a single run's raw error is a sample from a
   noise distribution, not a fixed constant comparable to a
   manuscript-reported figure without repeated independent runs and a
   summary statistic (mean/max across runs), which have not yet been
   performed on real data (only Stage 1's matching-fidelity diagnostic
   has been repeated across independent realisations, and only on the
   fixture — see Phase 7 above).
3. The manuscript's own internal contradiction on this figure (Phase 6's
   "Manuscript contradiction" note above) was never resolved — this run
   does not resolve it either.

Per the task's standing instruction, the manuscript text itself is not
edited. The prior verdict stands and is reaffirmed with real-data
evidence now available:

> **The manuscript's `2.1×10⁻⁵` maximum fairness-reconstruction-error
> figure remains unverified on real LendingClub data — this phase
> neither confirms nor contradicts it, because it measures a different
> quantity (exact rounded-count reconstruction error, currently zero) and
> a per-run-randomised diagnostic quantity, neither of which is
> comparable to a single fixed manuscript figure without further,
> explicitly-scoped work (see "Remaining scientific work" in this
> session's Stage 4 report).**

### Interpretation: FairLend does not make RF "less fair" than LR

Observed primary-policy (`validation_balanced_accuracy_max`, tau=0.80)
audit results:

| | LR | RF |
|---|---|---|
| DP | ≈0.00063 | ≈0.00996 |
| EO | ≈0.00422 | ≈0.01352 |

These numbers describe disparities in the FROZEN DECISION POLICIES of two
different credit models evaluated under the identical audit — they do
not, by themselves, establish that one model is globally fairer, more
accurate, or more suitable for deployment (e.g. they say nothing about
either model's calibration, overall accuracy, or the relative cost of
false positives vs. false negatives, none of which this audit measures).
**FairLend's own scientific result here is narrower and unconditional on
which model looks "fairer": its privacy-preserving encrypted audit
reproduces the corresponding PLAINTEXT group statistics exactly, for
both models, under the same policy** — the audit is a faithful,
privacy-preserving mirror of a plaintext computation, not a fairness
verdict on the underlying models.

### Raw CKKS error: one run's diagnostic, not a systematic property

In these individual runs, RF showed a larger raw aggregate approximation
error than LR (max abs error 0.0536 vs. 0.0117; mean 0.0287 vs. 0.0062),
while both remained well below the 0.5 count-rounding boundary (rounding
safety margin ≈0.446 for RF, ≈0.488 for LR — see
`results/evaluation/primary_policy_results.csv`'s
`rounding_safety_margin` column). This should **not** be read as "RF has
intrinsically ~4.6x more encryption error than LR" — the LR and RF runs
used different fresh CKKS realisations (independent keys, independent
randomised encryptions per manuscript Sec. 4.6), and a systematic claim
about each model's CKKS error distribution would require repeated
independent cryptographic runs per model (as Stage 1's matching-fidelity
diagnostic already does on the fixture — Phase 7 above — but has not yet
been done for the encrypted-aggregation path on real data).

### Provenance (Stages 1-4)

- Dataset SHA-256 `3eae03c28fd9d2e8a076ebeb73507e8d4d0f44d90500decdb0936e0933d1f36a`
  (`accepted_2007_to_2018Q4.csv`), synthetic-attribute `alpha1=0.7`,
  `seed=0`, throughout.
- Stage 1 (matching): run_id `cd08706ed9b4428fb232b89a7ac9d1b1`, runtime
  7819.7s.
- Stage 2 (LR encrypted audit): run_id
  `9459dbee9e814e4bbe18745b8bf3fead`, runtime 5273.0s.
- Stage 3 (RF encrypted audit): run_id
  `e9ef4b95f79c43febe040fba47b2b5dc`, runtime 5641.3s.
- Total real encrypted runtime (matching + LR + RF): ≈18,734s (≈312 min).
- Every stage's LPU-side computation was structurally verified to never
  hold `sk_HE` (`context_can_decrypt(lpu_context) == False`) and never
  performed a per-record decryption — only one final aggregate packet was
  decrypted, by the FLA, per model per stage.

### Remaining scientific work (not yet performed)

- The manuscript's alpha1 x seed sensitivity sweep (Sec. 6.1.1) on real
  data — Stages 1-4 use only the single frozen `alpha1=0.7, seed=0`
  setting.
- Repeated independent cryptographic realisations of the ENCRYPTED
  AGGREGATION path (Stages 2/3) on real data, analogous to Stage 1's
  10-realisation fixture diagnostic (Phase 7) — needed before any
  systematic (rather than single-run) statement about CKKS raw-error
  magnitude, and before any attempt to reconcile the manuscript's
  `2.1e-5` figure.
- A deliberate choice (and justification) of `fairness.minimum_cell_size`
  for a production disclosure policy — remains unconfigured (`None`) by
  design; see Phase 6 above.

## Phase 10 (real-data alpha1 x seed sensitivity): REAL-DATA STATISTICAL SENSITIVITY

**This phase is REAL-DATA STATISTICAL SENSITIVITY, not an
ENCRYPTED-FIDELITY EVALUATION.** Every one of the 50 configurations below
(`evaluation/run_alpha1_seed_sensitivity.py`,
`fairlend.audit.alpha_seed_sensitivity`) uses the PLAINTEXT audit path
only (`fairlend.audit.aggregation.compute_plaintext_audit`,
`fairlend.audit.fairness`) — no CKKS, no credential issuance, no
encrypted aggregation, and no matching-fidelity diagnostic runs anywhere
in this phase. FairLend's encrypted-fidelity claim (Phase 9 above) was
established on exactly ONE configuration (`alpha1=0.7, seed=0`, the
primary policy); this phase does NOT extend that encrypted claim to the
other 49 configurations — it answers a different, narrower question: how
sensitive is the PLAINTEXT fairness RESULT to the controlled
synthetic-protected-attribute generation process, holding the dataset,
split, trained LR/RF models, credit probabilities, and decision threshold
(`validation_balanced_accuracy_max`, tau=0.80) fixed throughout.

### What was held fixed vs. what varied

| Fixed | Varied |
|---|---|
| LendingClub dataset, SHA-256 `3eae03c2...9f36a` | `alpha1` in {0.0, 0.4, 0.7, 1.0, 1.3} |
| Train/validation/test split | synthetic-gender RNG `seed` in {0..9} |
| Trained LR/RF models (never refit) | (only the resulting protected-group assignment) |
| LR/RF TEST probabilities (`y_proba`, frozen) | |
| Decision threshold policy (`validation_balanced_accuracy_max`, tau=0.80 for both models) | |
| LR/RF TEST decisions (`y_pred`) — asserted bit-identical across all 50 configurations at runtime | |

### Results: 50 configurations x 2 models = 100 rows

- `results/evaluation/alpha1_seed_sensitivity_runs.csv` (100 rows: one per alpha1 x seed x model)
- `results/evaluation/alpha1_seed_sensitivity_summary.csv` (10 rows: one per alpha1 x model, mean/std/min/max across the 10 seeds)
- Total runtime: **80.57s** (100 rows / 50 configurations, plaintext only) — see "Performance" below.

| alpha1 | proxy_auc mean (both models identical) | LR DP mean±std | LR EO mean±std | RF DP mean±std | RF EO mean±std |
|---|---|---|---|---|---|
| 0.0 | 0.5005 ± 0.0009 | 0.001810 ± 0.001452 | 0.004815 ± 0.005459 | 0.001913 ± 0.001525 | 0.005282 ± 0.005703 |
| 0.4 | 0.6101 ± 0.0012 | 0.002224 ± 0.001642 | 0.006239 ± 0.004559 | 0.005566 ± 0.002168 | 0.007390 ± 0.003804 |
| 0.7 | 0.6830 ± 0.0010 | 0.002042 ± 0.001395 | 0.006948 ± 0.003392 | 0.009087 ± 0.001830 | 0.012500 ± 0.004640 |
| 1.0 | 0.7440 ± 0.0009 | 0.002975 ± 0.002068 | 0.008808 ± 0.002539 | 0.011040 ± 0.001873 | 0.016099 ± 0.005555 |
| 1.3 | 0.7927 ± 0.0007 | 0.005822 ± 0.001983 | 0.011070 ± 0.001822 | 0.011488 ± 0.002205 | 0.017804 ± 0.005712 |

### alpha1=0 control (Sec. 11)

Verified at generation time (not merely observed): `probability_female ==
0.5` EXACTLY for every one of the 887,440 records when `alpha1=0.0`
(`alpha0=0.0` per `configs/evaluation.yaml`, so `sigmoid(0)=0.5`
identically, independent of `z`) — the script raises immediately if this
invariant is violated. Across the 10 seeds at `alpha1=0.0`: proxy AUC
mean 0.5005 (std 0.0009, i.e. indistinguishable from chance given
finite-sample noise), LR DP mean 0.0018 (std 0.0015), RF DP mean 0.0019
(std 0.0015) — small nonzero fairness gaps are EXPECTED here (finite-sample
random variation in a ~887k-row Bernoulli(0.5) split, not a proxy signal),
not a bug and not evidence of a signal.

### Correlation / trend analysis (Sec. 10) — no causal claim beyond this controlled experiment

Pearson correlation across all 50 (alpha1, seed) points:

| Relationship | r |
|---|---|
| alpha1 vs. proxy AUC | **0.9946** |
| alpha1 vs. LR DP | 0.5493 |
| alpha1 vs. LR EO | 0.5041 |
| alpha1 vs. RF DP | 0.8675 |
| alpha1 vs. RF EO | 0.6924 |

`alpha1` controls proxy recoverability BY CONSTRUCTION (it is the sigmoid's
own coefficient on `z`), so the near-perfect `alpha1`-vs-proxy-AUC
correlation is expected, not a discovered effect. The `alpha1`-vs-DP/EO
correlations are weaker and model-dependent (RF's disparities track
`alpha1` more tightly than LR's) — this measures how the FIXED decision
policy's disparities vary under alternative synthetic-protected-group
realisations, not a causal claim about `alpha1` "causing" unfairness in
any general sense outside this controlled synthetic-generation
experiment.

### Stability across seeds

Protected-group BALANCE is extremely stable across seeds at every
`alpha1` (`female_fraction` std ≤ 0.0005 throughout — see the summary
CSV). The FAIRNESS METRICS (DP/EO) are noticeably less stable
seed-to-seed, particularly at lower `alpha1` (e.g. LR EO at `alpha1=0.0`:
std 0.0055 against a mean of 0.0048 — larger than the mean itself),
reflecting finite-sample noise in exactly which records land in each
synthetic group at weak proxy-signal strength. **DP/EO reported from a
single seed at low-to-moderate alpha1 should not be treated as a stable
per-model constant** — the sensitivity sweep itself is the evidence for
this caveat.

### Regression check (Sec. 12): alpha1=0.7, seed=0 reproduces Phase 9's primary result EXACTLY

Verified programmatically at runtime (the script raises immediately on
any mismatch, never silently continues): the `alpha1=0.7, seed=0`
configuration's independently-recomputed LR/RF DP/EO are bit-identical to
`results/evaluation/{lr,rf}_balanced_accuracy_fairness_reconstruction.json`'s
already-stored `DP_plain`/`EO_plain` values (LR: DP=0.0006298858929396633,
EO=0.0042204779429118044; RF: DP=0.009959793549564666,
EO=0.013518800643769757). **PASSED** for both models.

### Proposed encrypted-fidelity subset — NOT executed

Per the task's standing instruction, no encrypted computation was run in
this phase. A predeclared candidate subset (declared BEFORE any encrypted
result exists, to rule out selecting configurations because they "look
interesting"): `alpha1` in {0.0, 0.7, 1.3} x seed in {0, 5, 9} = 9
configurations. Estimated compute time (from Phase 9's measured
full-population rates): running matching fidelity once per configuration
(model-independent) plus ONE model's (LR, the cheaper of the two)
encrypted aggregation per configuration (the aggregation MECHANISM does
not depend on which model produced `y_pred`, so re-verifying it once per
configuration with LR is expected to establish the mechanism's fidelity
under alternative label distributions without doubling cost with a
second, mechanistically-identical RF run) — ≈9 x (7819.66s + 5273.05s) ≈
**32.7 hours**. Running BOTH models per configuration would cost ≈9 x
18734.0s ≈ 46.8 hours. Neither has been run. See this session's Phase 10
report for a subsampled-population alternative (~1.5 hours) offered as a
faster but lower-fidelity option, not yet decided.

### Performance (Sec. 16)

100 plaintext configuration-model rows computed in 80.57s total (≈0.81s
per row, ≈1.61s per alpha1 x seed configuration) — no CKKS processing
anywhere in this phase, several orders of magnitude faster than any
single encrypted stage in Phase 9 (which took 5273-7820 SECONDS per
single configuration).

## Phase 11 (reproducible runtime and communication-size benchmarking)

### REAL IMPLEMENTATION RUNTIME EVIDENCE

All numbers below are measured with `time.perf_counter_ns()` (monotonic,
high-resolution -- never a wall-clock `datetime` timestamp), after
explicit warm-up iterations (2-3 for record-processing operations, 3 for
constant-cost operations), with every raw observation retained
(`results/benchmarks/runtime_raw.csv`, 1,320 observations) and summarised
(`results/benchmarks/runtime_summary.csv`, 80 rows: n, mean, std, median,
min, max, p95). Batch sizes 1/5/10/25/50/100/250/500/1000 were exercised
for every record-processing operation; 5-30 repeats per batch size
depending on size (30 for <=10, 10 for <=100, 5 for larger). Environment:
`results/metadata/benchmark_environment.json` (Intel i7-10610U, 8 logical
/ 4 physical cores, 15.5GB RAM, WSL2/Linux 6.6, Python 3.13.5, TenSEAL
0.3.17, cryptography 45.0.5, load average low during the run).

**CONTROLLED BENCHMARK** (this phase, small/synthetic inputs, isolated
components) is kept STRICTLY SEPARATE from the **FULL REAL-DATA RUN**
(Phase 9's actual 177k/266k-record LendingClub application runs) --
never averaged or blended into one number:

| Full real-data run (Phase 9, NOT rerun here) | Runtime | Records | Throughput |
|---|---|---|---|
| Matching fidelity | 7819.66 s | 266,233 | 34.05 rec/s |
| LR encrypted aggregation | 5273.05 s | 177,489 | 33.66 rec/s |
| RF encrypted aggregation | 5641.28 s | 177,489 | 31.46 rec/s |

Controlled-benchmark component timings (batch=1, mean ± std; full grid
in the CSVs):

| Component | Operation | Mean (batch=1) | records/sec @ batch=1 |
|---|---|---|---|
| A: CKKS setup | FLA private-context generation | 173.2 ± 8.3 ms | n/a (one-time) |
| A: CKKS setup | LPU public-context derivation | 174.9 ± 10.9 ms | n/a (one-time) |
| A: CKKS setup | Encrypted reference generation | 12.8 ± 1.3 ms | n/a (one-time) |
| B: credential issuance | Bank account credential | 0.045 ms | 22,225/s |
| B: credential issuance | CA score credential | 0.044 ms | 22,753/s |
| B: credential issuance | IP protected-attribute credential | 6.92 ms | 144.5/s |
| C: credential verification | Bank verification | (sub-ms; see CSV) | ~1,368/s (IP verify) |
| C: credential verification | CA / IP verification | (sub-ms; see CSV) | see CSV |
| D: protected-group processing | compSim | 12.70 ms | 78.7/s |
| D: protected-group processing | aggregate addition/update (12 ciphertext adds/record) | 56.78 ms | 17.6/s |
| E: audit finalization (fixed-cost, independent of population size) | packet serialization | 7.19 ± 2.34 ms | n/a |
| E: audit finalization | FLA deserialization (12 ciphertexts) | 5.00 ± 0.30 ms | n/a |
| E: audit finalization | aggregate decryption (12 ciphertexts) | 17.61 ± 1.04 ms | n/a |
| E: audit finalization | DP calculation | 5.75 ± 2.47 us | n/a |
| E: audit finalization | EO calculation | 6.56 ± 0.21 us | n/a |

Per-record compSim/credential-issuance throughput did not scale perfectly
linearly with batch size (e.g. IP-credential throughput ranged
65-145 rec/s across batch sizes 1-1000, comp_sim 53-79 rec/s) --
consistent with ordinary system noise/GC/allocator effects at this scale,
not a discovered algorithmic property; the full raw distribution is in
`runtime_raw.csv` for independent reanalysis.

### REAL SERIALIZATION/COMMUNICATION EVIDENCE

**Measured** (`results/benchmarks/serialization_measured.csv`, 16 rows --
`len()` on the exact bytes the implementation produced) is kept STRICTLY
SEPARATE from **analytical** (`results/benchmarks/serialization_analytical.csv`,
2 rows -- a formula over CKKS parameters only, computed independently and
never adjusted to match the measured column):

| Object | Measured bytes | Method |
|---|---|---|
| Fresh CKKS scalar (full 4-modulus chain) | 331,540 | `CKKSVector.serialize()` |
| IP protected-attribute ciphertext (packed one-hot pair) | 331,060 | `ProtectedAttributeCredential.ciphertext_bytes` |
| Male / female reference vector | 331,221 / 331,331 | `EncryptedReferenceVectors.*_reference_bytes` |
| One EncryptedSimilarityPair | 470,187 | sum of both score ciphertext lengths |
| One SerializedGroupAuditCounts (6 post-aggregation ciphertexts) | 1,410,665 (≈235,111/ciphertext) | sum of 6 field lengths |
| Complete EncryptedAuditPacket (12 ciphertexts + metadata) | 5,642,620 (canonical-JSON, hex-encoded bytes fields) | `canonical_encode(asdict(packet))` |
| LPU public/evaluation context (pk + Galois + relin, no secret key) | 35,291,733 | `Context.serialize(save_secret_key=False, ...)` |
| Public-key material only | 464,938 | `Context.serialize(galois=False, relin=False)` |
| Galois key material (isolated delta) | 33,432,117 | serialize-flag delta |
| Relinearization key material (isolated delta) | 1,394,678 | serialize-flag delta |
| FLA private context -- **LENGTH ONLY** | 697,484 | length computed transiently; bytes never written (contains `sk_HE`) |
| Bank / CA credential (canonical-JSON) | 238 / 226 | `canonical_encode(asdict(...))` |
| Ed25519 public key (raw) | 32 | `public_bytes(Encoding.Raw, PublicFormat.Raw)` |

Analytical estimate (formula only, `poly_modulus_degree=8192`,
`coeff_mod_bit_sizes=[60,40,40,60]`, `num_polys=2`):

| Object | Formula | analytical_estimate_bytes | vs. measured |
|---|---|---|---|
| Fresh ciphertext, full 4-modulus chain | `2 x 8192 x (8+5+5+8)` | 425,984 | measured 331,540 = **-22.2%** |
| Post-compSim ciphertext, 1 level down (approx., 3 moduli) | `2 x 8192 x (5+8+8)` | 344,064 | (no single directly-matching measured row; ≈+46% vs. the 235,111-byte average post-aggregation ciphertext) |

The analytical formula deliberately omits SEAL/TenSEAL's own container
format, optional compression, and packed/compact coefficient encoding
(documented in `fairlend.benchmarks.serialization_estimate`'s module
docstring) -- the gap above is the EXPECTED, disclosed consequence of
those omissions, not an error to reconcile.

**Communication paths** (`results/benchmarks/communication_summary.csv`)
-- one-time setup kept separate from per-application and per-audit-batch
traffic (never added into every application's cost):

| Category | Total bytes |
|---|---|
| One-time setup (LPU context + both reference vectors) | 35,954,285 |
| Per application (Bank + CA + IP credentials) | 1,325,400 |
| Per audit batch (one EncryptedAuditPacket) | 5,642,620 |

**Derived communication projections** (serialized-payload-size
calculations, NOT network measurements -- `fixed_setup + n*per_application
+ one_audit_packet`):

| n applications | Projected total bytes |
|---|---|
| 1 | 42,922,305 |
| 100 | 174,136,905 |
| 1,000 | 1,366,996,905 |
| 10,000 | 13,295,596,905 |
| 100,000 | 132,581,596,905 |

No network latency or bandwidth is claimed anywhere above -- every number
is a "serialized communication payload" size, never a "network transfer
time." No secret key material (`sk_HE`, Ed25519 private keys, private
CKKS context bytes) was written to any result file -- only the private
context's byte LENGTH was computed and retained.

### Manuscript comparison: runtime (Fig. 3, Sec. 6.4.1)

The manuscript's Fig. 3 batch 1->100 timings were never reproduced by
running new code to match them -- every row below was measured first,
compared second, per the task's standing instruction.

| Manuscript claim (batch 1 -> 100) | Best-effort mapping to the rebuilt implementation | Measured (batch 1 -> 100) | Classification |
|---|---|---|---|
| Account opening: 8.887ms -> 571.9ms | Bank account credential issuance | 0.045ms -> 5.03ms | **NOT REPRODUCED** (~110-180x smaller; real Ed25519 signing is far cheaper than the manuscript's described operational-encryption design) |
| Credit-score processing: 0.426ms -> 458.4ms | CA score credential issuance | 0.044ms -> 6.09ms | **NOT REPRODUCED** (~10-75x smaller) |
| Loan-application packet construction: 0.446ms -> 44.6ms | No corresponding operation exists in the rebuilt implementation (NIZKP proving/application-binding `C_app_i` remain unimplemented -- see Phase 3 above) | n/a | **NOT COMPARABLE** |
| Secure processing: 0.411ms -> 41.1ms | compSim (the actual encrypted protected-group similarity computation) | 12.70ms -> 1441.04ms | **NOT REPRODUCED** (~31-35x LARGER; real CKKS ciphertext-ciphertext work is far more expensive than the manuscript's figure) |
| Aggregate fairness-statistic processing: 0.122ms -> 12.2ms | Aggregate ciphertext addition/update (12 per record) | 56.78ms -> 137.31ms | **NOT REPRODUCED** (batch-1 alone is ~465x larger than the manuscript's batch-100 claim) |

Every manuscript Fig. 3 figure is therefore either NOT REPRODUCED (by a
large, consistent margin, in both directions depending on the operation)
or NOT COMPARABLE (the corresponding component was never built). This
does not, by itself, mean the manuscript's original measurements were
fabricated -- see `docs/MANUSCRIPT_IMPLEMENTATION_AUDIT.md`'s established
finding that the manuscript's Fig. 3 hardware/measurement claim is
internally consistent but was never shown to derive from a repository
matching the manuscript's own described architecture. What this phase
adds is the first REAL measurement from the REBUILT architecture itself,
which disagrees with those numbers substantially in both directions.

### Manuscript comparison: serialized/communication sizes (Table tab:serialized_sizes)

The manuscript's own Table (Sec. 6.4.2) is ALREADY explicitly labelled
"analytical estimates rather than direct measurements" -- this phase
supplies the first actual measurements to compare against those
estimates.

| Manuscript's analytical estimate | Value | Rebuilt implementation's actual/analytical figure | Classification |
|---|---|---|---|
| Fresh ciphertext, "first data level" (3 active moduli) | 393,216 B | Measured fresh scalar: 331,540 B (-15.6% vs. this figure); this repo's own 4-modulus analytical restatement: 425,984 B | **PREVIOUSLY ANALYTICAL, NOW MEASURED** |
| CKKS protected-attribute ciphertext pair (2 separate ciphertexts assumed) | ~786,560 B | Measured: 331,060 B (ONE packed size-2 vector) | **NOT REPRODUCED** -- architecturally different: the rebuilt implementation packs both one-hot coordinates into a single ciphertext, ~2.4x smaller than a two-separate-ciphertexts design |
| CKKS encrypted aggregate ciphertext (post-mult/rescale) | ~262,208 B | Measured (avg. per-stat post-aggregation ciphertext): ~235,111 B | **APPROXIMATELY REPRODUCED** (-10.3%) |
| CKKS public key pk_HE | ~524,352 B | Measured public-key-only material: 464,938 B | **APPROXIMATELY REPRODUCED** (-11.3%) |
| CKKS evaluation-key material evk_HE | ~1,573,120 B | Measured Galois+relin key material: ~34,826,795 B | **NOT REPRODUCED** (~22x LARGER -- the manuscript's estimate substantially underestimates real Galois/relinearization key material) |
| Complete application packet excl. NIZKPs | ~787,100 B | Measured (Bank+CA+IP credentials, canonical-JSON): 662,932 B | **APPROXIMATELY REPRODUCED** (-15.8%) |
| Complete aggregate audit packet | ~3,146,752 B | Measured raw ciphertext-bytes sum: ~2,821,330 B (-10.3%); canonical-JSON hex-encoded total: 5,642,620 B (a different, also-valid wire-format choice) | **APPROXIMATELY REPRODUCED** on a raw-bytes basis |
| Operational account/credit-score ciphertext (~101 B / ~77 B) | -- | No operational-encryption layer exists (credentials are SIGNED, not encrypted, in the rebuilt implementation) | **NOT COMPARABLE** |
| Borrower public key / Bank-CA verification key (65 B) | -- | Measured Ed25519 public key: 32 B | **NOT COMPARABLE** (different key algorithm/representation -- the manuscript figure assumes an uncompressed EC point, not Ed25519) |

The single most consequential finding: **the manuscript's evaluation-key
size estimate is off by roughly 22x** relative to the real, measured
Galois/relinearization key material this implementation actually produces
-- a real CKKS deployment's rotation-key material is far larger than a
naive per-ciphertext analytical formula suggests, and any future
manuscript revision citing evaluation-key communication cost should use
this phase's measured figure, not the prior analytical one.
