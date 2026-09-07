# FairLend public package API

This document describes the **stable, public** surface of the
`fairlend` package (distributed as `fairlend-privacy`). Anything not
listed here (private helpers prefixed `_`, internal dataclass fields
used only for wiring, modules under `fairlend.data`/`fairlend.models`/
`fairlend.benchmarks` used only by `evaluation/`) is implementation
detail and may change without notice.

Canonical implementations live in `fairlend.crypto`, `fairlend.audit`,
`fairlend.credentials`, and `fairlend.roles`. `fairlend.secure_compute`
is a re-export facade over the encrypted-compute parts of those modules
— it does not duplicate any logic.

## `fairlend.secure_compute`

**Purpose:** reusable privacy-preserving computation primitives — CKKS
context management with structural LPU/FLA key separation, encrypted
group-similarity computation (compSim), encrypted aggregate
construction, and plaintext/encrypted fairness reconstruction. This is
the subpackage most useful to a consumer who wants to reuse FairLend's
cryptographic protocol pieces without importing the full role/data
pipeline.

**Main public objects:**

- `build_fla_context(config=None)` — build the FLA's private CKKS
  context (holds `sk_HE`).
- `derive_lpu_context(fla_context)` — derive the LPU's public context
  (no `sk_HE`) from an FLA context.
- `context_can_decrypt(context)` — structural check
  (`context.has_secret_key()`).
- `generate_encrypted_references(fla_context)` /
  `load_reference_vectors(references, context)` — FLA-side reference
  vector setup (`HE.r_m`, `HE.r_f`).
- `comp_sim(credential, ip_public_key, references, lpu_context)` —
  compSim: encrypted group-similarity computation.
- `compute_encrypted_audit(records, ip_public_key, references, lpu_context, model_name)`
  — LPU-side encrypted aggregate construction over a TEST population.
- `build_encrypted_aggregate_packet(result)` /
  `decrypt_audit_packet_for_diagnostics(packet, fla_context)` —
  serialize an `EncryptedAuditResult` for transport, and FLA-side
  decryption for diagnostics.
- `compute_aggregate_reconstruction(...)` /
  `compute_fairness_reconstruction(...)` — plaintext-vs-decrypted
  aggregate comparison and DP/EO reconstruction from decrypted counts.

**Example:**

```python
from fairlend.secure_compute import build_fla_context, derive_lpu_context

fla_context = build_fla_context()
lpu_context = derive_lpu_context(fla_context)
assert fla_context.has_secret_key()
assert not lpu_context.has_secret_key()
```

## `fairlend.crypto`

**Purpose:** low-level cryptographic primitives underlying the
protocol: CKKS context management, Ed25519 signatures, hashing, and
serialization helpers.

**Main public objects:**

- `fairlend.crypto.ckks.build_fla_context`, `derive_lpu_context`,
  `context_can_decrypt` (also re-exported via
  `fairlend.secure_compute`).
- `fairlend.crypto.signatures` — Ed25519 keypair generation, signing,
  and verification helpers used by credential issuance/verification.
- `fairlend.crypto.hashing` — digest helpers used to bind credential
  contents.
- `fairlend.crypto.serialization` — CKKS ciphertext (de)serialization
  helpers with expected-size checks.

**Example:**

```python
from fairlend.crypto.ckks import build_fla_context, context_can_decrypt

ctx = build_fla_context()
assert context_can_decrypt(ctx)
```

## `fairlend.credentials`

**Purpose:** construction of the three signed credential types the
protocol issues to a borrower: account, credit-score, and
protected-attribute (CKKS-encrypted) credentials.

**Main public objects:**

- `AccountCredential`, `issue_account_credential(...)`
- `ScoreCredential`, `issue_score_credential(...)`
- `ProtectedAttributeCredential`, `issue_protected_attribute_credential(...)`

**Example:**

```python
from fairlend.credentials import ProtectedAttributeCredential

# issued by fairlend.roles.identity_provider.IdentityProvider in the
# full protocol flow; the class itself is the transportable, verifiable
# credential object.
```

## `fairlend.audit`

**Purpose:** fairness-metric computation (demographic parity,
equalised odds) from resolved audit counts, plus the similarity /
aggregation / reconstruction implementations re-exported through
`fairlend.secure_compute`.

**Main public objects:**

- `compute_demographic_parity(result)` -> `DemographicParityResult`
- `compute_equalised_odds(result)` -> `EqualisedOddsResult`

**Example:**

```python
from fairlend.audit import compute_demographic_parity, compute_equalised_odds

dp = compute_demographic_parity(plaintext_result)
eo = compute_equalised_odds(plaintext_result)
```

## `fairlend.roles`

**Purpose:** the protocol's role objects — `Borrower`, `Bank`,
`IdentityProvider`, `CreditAgency`, `LoanProcessingUnit` (LPU), and
`FairLendingAuditor` (FLA). These wire the credential and secure-compute
primitives above into the actual multi-party flow, enforcing the
LPU/FLA key-separation boundary structurally at construction time.

**Main public objects:**

- `fairlend.roles.fla.FairLendingAuditor` — constructible only with a
  private (`sk_HE`-holding) CKKS context.
- `fairlend.roles.lpu.LoanProcessingUnit` — constructible only with a
  public (non-`sk_HE`) CKKS context; raises `KeyBoundaryError`
  otherwise.
- `fairlend.roles.identity_provider.IdentityProvider`,
  `fairlend.roles.bank.Bank`,
  `fairlend.roles.credit_agency.CreditAgency`,
  `fairlend.roles.borrower.Borrower`.

**Example:**

```python
from fairlend.secure_compute import build_fla_context, derive_lpu_context
from fairlend.roles.fla import FairLendingAuditor
from fairlend.roles.lpu import LoanProcessingUnit

fla_context = build_fla_context()
lpu_context = derive_lpu_context(fla_context)
fla = FairLendingAuditor(fla_context)
lpu = LoanProcessingUnit(lpu_context)
```

## Not part of the public API

`fairlend.data`, `fairlend.models`, and `fairlend.benchmarks` are
evaluation-support code (dataset loading, model fitting, benchmark
measurement) used by the scripts under `evaluation/`. They are
importable, but their APIs track the reproducibility scripts rather
than external-consumer needs and are not covered by the same stability
expectations as the subpackages above.
