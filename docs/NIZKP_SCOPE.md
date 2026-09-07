# NIZKP Scope

## What the manuscript claims

The manuscript formalises three non-interactive zero-knowledge proof
relations at the protocol and arithmetic-constraint level (Sec. 4.5.1):

- `R_acc` — knowledge of an opening of the account commitment `C_acc_i`.
- `R_score` — knowledge of an opening of the score commitment `C_score_i`.
- `R_bind` — that the account, score, and protected-attribute components
  of a single application all bind to the same application commitment
  `C_app_i`.

The manuscript states explicitly and repeatedly (Sec. 4.5.1, Sec. 6.4,
Sec. 7, Table 7) that **concrete proof generation and verification —
proof sizes, constraint counts, proving/verification time — are outside
the current prototype.** This is a scope statement the manuscript makes
about itself, not a gap this codebase needs to close to be faithful to it.

## What this codebase does (and does not do)

- `src/fairlend/nizkp/relations.py` holds (or will hold, once Phase 9 is
  reached) typed dataclasses describing each relation's public statement
  and private witness shape, and a plain-language description of its
  constraints — enough to be precise about what each relation asserts.
- It does **not**, and must not, implement `Setup`, `Prove`, or `Verify`
  for any of the three relations. There is no `prove()` or
  `verify_nizkp()` function anywhere in this package, and none should be
  added until a concrete proof system is deliberately chosen and
  implemented as its own reviewed phase.
- Credential objects that will eventually need to satisfy `R_acc`/
  `R_score`/`R_bind` (see `src/fairlend/credentials/`) may carry typed,
  optional protocol-metadata fields reserved for future NIZKP-related
  data (e.g. a `binding_commitment` field), but such a field must never
  be populated with a fabricated "proof" (a hash, a signature relabelled
  as a proof, or a hardcoded `True`) — it stays `None`/absent until a real
  proof system exists.

## Why this matters

The legacy 2023 prototype (`legacy/secureloan_2023/source_code/Account
open.py::NIZKP`) is exactly the failure mode this scope note exists to
prevent: a function *named* `NIZKP` that is neither zero-knowledge, nor
non-interactive, nor a proof of `R_acc`/`R_score`/`R_bind` — it reuses one
commitment/challenge pair across four unrelated secrets and verifies
correctly only when those secrets coincide, which will not happen for
real, distinct PII fields (see `docs/IMPLEMENTATION_GAPS.md`, item B.4).
Nothing in `src/fairlend/nizkp/` may import from, resemble, or be
described as continuing that function. A reader who sees `NIZKP`-shaped
naming in this package should find typed statement/witness descriptions
only, never a working (or fake-working) proof.

## When this changes

This file must be updated in the same change that first implements any
part of `Setup`/`Prove`/`Verify` for `R_acc`, `R_score`, or `R_bind` — at
that point this document's "not implemented" claim becomes false and must
say what changed, under what threat model, and with what concrete proof
system.
