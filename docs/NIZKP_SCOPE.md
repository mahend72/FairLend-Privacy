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
the current prototype.** This was true when this scope note was first
written; it is **no longer true for `R_acc` specifically** as of Phase
3B (`reviewer2_phase3b_nizkp_instantiation_report.md`) — see "What
changed in Phase 3B" below. `R_score` and `R_bind` remain exactly as
originally scoped: formalised, not implemented.

## What this codebase does (and does not do)

- **`R_acc`: IMPLEMENTED** (Phase 3B). `src/fairlend/nizkp/r_acc.py` +
  `src/fairlend/nizkp/groth16_toolchain.py` provide a real, executable
  `Setup`/`Prove`/`Verify` for `R_acc`, using Groth16 over BN254 (circom
  2.0.9 + snarkjs 0.7.6), with EdDSA-Poseidon in place of the manuscript's
  generic `Sign`/`VerifySig` and a Poseidon-hash commitment in place of
  its generic `Com` — see `src/fairlend/nizkp/circuits/r_acc.circom`'s
  header comment and `reviewer2_phase3b_nizkp_instantiation_report.md`'s
  "Manuscript-to-concrete primitive mapping" for the exact substitutions
  and why. This EdDSA-Poseidon key is a SEPARATE, circuit-only keypair —
  it does not interoperate with, and does not replace,
  `fairlend.roles.bank.Bank`'s real Ed25519 signing key used elsewhere in
  this codebase.
- **`R_score`: NOT YET IMPLEMENTED** — classified as a straightforward
  extension of `R_acc` (structurally identical: one signature
  verification + one commitment opening, over `(uid_i, s_i)` instead of
  `(uid_i, acc_i)`). See the Phase 3B report's "Remaining relations"
  section.
- **`R_bind`: NOT YET IMPLEMENTED** — classified as requiring genuinely
  new circuit work (two commitment openings, two in-circuit encryption
  relations, and a hash-chain equality over a serialized ciphertext), and
  partially blocked by an underspecified manuscript primitive (`Enc`'s
  concrete, circuit-compatible form was never chosen — see the Phase 3B
  report).
- `src/fairlend/nizkp/relations.py` remains a scope note only — it was
  never populated with typed dataclasses, since `r_acc.py` now provides
  those directly (`RAccStatement`, `RAccWitness`, `RAccProof`) for the one
  relation that has a concrete instantiation.
- Credential objects elsewhere in this codebase (`src/fairlend/credentials/`)
  are UNCHANGED by Phase 3B — no field was added to
  `ProtectedAttributeCredential`/`AccountCredential`/`ScoreCredential` to
  carry an `R_acc` proof; Phase 3B's integration is deliberately minimal
  (statement/witness -> proof -> verify -> accept/reject), not deeply
  wired into the LPU pipeline (see the Phase 3B report's "Integration
  with FairLend" section).

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

## What changed in Phase 3B

`R_acc`'s `Setup`/`Prove`/`Verify` are now real and executable
(`src/fairlend/nizkp/r_acc.py`), under the semi-honest/malicious-borrower
threat model already stated in the manuscript's Sec. 3.3/Threat 2 (a
malicious borrower must not be able to submit an invalid account
credential or fabricate a commitment opening) — proved end-to-end,
including negative tests that a tampered witness, tampered public
commitment, reused proof, or malformed proof are all rejected (see
`tests/scientific/test_nizkp_r_acc.py`). This does **not** change
anything about `R_score`/`R_bind`'s status, and does **not** claim this
proof system protects aggregate confidentiality, fairness, or anything
about the BFV encrypted-audit path — see the Phase 3B report's "Threat-
model interpretation" section for the precise, bounded claim.

## When this changes further

This file must be updated again in the same change that first implements
`Setup`/`Prove`/`Verify` for `R_score` or `R_bind`.
