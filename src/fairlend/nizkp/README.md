# NIZKP scope note

The manuscript formalises three NIZKP relations (`R_acc`, `R_score`,
`R_bind`, Sec. 4.5.1) at the protocol and arithmetic-constraint level, and
states explicitly that "concrete proof-generation and proof-verification
costs are outside the current prototype." This package follows that scope
exactly: `relations.py` will hold typed statement/witness descriptions
(Phase 9), never a `Setup`/`Prove`/`Verify` implementation.

See `docs/NIZKP_SCOPE.md` (repository root `docs/`) for the full policy once
written, and `docs/IMPLEMENTATION_GAPS.md` item B.4 for why the legacy
prototype's same-named `NIZKP()` function must not be confused with, or
ported into, this package.
