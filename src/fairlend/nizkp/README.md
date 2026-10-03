# NIZKP scope note

The manuscript formalises three NIZKP relations (`R_acc`, `R_score`,
`R_bind`, Sec. 4.5.1) at the protocol and arithmetic-constraint level.

**Phase 3B update**: `R_acc` now has a real, executable Groth16
`Setup`/`Prove`/`Verify` — see `r_acc.py` and `groth16_toolchain.py`, the
circuit source in `circuits/r_acc.circom`, and
`reviewer2_phase3b_nizkp_instantiation_report.md` for the full
constraint-count/timing/threat-model writeup. `R_score` and `R_bind`
remain formalised-only (no `Setup`/`Prove`/`Verify`); `relations.py` is
retained only as a scope note now that `r_acc.py` provides the typed
statement/witness dataclasses directly for the one implemented relation.

See `docs/NIZKP_SCOPE.md` (repository root `docs/`) for the full,
up-to-date policy, and `docs/IMPLEMENTATION_GAPS.md` item B.4 for why the
legacy prototype's same-named `NIZKP()` function must not be confused
with, or ported into, this package.

## Circuit toolchain (Phase 3B only)

`circuits/` holds a self-contained Node.js project (circom + snarkjs +
circomlib + circomlibjs) used ONLY to compile/prove/verify the R_acc
circuit. `node_modules/` and all compiled build artifacts
(`circuits/build/`) are gitignored and fully reproducible from
`circuits/package.json` + `circuits/r_acc.circom` — see the Phase 3B
report's "Proof-system configuration" section for exact versions and
setup steps (`circom` in particular must be v2.0.9, not the current
2.2.x release, on a glibc 2.31 host — verified empirically).
