"""NIZKP relations for the FairLend integrity layer -- see README.md in
this package and docs/NIZKP_SCOPE.md for the up-to-date scope.

Phase 3B: R_acc has a real, executable Groth16 Setup/Prove/Verify -- see
fairlend.nizkp.r_acc (relation-specific) and
fairlend.nizkp.groth16_toolchain (relation-agnostic circom/snarkjs
subprocess orchestration). R_score and R_bind remain formalised only, no
Setup/Prove/Verify implementation -- see
reviewer2_phase3b_nizkp_instantiation_report.md's "Remaining relations"
section for why."""
