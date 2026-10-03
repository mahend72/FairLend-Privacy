# Revision Summary for the Editor

This revision responds to Reviewer #2's second-round comments. The substantive changes are:

1. **Removed the degenerate similarity computation (compSim) from the active protocol.** Reviewer #2 showed algebraically that this computation was mathematically redundant given our one-hot encoding. We confirmed this independently and rewrote the active protected-attribute aggregation path around direct encrypted-additive aggregation, which produces identical results at zero multiplicative depth. The removed construction is retained in the manuscript only as clearly labelled historical context.

2. **Migrated the active protected-attribute aggregation scheme from CKKS to BFV.** Every aggregated quantity in this protocol is an integer count; BFV provides these exactly, removing the approximation-error/rounding discussion CKKS required and directly addressing the reviewer's concern about the applicable security notion (IND-CPA vs. IND-CPA$^D$) for the party that decrypts aggregates.

3. **Restored a coherent, quantitative evaluation built entirely from real, traceable measurements.** This includes proxy-inference AUC, a 50-configuration plaintext demographic-parity/equalised-odds sensitivity sweep, measured (not estimated) serialised communication sizes, and regenerated computation/communication-cost figures — every number now traces to a specific tracked result file.

4. **Implemented and benchmarked a concrete zero-knowledge proof for the credential-integrity layer.** One of the three formalised relations (account-credential validity) now has a full, working Groth16 implementation with measured constraint counts, proof size, and setup/proving/verification timings, directly answering the reviewer's request for at least one concrete instantiation.

5. **Clarified the trust model.** The manuscript now states plainly that the Identity Provider is a trusted party that necessarily observes the borrower's protected attribute before encrypting it, and that the aggregate statistics released to the auditor are an intentional disclosure by design, not an incidental leak.

6. **Resolved five internal inconsistencies the reviewer identified**, including an unsupported numerical claim that has been deleted, a model-count discrepancy, a duplicate definition block, and a mismatch between a data table and an unreproducible figure (both figures are now regenerated from tracked data with a checked-in script).

7. **Fixed the remaining minor issues** the reviewer flagged (trust-boundary statement, a gratuitous figure example, tangential self-citations, an algorithm's ambiguous guard condition, and the missing selective-label coverage statistic), and explicitly flagged the one issue that requires author input rather than editorial correction (a mismatch between the funding statement and the title-page grant footnote).

**One item remains open and is disclosed as such, not glossed over:** the pre-declared nine-configuration real-data encrypted-fidelity experiment under the new BFV construction has not yet been run, because the required raw dataset is not currently available in our evaluation environment. This is marked explicitly in the manuscript and in our response letter rather than filled with an estimated or borrowed number. We expect to complete this run, confirm the funding statement, and provide a fully compiled and proofread PDF before this revision is finalised for resubmission.
