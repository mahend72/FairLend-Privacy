# Phase 3B: Concrete NIZKP Instantiation (R_acc, Groth16)

Scope: implement and benchmark at least one concrete NIZKP instantiation for the manuscript's integrity layer. No manuscript edits. No BFV architecture changes. No LendingClub substitution. No fabricated benchmarks. No claim that all three relations are implemented.

**Provenance flag**: all artifacts in this report were produced at git commit `8619aab` (Phase 3A's commit) with `git_dirty=true` (this phase's own changes were uncommitted at measurement time, per `results/nizkp/nizkp_environment.json`). Per this project's own standard, **these numbers are PROVISIONAL** until re-measured from a clean, tagged commit.

---

## Executive conclusion

- **R_acc is the relation implemented.** Chosen because it is structurally the simplest of the three (one signature verification + one commitment opening; no encryption relation, no hash-chain composition), it directly supports a central integrity claim (a borrower cannot fabricate an account credential's committed value), and it can be independently, meaningfully tested — exactly the selection criteria this phase specified.
- **Proof system: Groth16** over BN254 (circom 2.0.9 + snarkjs 0.7.6 + circomlib 2.0.5/circomlibjs 0.1.7).
- **Setup/Prove/Verify all work end-to-end**, executed for real (not simulated): a genuine EdDSA-Poseidon-signed, Poseidon-committed instance was proved and verified; a tampered public commitment, a tampered/forged witness, a reused proof against a different statement, and a corrupted proof object were all correctly rejected.
- **Negative/adversarial tests pass**: 13 new tests, all passing, covering every item-12 sub-case applicable to R_acc (R_acc has no protected-attribute, categorical, or application-identifier field, so those specific sub-cases are correctly reported as not applicable rather than faked).
- **This satisfies Reviewer #2's explicit request** for "at least one concrete NIZKP instantiation with constraint counts and proving/verification times" — both are reported below, measured, not estimated.
- **R_score and R_bind remain unimplemented** — classified below as, respectively, a straightforward extension and requiring genuinely new circuit work.

---

## Relation instantiated

Manuscript Sec. 4.1, "Account-validity relation" (verbatim from `manucript.tex`):

**Public statement**: `x_acc,i = (pk_b_sig, uid_i, C_acc,i)`
**Private witness**: `w_acc,i = (acc_i, sigma_b,i, r_acc,i)`
**Predicate**: `R_acc(x,w) = 1` iff
`VerifySig(pk_b_sig, uid_i || acc_i, sigma_b,i) = 1` **AND** `C_acc,i = Com(uid_i || acc_i; r_acc,i)`.

### Relation audit table (task item 1)

| Relation | Public inputs | Private witness | Predicate | Current implementation |
|---|---|---|---|---|
| `R_acc` | `pk_b_sig`, `uid_i`, `C_acc,i` | `acc_i`, `sigma_b,i`, `r_acc,i` | `VerifySig(pk_b_sig, uid_i‖acc_i, sigma_b,i)=1` ∧ `C_acc,i=Com(uid_i‖acc_i; r_acc,i)` | **IMPLEMENTED (Phase 3B)** — Groth16, `src/fairlend/nizkp/r_acc.py` |
| `R_score` | `pk_c_sig`, `uid_i`, `C_score,i` | `s_i`, `sigma_c,i`, `r_score,i` | `VerifySig(pk_c_sig, uid_i‖s_i, sigma_c,i)=1` ∧ `C_score,i=Com(uid_i‖s_i; r_score,i)` | NOT IMPLEMENTED — same shape as `R_acc` |
| `R_bind` | `pk_l`, `uid_i`, `C_acc,i`, `C_score,i`, `Enc.acc_i`, `Enc.s_i`, `d_{g,i}`, `C_app,i` | `acc_i`, `s_i`, `r_acc,i`, `r_score,i`, `rho_acc,i`, `rho_score,i`, `n_i` | Two commitment openings ∧ two `Enc(pk_l, ·; rho)` correctness relations ∧ `C_app,i = H(uid_i‖C_acc,i‖C_score,i‖H(Enc.acc_i)‖H(Enc.s_i)‖d_{g,i}‖n_i)` | NOT IMPLEMENTED — needs an in-circuit encryption relation and hash-chain composition |

Why `R_acc` was chosen (task item 2): it is the relation with (a) the smallest circuit (no `Enc` relation, no multi-way hash chain), (b) the fewest incompatible external primitives (only `Sign`+`Com`, both of which have standard circuit-friendly substitutes), (c) a central, independently-meaningful integrity claim (the borrower cannot submit a fabricated or altered account value while keeping a valid Bank signature and a consistent commitment), and (d) a design that produces real constraint counts and timings without any placeholder logic. `R_score` was not implemented in this phase specifically to keep this deliverable to "one rigorous relation" rather than diluting effort across two structurally-identical ones; `R_bind` was not attempted because it requires a genuinely different, harder circuit component (see "Remaining relations" below) — attempting it in this phase would have meant a shallower, less-tested implementation of a harder relation, which this phase's instructions explicitly discourage.

---

## Manuscript-to-concrete primitive mapping

| Manuscript primitive | Concrete primitive (this module only) | Reason |
|---|---|---|
| `Sign`/`VerifySig` (generic) | **EdDSA over Baby Jubjub with Poseidon** (circomlib's `EdDSAPoseidonVerifier`) | Standard Ed25519 (Curve25519) — which `fairlend.roles.bank`/`fairlend.crypto.signatures` actually use elsewhere in this codebase for the SAME Bank-account-credential signature — has no efficient native R1CS representation; EdDSA-Poseidon is the standard circuit-friendly substitute in the circom/snarkjs ecosystem. **This is a different key and a different signature from the real Ed25519 Bank credential** — the two do not interoperate (see "Integration with FairLend" below). |
| `Com` (generic, unspecified in the manuscript) | **Poseidon-hash commitment**, `Com(uid,acc;r) = Poseidon(uid, acc, r)` | The manuscript never specifies a concrete commitment scheme, and `fairlend.crypto.commitments` was never implemented in this codebase (confirmed absent — see the Phase 0 implementation-gap audit). Poseidon is computationally binding (collision resistance) and computationally hiding given `r` is sampled uniformly and never reused; it is also the natural in-circuit-cheap choice paired with EdDSA-Poseidon. |
| `uid_i`, `acc_i`, `r_acc,i` (abstract values) | Single **BN254 scalar-field elements** (`Fr`, ~254 bits) | Poseidon/EdDSA-Poseidon operate over this field. This codebase's actual `uid` (a string) and `acc` (an account-number-shaped value) are mapped into `Fr` via SHA-256-then-reduce (`fairlend.nizkp.r_acc.encode_to_field`) — a NEW encoding specific to this circuit, not reused from anywhere else in the codebase. |

No manuscript primitive was silently replaced without this table; nowhere in this codebase's report or code does it claim Ed25519 or a generic commitment was verified inside the circuit.

---

## Proof-system configuration

| | |
|---|---|
| Proof system | Groth16 |
| Curve | BN254 (`bn128`/`alt_bn128`) |
| Circuit compiler | `circom` **2.0.9** (precompiled Linux x86_64 binary from the official `iden3/circom` GitHub releases) — **not** the current 2.2.3 release, which requires `GLIBC_2.32`+; this environment has glibc 2.31 (Ubuntu 20.04-based). Verified empirically: 2.2.3 failed to even run (`GLIBC_2.32' not found`); 2.0.9 ran correctly. |
| Proving/verification library | `snarkjs` **0.7.6** |
| Circuit component library | `circomlib` **2.0.5** (circuits: `poseidon.circom`, `eddsaposeidon.circom`, `babyjub.circom`, `bitify.circom`, `escalarmulany.circom`, `escalarmulfix.circom`, `compconstant.circom`) |
| JS-side crypto (witness-input construction only, never inside the circuit itself) | `circomlibjs` **0.1.7** |
| Setup model | **Groth16 circuit-specific trusted setup** — Powers-of-Tau (`2^13`, generated fresh + one local contribution) → phase-2 preparation → Groth16 key generation → one local circuit-specific (phase-2) contribution → verification-key export. **This is explicitly NOT a production multi-party trusted-setup ceremony** — both random contributions were made by this same process using its own CSPRNG (`secrets.token_hex`), not by independent parties. This is adequate for a reproducible development/benchmarking artifact and is stated here, loudly, as inadequate for production deployment. |
| High-level security assumptions | Groth16's soundness/knowledge-soundness rest on the Q-PKE/knowledge-of-exponent-style assumptions in the generic bilinear group model over BN254, PLUS the structured-reference-string being honestly generated (not satisfied by this phase's toy local setup — see above); zero-knowledge is unconditional (perfect) for Groth16 given an honestly generated CRS. |

---

## Constraint statistics

Reported directly from `circom`'s own compiler output (`results/nizkp/nizkp_constraint_summary.json`) — never manually estimated:

| Metric | Value |
|---|---|
| Template instances | 240 |
| Non-linear constraints | **4,708** |
| Linear constraints | 0 |
| Public inputs | 4 |
| Public outputs | 0 |
| Private inputs | 5 |
| Private outputs | 0 |
| Wires | 4,713 |
| Labels | 22,955 |
| Powers-of-Tau size used | `2^13 = 8,192` (chosen because it must exceed 4,708 non-linear constraints; `2^12=4,096` would not have sufficed) |

circom does not distinguish "R1CS constraints" from "witness signals" as separate reported categories beyond what is shown above (non-linear/linear constraints vs. wires) — both are reported as circom itself labels them, not conflated.

---

## Performance

All measurements: `results/nizkp/nizkp_benchmark_{raw,summary}.csv`, N=10 repeats for witness generation/proving/verification (Setup is N=1, a one-time cost, stated explicitly per this task's own instruction). Hardware: Intel i7-10610U (8 logical/4 physical cores), WSL2/Linux 6.6, 15.51 GB RAM, "low" competing load. Memory measured via `/usr/bin/time -v`'s "Maximum resident set size" (available and used — not estimated).

| Operation | N | Mean | Std | Median | Min | Max | Mean peak RSS | Max peak RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Setup (Powers-of-Tau + Groth16 keygen) | 1 | **210.88 s** (one-time only) | — | — | — | — | not measured | not measured |
| Witness generation | 10 | 0.336 s | 0.080 s | 0.319 s | 0.257 s | 0.545 s | 68.8 MB | 69.1 MB |
| Proving | 10 | **5.004 s** | 0.541 s | 4.975 s | 4.058 s | 5.733 s | 379.7 MB | 381.1 MB |
| Verification | 10 | **3.169 s** | 0.509 s | 3.044 s | 2.623 s | 4.443 s | 176.4 MB | 177.4 MB |

| Artifact | Size (measured) |
|---|---|
| Proof (`proof.json`) | **805 bytes** |
| Proving key (`r_acc_final.zkey`) | 3,017,740 bytes (≈2.88 MB) |
| Verification key (`verification_key.json`) | 3,475 bytes |

**Honest caveats, not smoothed over**: verification (~3.2s) and proving (~5.0s) times are dominated by Node.js/`npx` process-startup overhead on this specific toolchain invocation path (each `snarkjs` CLI call is a fresh Node process), not solely the underlying Groth16 arithmetic, which for a 4,708-constraint circuit is typically much faster in a warm, in-process library call. This report measures the ACTUAL, REPRODUCIBLE cost of this CLI-based toolchain as built, not a theoretical lower bound achievable via a persistent-process/native binding integration (out of this phase's scope). The peak-memory figures for proving/verification (~380 MB / ~176 MB) likewise include the Node.js runtime's own baseline footprint, not only the cryptographic computation's incremental cost. Setup's one observed value (210.9s) should not be read as a tight distribution estimate — it was measured once, per its own one-time nature, exactly as this task instructed.

---

## Correctness and adversarial tests

`tests/scientific/test_nizkp_r_acc.py`, 13/13 passing:

**Positive** (4 tests): setup produces all expected artifacts; a valid instance's proof verifies; the public signals match the statement in circom's declared order (`Ax, Ay, uid, Cacc`); different instances produce different commitments.

**Negative — malformed/tampered witness rejected at WITNESS GENERATION** (4 tests, item 12.1/12.2/12.4 plus a signature-forgery case): a wrong `acc` value; an altered public `Cacc` inconsistent with the real witness; wrong opening randomness `r_acc`; a genuine signature from an unrelated key spliced onto a different claimed public key. All four correctly cause `generate_witness.js` itself to fail (circom's `<==`/`===` constraints reject an unsatisfying witness before any proof can be produced at all — a stronger, earlier rejection point than a Verify-time check).

**Negative — valid proof, tampered/misused at VERIFY time** (3 tests, item 12.3/12.5/12.6): an altered public digest handed to Verify after a genuinely valid proof was produced; a proof generated for one statement, replayed against a different, unrelated statement's public signals; a structurally corrupted proof object (a curve-point coordinate replaced with a bogus value). All three correctly return `verify() == False`.

**Not applicable to R_acc, correctly not faked** (item 12.7-12.10): out-of-range protected/group value, invalid categorical encoding, modified application identifier, modified binding identifier — none of these fields exist in `R_acc`'s statement/witness; they belong to `R_bind` (not implemented) and are not tested here.

---

## Privacy/leakage inspection

Field-level inspection only (task item 13's own caveat: this is an implementation-leakage check, not a substitute for Groth16's formal zero-knowledge property, which rests on the proof system itself):

- **Proof object** (`proof.json`) contains exactly the standard Groth16 fields (`pi_a`, `pi_b`, `pi_c`, `protocol`, `curve`) — confirmed by `set(proof.keys()) <= {...}` assertion. None of the witness field names (`acc`, `r_acc`, `S`, `R8x`, `R8y`) appear anywhere in the serialized proof JSON.
- **Public signals** (`public.json`) contain exactly 4 values, in circom's declared order (`Ax, Ay, uid, Cacc`) — confirmed no witness value is present among them.
- The private witness (`acc_i`, `r_acc,i`, and the EdDSA signature components) is never written to any artifact this phase produces except the ephemeral, test-scoped `input.json` used to drive witness generation (deleted after each benchmark iteration; not a tracked result artifact).

---

## Threat-model interpretation

**What this concrete R_acc proof DOES prevent** (task item 7):
- A borrower cannot submit an account value `acc_i` other than the one the Bank (in this demonstration, the EdDSA-Poseidon-keyed issuer role) actually authenticated for that `uid_i`, while still producing a proof that verifies against the publicly bound commitment `C_acc,i` — proved directly by the "forged signature"/"wrong witness acc" negative tests.
- A borrower cannot open the public commitment `C_acc,i` to a different value than what was actually committed, even knowing SOME valid-looking witness — proved by the "altered committed value"/"wrong opening randomness" negative tests.
- A verifier cannot be tricked into accepting a proof produced for a different statement (different `uid`/`Cacc`/public key) as if it applied to the one at hand — proved by the "proof reused against a different statement" negative test.
- The proof reveals `acc_i` and the Bank's signature to no one — the verifier learns only that SOME account value known to the prover satisfies both the signature and commitment relations, never the value itself (subject to the field-inspection caveat above, and to Groth16's own zero-knowledge property, not re-derived here).

**What this proof does NOT prove or protect, and must not be described as doing** (explicit, per this phase's own constraint):
- It does **not** solve fairness, does not touch the BFV encrypted-audit-aggregation architecture, and is entirely independent of demographic parity/equalised odds.
- It does **not** protect aggregate confidentiality — that property rests entirely on the BFV scheme and the LPU/FLA key-separation boundary (Phases 1-2), unrelated to this proof system.
- It does **not** prevent malicious training data or validate the semantic truth of `acc_i` itself (e.g. that the account number corresponds to a real, solvent bank account) — it only proves that the Bank's own signing process authenticated whatever value `acc_i` is, and that the public commitment opens to that same value. A colluding or compromised Bank issuer could still sign a false `acc_i`; this proof does not detect that.
- It does **not** address LPU/FLA collusion in any way — this relation concerns the borrower/Bank/LPU credential-issuance boundary only, not the FLA's aggregate-disclosure boundary.
- **This demonstration's EdDSA-Poseidon signature is not the same signature as the actual `AccountCredential.signature`** issued elsewhere in this codebase (Ed25519) — see "Integration with FairLend" below for exactly what would be needed to connect the two, which was NOT done in this phase.

---

## Integration with FairLend

Per this phase's explicit instruction, the NIZKP was **not** deeply integrated into the loan-processing pipeline. The minimal integration path that exists and is executable end-to-end:

```
statement/witness (RAccStatement, RAccWitness)
    -> Prove (fairlend.nizkp.r_acc.prove)
    -> Verify (fairlend.nizkp.r_acc.verify)
    -> accept/reject (bool)
```

How this would feed the existing LPU integrity check, WITHOUT changing anything about the BFV aggregation architecture: `fairlend.roles.lpu.LoanProcessingUnit.verify_account_credential` currently performs ONLY an Ed25519 `VerifySig` check on the real `AccountCredential`. A production system implementing this manuscript's NIZKP layer for real would need the Bank to issue account credentials under an EdDSA-Poseidon key (or an equivalent circuit-friendly scheme) FROM THE OUTSET — not layer a second, parallel proof system on top of the existing Ed25519 credential — and the LPU would call `fairlend.nizkp.r_acc.verify(...)` as an ADDITIONAL, independent gate alongside (not instead of) its existing signature check, rejecting the application if either check fails. **This phase does not make that change** to `fairlend.roles.lpu`/`fairlend.credentials.account` — doing so would be exactly the "deep integration" this phase was told to avoid, and would conflate a demonstration-only EdDSA-Poseidon key with this codebase's real Bank signing key without a considered key-management decision (out of scope here).

---

## Remaining relations

| Relation | Classification | Why |
|---|---|---|
| `R_score` | **STRAIGHTFORWARD EXTENSION** | Structurally IDENTICAL circuit topology to `R_acc` — one signature verification (over `uid_i ‖ s_i` instead of `uid_i ‖ acc_i`) plus one Poseidon commitment opening. The existing `r_acc.circom`/`r_acc.py` could be near-directly copied and relabelled (new CA EdDSA-Poseidon key in place of the Bank's) with no new circuit primitives needed. |
| `R_bind` | **REQUIRES NEW CIRCUIT WORK, partially BLOCKED BY UNDERSPECIFIED MANUSCRIPT PRIMITIVE** | Needs: (a) two commitment openings (straightforward, same as above); (b) TWO in-circuit `Enc(pk_l, ·; rho)` correctness relations — the manuscript never specifies which concrete public-key encryption scheme `Enc` is, and this codebase's own operational encryption (whatever `fairlend.crypto`/the legacy prototype's RSA-OAEP-based scheme concretely is) is not a circuit-friendly primitive; a circuit-compatible substitute (e.g. ElGamal over Baby Jubjub) would be YET ANOTHER primitive substitution requiring its own justification, not yet made; (c) a hash-chain equality `C_app,i = H(...)` over values that include `H(Serialize(Enc.acc_i))` — hashing a serialized ciphertext blob in-circuit at a specific, exact bit layout is a materially larger and more fragile circuit component than anything `R_acc`/`R_score` require. This is genuinely new engineering work, not a naming/relabelling exercise, and was correctly not attempted in this phase. |

Per this task's own preference ("Reviewer #2 asks for at least one concrete instantiation, so one rigorous relation is preferable to three superficial ones"), only `R_acc` was implemented, tested, and benchmarked to the standard shown above.

---

## Full regression result

| Suite | Result |
|---|---|
| New NIZKP tests (`tests/scientific/test_nizkp_r_acc.py`) | 13 passed |
| Full repository test suite | **568 passed, 2 skipped, 0 failed** (452.05s) — up from the Phase 3A baseline of 555 passed. The +13 is exactly the new NIZKP test file; no other test count changed, and the same 2 tests remain skipped for the same pre-existing, gitignored-data reason as every prior phase. |

Explicitly confirmed NOT weakened by this phase (all pre-existing, unmodified tests still pass): key separation (`test_key_separation.py`, `test_key_ownership.py`), BFV packet privacy (`test_encrypted_aggregation_bfv.py`), no per-record HE decryption (same suite), protected-attribute exclusion from model features (`test_gender_exclusion.py`). This phase touched no file any of those tests exercise.

---

## Manuscript-ready results

| Fact | Exact source artifact |
|---|---|
| `R_acc` circuit: 4,708 non-linear constraints, 4,713 wires, 4 public inputs, 5 private inputs | `results/nizkp/nizkp_constraint_summary.json` |
| Proving system: Groth16 over BN254, circom 2.0.9 / snarkjs 0.7.6 | `results/nizkp/nizkp_constraint_summary.json`, `results/nizkp/nizkp_environment.json` |
| Setup (one-time): 210.88 s | `results/nizkp/nizkp_benchmark_summary.csv` (row `setup_one_time_only`; the 210.88s figure is this phase's single observation, recorded in this report's narrative rather than a repeated-N row, per the task's own "state this explicitly" instruction) |
| Witness generation: 0.336 s ± 0.080 s (N=10) | `results/nizkp/nizkp_benchmark_summary.csv` |
| Proving: 5.004 s ± 0.541 s (N=10), peak RSS ≈380 MB | `results/nizkp/nizkp_benchmark_{summary,raw}.csv` |
| Verification: 3.169 s ± 0.509 s (N=10), peak RSS ≈176 MB | `results/nizkp/nizkp_benchmark_{summary,raw}.csv` |
| Proof size 805 B; proving key 3,017,740 B; verification key 3,475 B | `results/nizkp/nizkp_sizes.json` |
| 13/13 positive and negative correctness/adversarial tests pass | `tests/scientific/test_nizkp_r_acc.py` (this session's run, 452.05s full-suite total) |

These are the numbers that should eventually feed the manuscript's Table 9 (currently formula-only, `T_NIZK-P`/`T_NIZK-V` symbols with no concrete values) and the "Concrete NIZKP proving/verification is not implemented" line in `README.md`/`docs/NIZKP_SCOPE.md` (now partially false — updated in this phase for `R_acc` specifically). **No manuscript file was edited in this phase**, per its own constraint; this table only identifies WHICH numbers would need inserting later.

---

## Remaining Reviewer #2 work

1. **The BFV 9-configuration LendingClub real-data fidelity run** — still blocked awaiting the original raw dataset (Phase 3A's finding, unchanged; this phase did not touch the BFV/data pipeline at all).
2. **`R_score`** — straightforward extension of this phase's work, not yet done.
3. **`R_bind`** — requires new circuit work (an in-circuit encryption relation, plus a decision on which circuit-compatible encryption primitive to substitute for the manuscript's generic `Enc`) and is not yet done.
4. **Production trusted setup** — this phase's Powers-of-Tau/Groth16 setup is explicitly a single-local-contribution test artifact, not a multi-party ceremony; a real deployment would need one.
5. **Deep LPU integration** — deliberately not done in this phase (see "Integration with FairLend"); would require a considered decision about issuing real Bank/CA credentials under a circuit-friendly key from the outset, which touches key-management design beyond this phase's scope.
