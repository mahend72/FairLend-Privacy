pragma circom 2.0.0;

// R_acc (manuscript Sec. 4.1, "Account-validity relation"):
//
//   x_acc,i = (pk_b_sig, uid_i, C_acc,i)
//   w_acc,i = (acc_i, sigma_b,i, r_acc,i)
//
//   R_acc(x,w) = 1  iff
//       VerifySig(pk_b_sig, uid_i || acc_i, sigma_b,i) = 1
//       AND
//       C_acc,i = Com(uid_i || acc_i; r_acc,i)
//
// CONCRETE PRIMITIVE SUBSTITUTION (see
// reviewer2_phase3b_nizkp_instantiation_report.md, "Manuscript-to-concrete
// primitive mapping" -- documented here, not hidden):
//
//   - Sign/VerifySig: the manuscript's generic signature scheme is
//     instantiated, INSIDE THIS CIRCUIT ONLY, as EdDSA over Baby Jubjub
//     with a Poseidon hash (circomlib's EdDSAPoseidonVerifier) -- NOT the
//     Ed25519 (Curve25519) scheme fairlend.crypto.signatures/
//     fairlend.roles.bank use elsewhere in this codebase for the SAME
//     Bank-account-credential signature. Ed25519 verification is not
//     efficiently expressible as an R1CS circuit; EdDSA-Poseidon is the
//     standard circuit-friendly substitute in this proving-system family.
//     A production system would need either a from-scratch Ed25519-
//     in-circuit verifier (a much larger, separate engineering effort) or
//     would issue account credentials directly under an EdDSA-Poseidon
//     key from the outset.
//   - Com: the manuscript's generic, unspecified commitment scheme is
//     instantiated as a Poseidon-hash commitment, Com(uid,acc;r) =
//     Poseidon(uid, acc, r) -- computationally binding under Poseidon's
//     collision resistance, computationally hiding given r is sampled
//     uniformly at random from the scalar field and never reused.
//   - uid_i, acc_i, r_acc,i are each represented as single BN254 scalar-
//     field elements (Fr, ~254 bits) -- the Python-side encoding that
//     maps this codebase's actual uid (a string) and acc (an
//     AccountCredential's account-number field) into Fr is documented in
//     src/fairlend/nizkp/r_acc.py, not inside this circuit.
//
// Public inputs:  Ax, Ay (pk_b_sig, a Baby Jubjub point), uid, Cacc
// Private witness: acc, r_acc, S, R8x, R8y (the EdDSA-Poseidon signature)

include "poseidon.circom";
include "eddsaposeidon.circom";

template RAcc() {
    signal input Ax;
    signal input Ay;
    signal input uid;
    signal input Cacc;

    signal input acc;
    signal input r_acc;
    signal input S;
    signal input R8x;
    signal input R8y;

    // Message the Bank signed: M = Poseidon(uid, acc) -- stands in for
    // the manuscript's "uid_i || acc_i" concatenation.
    component msgHasher = Poseidon(2);
    msgHasher.inputs[0] <== uid;
    msgHasher.inputs[1] <== acc;

    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== Ax;
    sigVerifier.Ay <== Ay;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // Commitment opening: Cacc == Poseidon(uid, acc, r_acc).
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== uid;
    commitmentHasher.inputs[1] <== acc;
    commitmentHasher.inputs[2] <== r_acc;

    Cacc === commitmentHasher.out;
}

component main {public [Ax, Ay, uid, Cacc]} = RAcc();
