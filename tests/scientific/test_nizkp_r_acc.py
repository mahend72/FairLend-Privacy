"""Phase 3B: concrete Groth16 instantiation of R_acc
(reviewer2_phase3b_nizkp_instantiation_report.md).

Requires the circom/snarkjs toolchain (see
src/fairlend/nizkp/groth16_toolchain.py's module docstring for exact
versions) and the compiled circuit + Groth16 keys under
src/fairlend/nizkp/circuits/build/r_acc/ -- both gitignored, both
reproducible by calling ``fairlend.nizkp.r_acc.setup()`` (this module's
own session fixture does so automatically if the artifacts are absent,
which takes several minutes; if already present from a prior run, the
fixture reuses them and is fast).

Positive tests prove Setup/Prove/Verify work end-to-end for a genuine
statement/witness pair. Negative tests prove the verifier rejects
exactly the tamperings listed in reviewer2_phase3b_nizkp_instantiation_
report.md's task item 12 that are actually applicable to R_acc (R_acc has
no protected-attribute/categorical/application-identifier fields, so
those specific item-12 sub-cases are not applicable here and are not
faked into existence).
"""
from __future__ import annotations

import dataclasses
import json

import pytest

from fairlend.nizkp import r_acc
from fairlend.nizkp.groth16_toolchain import NizkpToolchainError, circuit_paths


@pytest.fixture(scope="session")
def r_acc_setup(tmp_path_factory):
    paths = circuit_paths("r_acc")
    if not paths.vkey_path.exists():
        r_acc.setup(ptau_power=13)
    return circuit_paths("r_acc")


@pytest.fixture(scope="session")
def bank_key():
    return r_acc.generate_bank_signing_key()


@pytest.fixture()
def valid_instance(bank_key):
    return r_acc.issue_r_acc_instance(
        bank_key, uid=r_acc.encode_to_field(b"borrower-test-001"), acc=r_acc.encode_to_field(b"ACC-TEST-001")
    )


# --- Positive: Setup/Prove/Verify work end-to-end ---------------------------


def test_setup_produces_all_expected_artifacts(r_acc_setup):
    assert r_acc_setup.r1cs_path.exists()
    assert r_acc_setup.wasm_path.exists()
    assert r_acc_setup.zkey_final_path.exists()
    assert r_acc_setup.vkey_path.exists()
    # No intermediate (non-final) key material should remain.
    assert not r_acc_setup.zkey_0_path.exists()


def test_valid_proof_verifies(r_acc_setup, valid_instance, tmp_path):
    proof = r_acc.prove(valid_instance, tmp_path / "prove")
    assert r_acc.verify(proof, tmp_path / "verify") is True


def test_public_signals_match_the_statement_in_declared_order(r_acc_setup, valid_instance, tmp_path):
    proof = r_acc.prove(valid_instance, tmp_path / "prove")
    # circom's `component main {public [Ax, Ay, uid, Cacc]}` fixes this order.
    assert proof.public_signals == [
        valid_instance.statement.Ax, valid_instance.statement.Ay,
        valid_instance.statement.uid, valid_instance.statement.Cacc,
    ]


def test_different_valid_instances_produce_different_commitments(r_acc_setup, bank_key):
    i1 = r_acc.issue_r_acc_instance(bank_key, uid=1001, acc=2002)
    i2 = r_acc.issue_r_acc_instance(bank_key, uid=1001, acc=2003)
    assert i1.statement.Cacc != i2.statement.Cacc


# --- Negative: malformed/tampered witness fails at WITNESS GENERATION ------
# (circom's <==/=== constraints reject an inconsistent witness before a
# proof can even be produced -- this is itself a correctness property,
# not merely a Verify-time check.)


def test_wrong_witness_acc_value_fails_witness_generation(r_acc_setup, valid_instance, tmp_path):
    """Item 12.1 (witness changes): substitute a different acc_i than the
    one the Bank actually signed and committed to."""
    tampered_witness = dataclasses.replace(valid_instance.witness, acc=str(int(valid_instance.witness.acc) + 1))
    tampered_instance = r_acc.RAccInstance(statement=valid_instance.statement, witness=tampered_witness)
    with pytest.raises(NizkpToolchainError):
        r_acc.prove(tampered_instance, tmp_path / "prove_bad_witness")


def test_altered_committed_value_fails_witness_generation(r_acc_setup, valid_instance, tmp_path):
    """Item 12.2 (committed value changes): the PUBLIC Cacc is altered
    but the witness (acc, r_acc) that produced the ORIGINAL Cacc is kept
    -- the commitment-opening constraint must fail."""
    tampered_statement = dataclasses.replace(valid_instance.statement, Cacc=str(int(valid_instance.statement.Cacc) + 1))
    tampered_instance = r_acc.RAccInstance(statement=tampered_statement, witness=valid_instance.witness)
    with pytest.raises(NizkpToolchainError):
        r_acc.prove(tampered_instance, tmp_path / "prove_bad_commitment")


def test_wrong_opening_randomness_fails_witness_generation(r_acc_setup, valid_instance, tmp_path):
    """Item 12.4 (wrong opening/randomness): a different r_acc than the
    one actually used to build the public Cacc."""
    tampered_witness = dataclasses.replace(valid_instance.witness, r_acc=str(int(valid_instance.witness.r_acc) + 1))
    tampered_instance = r_acc.RAccInstance(statement=valid_instance.statement, witness=tampered_witness)
    with pytest.raises(NizkpToolchainError):
        r_acc.prove(tampered_instance, tmp_path / "prove_bad_randomness")


def test_forged_signature_fails_witness_generation(r_acc_setup, bank_key, tmp_path):
    """A witness signed by a DIFFERENT (unrelated) key than the public
    pk_b_sig in the statement -- the signature-verification constraint
    must fail."""
    other_key = r_acc.generate_bank_signing_key()
    genuine = r_acc.issue_r_acc_instance(other_key, uid=555, acc=777)
    # Splice the genuine signature onto a statement claiming a DIFFERENT
    # (unrelated) public key.
    forged_statement = dataclasses.replace(genuine.statement, Ax=bank_key.Ax, Ay=bank_key.Ay)
    forged_instance = r_acc.RAccInstance(statement=forged_statement, witness=genuine.witness)
    with pytest.raises(NizkpToolchainError):
        r_acc.prove(forged_instance, tmp_path / "prove_forged_signature")


# --- Negative: valid proof, but tampered/misused AT VERIFY TIME -------------


def test_altered_public_digest_at_verify_time_is_rejected(r_acc_setup, valid_instance, tmp_path):
    """Item 12.3: a genuinely valid proof, but the public Cacc signal
    handed to Verify is altered afterward."""
    proof = r_acc.prove(valid_instance, tmp_path / "prove")
    tampered_signals = list(proof.public_signals)
    tampered_signals[3] = str(int(tampered_signals[3]) + 1)
    tampered_proof = r_acc.RAccProof(proof=proof.proof, public_signals=tampered_signals)
    assert r_acc.verify(tampered_proof, tmp_path / "verify_tampered_digest") is False


def test_proof_reused_against_a_different_statement_is_rejected(r_acc_setup, bank_key, tmp_path):
    """Item 12.5: a proof generated for one statement must not verify
    against a different, unrelated statement's public signals."""
    instance_a = r_acc.issue_r_acc_instance(bank_key, uid=111, acc=222)
    instance_b = r_acc.issue_r_acc_instance(bank_key, uid=333, acc=444)
    proof_a = r_acc.prove(instance_a, tmp_path / "prove_a")
    swapped = r_acc.RAccProof(proof=proof_a.proof, public_signals=list(
        [instance_b.statement.Ax, instance_b.statement.Ay, instance_b.statement.uid, instance_b.statement.Cacc]
    ))
    assert r_acc.verify(swapped, tmp_path / "verify_swapped") is False


def test_malformed_proof_object_is_rejected(r_acc_setup, valid_instance, tmp_path):
    """Item 12.6: a structurally corrupted proof (a curve point field
    zeroed out) must not verify."""
    proof = r_acc.prove(valid_instance, tmp_path / "prove")
    corrupted = json.loads(json.dumps(proof.proof))
    corrupted["pi_a"][0] = "1"  # replace a real curve coordinate with a bogus value
    malformed_proof = r_acc.RAccProof(proof=corrupted, public_signals=proof.public_signals)
    assert r_acc.verify(malformed_proof, tmp_path / "verify_malformed") is False


# --- Privacy/leakage inspection (task item 13) ------------------------------


def test_proof_object_does_not_serialize_witness_fields(r_acc_setup, valid_instance, tmp_path):
    """Field-inspection leakage check ONLY (not a substitute for the
    formal zero-knowledge property, which rests on Groth16 itself, not
    on this test) -- the private witness values (acc, r_acc, S, R8x,
    R8y) must not appear as dict keys anywhere in the serialized proof
    object, and the proof object's only keys are the standard Groth16
    proof fields."""
    proof = r_acc.prove(valid_instance, tmp_path / "prove")
    proof_str = json.dumps(proof.proof)
    witness_field_names = ("acc", "r_acc", "S", "R8x", "R8y")
    for name in witness_field_names:
        assert f'"{name}"' not in proof_str, f"witness field name {name!r} unexpectedly serialized in proof object"
    assert set(proof.proof.keys()) <= {"pi_a", "pi_b", "pi_c", "protocol", "curve"}


def test_public_signals_are_exactly_the_declared_public_statement(r_acc_setup, valid_instance, tmp_path):
    """The public_signals list must contain EXACTLY the 4 declared public
    values (Ax, Ay, uid, Cacc) -- no more, no fewer, and in particular no
    witness value smuggled in as an extra public signal."""
    proof = r_acc.prove(valid_instance, tmp_path / "prove")
    assert len(proof.public_signals) == 4
    witness_values = {
        valid_instance.witness.acc, valid_instance.witness.r_acc,
        valid_instance.witness.S, valid_instance.witness.R8x, valid_instance.witness.R8y,
    }
    assert not (set(proof.public_signals) & witness_values)
