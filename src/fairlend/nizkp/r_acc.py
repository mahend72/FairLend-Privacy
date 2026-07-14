"""Concrete Groth16 instantiation of the manuscript's R_acc relation
(Phase 3B, reviewer2_phase3b_nizkp_instantiation_report.md).

Manuscript definition (Sec. 4.1, "Account-validity relation"):

    x_acc,i = (pk_b_sig, uid_i, C_acc,i)
    w_acc,i = (acc_i, sigma_b,i, r_acc,i)

    R_acc(x,w) = 1  iff
        VerifySig(pk_b_sig, uid_i || acc_i, sigma_b,i) = 1
        AND
        C_acc,i = Com(uid_i || acc_i; r_acc,i)

CONCRETE PRIMITIVE SUBSTITUTION (see ``circuits/r_acc.circom``'s header
for the full justification -- summarised here):

    Manuscript primitive          -> Concrete primitive (THIS module only)
    ---------------------------------------------------------------------
    Sign/VerifySig (generic)      -> EdDSA over Baby Jubjub + Poseidon
                                      (circomlib's EdDSAPoseidonVerifier)
    Com (generic, unspecified)    -> Poseidon-hash commitment,
                                      Com(uid,acc;r) = Poseidon(uid,acc,r)
    uid_i, acc_i, r_acc,i         -> single BN254 scalar-field elements

This is NOT the same signature scheme fairlend.roles.bank/fairlend.crypto.
signatures use elsewhere in this codebase (Ed25519) -- this module's
"Bank" key is a SEPARATE, circuit-only EdDSA-Poseidon keypair, used only
to demonstrate the R_acc relation's shape end-to-end. It does not
interoperate with, and does not replace, the real Ed25519-signed
``AccountCredential`` issued by ``fairlend.roles.bank.Bank`` elsewhere in
this codebase (see reviewer2_phase3b_nizkp_instantiation_report.md,
"Integration with FairLend").
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from fairlend.nizkp.groth16_toolchain import (
    CircuitPaths,
    NizkpToolchainError,
    _run,
    circuit_paths,
    compile_circuit,
    groth16_prove,
    groth16_verify,
    parse_compile_stats,
    run_full_setup,
)

CIRCUIT_NAME = "r_acc"
_CIRCUITS_DIR = Path(__file__).resolve().parent / "circuits"
_HELPER_JS = _CIRCUITS_DIR / "gen_witness_input.mjs"

# BN254 scalar field order -- Poseidon/EdDSA-Poseidon operate modulo
# this prime. uid_i/acc_i/r_acc,i must each be reduced into this range;
# this module never silently wraps a too-large value without the caller
# knowing (see encode_to_field below).
BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def encode_to_field(value: bytes) -> int:
    """Deterministically maps arbitrary bytes (e.g. this codebase's
    string ``uid``, or an account number) into a BN254 scalar-field
    element via SHA-256 followed by a modular reduction. This is a
    DIFFERENT encoding from fairlend.crypto.hashing's SHA-256 usage
    elsewhere (which never reduces mod a scalar field) -- documented
    here as its own, circuit-specific encoding step, not reused code."""
    import hashlib

    digest = hashlib.sha256(value).digest()
    return int.from_bytes(digest, "big") % BN254_SCALAR_FIELD


@dataclass(frozen=True)
class BankEdDSAPoseidonKey:
    """A circuit-only "Bank" signing key -- NOT fairlend.roles.bank.Bank's
    real Ed25519 key. Generating this key is the one place this module
    touches a private key at all; everything downstream (RAccStatement,
    RAccProof) carries only the public key (Ax, Ay)."""

    private_key_hex: str
    Ax: str
    Ay: str


def generate_bank_signing_key() -> BankEdDSAPoseidonKey:
    out = _run(["node", str(_HELPER_JS), "keygen"], cwd=_CIRCUITS_DIR)
    d = json.loads(out)
    return BankEdDSAPoseidonKey(private_key_hex=d["privateKeyHex"], Ax=d["Ax"], Ay=d["Ay"])


@dataclass(frozen=True)
class RAccStatement:
    """The PUBLIC statement x_acc,i = (pk_b_sig, uid_i, C_acc,i) -- safe
    to reveal to the LPU/verifier in full."""

    Ax: str
    Ay: str
    uid: str
    Cacc: str

    def as_circuit_input(self) -> dict:
        return {"Ax": self.Ax, "Ay": self.Ay, "uid": self.uid, "Cacc": self.Cacc}


@dataclass(frozen=True)
class RAccWitness:
    """The PRIVATE witness w_acc,i = (acc_i, sigma_b,i, r_acc,i) -- never
    logged, never included in any proof/public-input artifact (see
    tests/scientific/test_nizkp_r_acc.py's privacy-inspection test)."""

    acc: str
    r_acc: str
    S: str
    R8x: str
    R8y: str

    def as_circuit_input(self) -> dict:
        return {"acc": self.acc, "r_acc": self.r_acc, "S": self.S, "R8x": self.R8x, "R8y": self.R8y}


@dataclass(frozen=True)
class RAccInstance:
    statement: RAccStatement
    witness: RAccWitness


def issue_r_acc_instance(
    bank_key: BankEdDSAPoseidonKey, uid: int, acc: int, r_acc: Optional[int] = None
) -> RAccInstance:
    """The "Bank issuance" step for this demonstration: signs (uid, acc)
    under the Bank's EdDSA-Poseidon key and computes the account
    commitment -- conceptually analogous to
    fairlend.roles.bank.Bank.issue_account_credential, but producing the
    circuit-compatible signature/commitment this relation's circuit
    checks (see this module's docstring for why). ``r_acc`` defaults to
    a fresh, uniformly random field element if not supplied (never
    reused across instances unless a caller deliberately passes the same
    value, e.g. for a negative test)."""
    if r_acc is None:
        r_acc = secrets.randbelow(BN254_SCALAR_FIELD)
    out = _run(
        ["node", str(_HELPER_JS), "build", bank_key.private_key_hex, str(uid), str(acc), str(r_acc)],
        cwd=_CIRCUITS_DIR,
    )
    d = json.loads(out)
    statement = RAccStatement(Ax=d["Ax"], Ay=d["Ay"], uid=d["uid"], Cacc=d["Cacc"])
    witness = RAccWitness(acc=d["acc"], r_acc=d["r_acc"], S=d["S"], R8x=d["R8x"], R8y=d["R8y"])
    return RAccInstance(statement=statement, witness=witness)


@dataclass(frozen=True)
class RAccProof:
    """A Groth16 proof for R_acc, plus the exact public signals snarkjs
    bound it to (in circom's declared public-input order: Ax, Ay, uid,
    Cacc). Contains no witness field -- see this module's privacy test."""

    proof: dict
    public_signals: list


def setup(ptau_power: int = 13) -> CircuitPaths:
    """Setup(1^lambda): compiles r_acc.circom and runs the (test-only,
    NOT production) Groth16 trusted setup. Idempotent: if the circuit is
    already compiled and set up, this still re-runs it (callers that want
    to skip re-setup should check ``circuit_paths("r_acc").vkey_path.
    exists()`` themselves -- this function does not cache silently)."""
    paths = compile_circuit(CIRCUIT_NAME)
    return run_full_setup(CIRCUIT_NAME, ptau_power=ptau_power)


def prove(instance: RAccInstance, work_dir: Path) -> RAccProof:
    """Prove(pp, x_acc,i, w_acc,i) -> pi_acc,i."""
    paths = circuit_paths(CIRCUIT_NAME)
    if not paths.zkey_final_path.exists():
        raise NizkpToolchainError(
            f"{paths.zkey_final_path} does not exist -- call fairlend.nizkp.r_acc.setup() first."
        )
    input_json = {**instance.statement.as_circuit_input(), **instance.witness.as_circuit_input()}
    proof, public_signals = groth16_prove(paths, input_json, work_dir)
    return RAccProof(proof=proof, public_signals=public_signals)


def verify(proof: RAccProof, work_dir: Path) -> bool:
    """Verify(pp, x_acc,i, pi_acc,i) -> {0,1}, returned as bool. Accepts
    only the proof + its own bundled public_signals -- callers that want
    to check a proof against a DIFFERENT statement than what was proved
    should construct that statement's public_signals list explicitly and
    call this with a modified ``RAccProof`` (see the negative tests)."""
    paths = circuit_paths(CIRCUIT_NAME)
    if not paths.vkey_path.exists():
        raise NizkpToolchainError(
            f"{paths.vkey_path} does not exist -- call fairlend.nizkp.r_acc.setup() first."
        )
    return groth16_verify(paths, proof.proof, proof.public_signals, work_dir)
