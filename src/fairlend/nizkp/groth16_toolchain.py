"""Generic subprocess orchestration over the circom + snarkjs Groth16
toolchain (Phase 3B, reviewer2_phase3b_nizkp_instantiation_report.md).

This module is deliberately RELATION-AGNOSTIC: it knows how to compile a
``.circom`` circuit, run a (locally-generated, test-only) Powers-of-Tau +
Groth16 ``Setup``, and invoke ``Prove``/``Verify`` -- it does not know
anything about R_acc, R_score, or R_bind specifically. ``fairlend.nizkp.r_acc``
is the relation-specific layer built on top of this.

TOOLCHAIN, VERSIONED AND DOCUMENTED (not assumed): ``circom`` 2.0.9
(precompiled Linux binary; the current 2.2.x release requires a newer
glibc than this environment provides -- verified empirically, see
reviewer2_phase3b_nizkp_instantiation_report.md's "Proof-system
configuration" section), ``snarkjs`` 0.7.6, ``circomlib`` 2.0.5,
``circomlibjs`` 0.1.7, all installed via ``npm`` into
``src/fairlend/nizkp/circuits/node_modules`` (gitignored -- reproducible
from ``package.json``, never committed).

SETUP IS NOT A PRODUCTION TRUSTED-SETUP CEREMONY. ``run_full_setup``
below performs a SINGLE local Powers-of-Tau contribution and a SINGLE
local circuit-specific (phase 2) contribution, both from this process's
own CSPRNG-backed entropy (``secrets.token_bytes``) -- adequate for a
reproducible development/benchmarking artifact, explicitly NOT adequate
as a real multi-party trusted setup. This is stated here once, loudly,
rather than left implicit.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

CIRCUITS_DIR = Path(__file__).resolve().parent / "circuits"


class NizkpToolchainError(Exception):
    """Raised when a circom/snarkjs subprocess step fails or a required
    tool/artifact is missing. Never silently swallowed or retried with a
    fabricated result."""


def _find_circom() -> str:
    """Locates the ``circom`` binary -- checks PATH first, then the
    known fallback install location this phase used
    (``~/.local/bin/circom``), since a fresh shell may not have sourced
    the PATH update yet. Never downloads or installs anything itself."""
    found = shutil.which("circom")
    if found:
        return found
    fallback = Path.home() / ".local" / "bin" / "circom"
    if fallback.exists():
        return str(fallback)
    raise NizkpToolchainError(
        "circom compiler not found on PATH or at ~/.local/bin/circom. "
        "See reviewer2_phase3b_nizkp_instantiation_report.md's 'Proof-system "
        "configuration' section for the exact version/install steps."
    )


def _run(cmd: list, cwd: Optional[Path] = None, timeout: Optional[float] = None) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)
    if result.returncode != 0:
        raise NizkpToolchainError(
            f"Command failed (exit {result.returncode}): {' '.join(str(c) for c in cmd)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


@dataclass(frozen=True)
class CircuitPaths:
    """All file paths for one compiled+set-up circuit, rooted at
    ``circuits/build/<name>/``."""

    name: str
    circom_source: Path
    build_dir: Path
    r1cs_path: Path
    sym_path: Path
    wasm_path: Path
    witness_gen_js: Path
    ptau_dir: Path
    ptau_final_path: Path
    zkey_0_path: Path
    zkey_final_path: Path
    vkey_path: Path


def circuit_paths(name: str) -> CircuitPaths:
    build_dir = CIRCUITS_DIR / "build" / name
    ptau_dir = CIRCUITS_DIR / "build" / name / "setup"
    return CircuitPaths(
        name=name,
        circom_source=CIRCUITS_DIR / f"{name}.circom",
        build_dir=build_dir,
        r1cs_path=build_dir / f"{name}.r1cs",
        sym_path=build_dir / f"{name}.sym",
        wasm_path=build_dir / f"{name}_js" / f"{name}.wasm",
        witness_gen_js=build_dir / f"{name}_js" / "generate_witness.js",
        ptau_dir=ptau_dir,
        ptau_final_path=ptau_dir / "pot_final.ptau",
        zkey_0_path=ptau_dir / f"{name}_0000.zkey",
        zkey_final_path=ptau_dir / f"{name}_final.zkey",
        vkey_path=ptau_dir / "verification_key.json",
    )


def compile_circuit(name: str) -> CircuitPaths:
    """circom compile: .circom -> {.r1cs, .sym, _js/*.wasm}. Returns the
    real, tool-reported constraint/wire counts parsed from circom's own
    stdout (never manually estimated) via ``last_compile_stats``
    (module-level, set by this call)."""
    paths = circuit_paths(name)
    paths.build_dir.mkdir(parents=True, exist_ok=True)
    circom = _find_circom()
    stdout = _run(
        [
            circom, str(paths.circom_source),
            "-l", str(CIRCUITS_DIR / "node_modules" / "circomlib" / "circuits"),
            "--r1cs", "--wasm", "--sym",
            "-o", str(paths.build_dir),
        ],
        cwd=CIRCUITS_DIR,
    )
    global _last_compile_stdout
    _last_compile_stdout = stdout
    return paths


_last_compile_stdout: str = ""


def parse_compile_stats(stdout: str) -> dict:
    """Parses circom's own reported constraint/wire counts from its
    compile stdout -- e.g. 'non-linear constraints: 4708'. Returns a
    dict with whatever keys circom printed; never fabricates a count
    circom did not itself report."""
    stats = {}
    for line in stdout.splitlines():
        line = line.strip()
        for key in (
            "template instances", "non-linear constraints", "linear constraints",
            "public inputs", "public outputs", "private inputs", "private outputs",
            "wires", "labels",
        ):
            prefix = f"{key}:"
            if line.startswith(prefix):
                value = line[len(prefix):].strip()
                stats[key.replace(" ", "_")] = int(value)
    return stats


def run_full_setup(name: str, ptau_power: int, entropy_bytes: int = 64) -> CircuitPaths:
    """Powers-of-Tau (phase 1, generated fresh + one local contribution)
    -> phase-2 preparation -> Groth16 setup -> one local circuit-specific
    contribution -> verification-key export. See this module's docstring
    for why this is explicitly NOT a production trusted setup.

    ``ptau_power``: circom reports the exact non-linear-constraint count
    at compile time (see ``parse_compile_stats``); the caller must choose
    ``ptau_power`` such that ``2**ptau_power`` exceeds that count (this
    function does not choose it automatically, so the choice is always
    visible in the calling code/report, not hidden here).
    """
    import secrets

    paths = circuit_paths(name)
    if not paths.r1cs_path.exists():
        raise NizkpToolchainError(f"{paths.r1cs_path} does not exist -- call compile_circuit({name!r}) first.")
    paths.ptau_dir.mkdir(parents=True, exist_ok=True)

    pot_0 = paths.ptau_dir / "pot_0000.ptau"
    pot_1 = paths.ptau_dir / "pot_0001.ptau"

    _run(["npx", "snarkjs", "powersoftau", "new", "bn128", str(ptau_power), str(pot_0), "-v"], cwd=CIRCUITS_DIR, timeout=300)
    _run(
        ["npx", "snarkjs", "powersoftau", "contribute", str(pot_0), str(pot_1),
         "--name=FairLend Phase 3B local test contribution (NOT a production ceremony)",
         "-v", f"-e={secrets.token_hex(entropy_bytes)}"],
        cwd=CIRCUITS_DIR, timeout=300,
    )
    _run(["npx", "snarkjs", "powersoftau", "prepare", "phase2", str(pot_1), str(paths.ptau_final_path), "-v"], cwd=CIRCUITS_DIR, timeout=300)
    _run(["npx", "snarkjs", "groth16", "setup", str(paths.r1cs_path), str(paths.ptau_final_path), str(paths.zkey_0_path)], cwd=CIRCUITS_DIR, timeout=300)
    _run(
        ["npx", "snarkjs", "zkey", "contribute", str(paths.zkey_0_path), str(paths.zkey_final_path),
         "--name=FairLend Phase 3B local test contribution (NOT production)",
         "-v", f"-e={secrets.token_hex(entropy_bytes)}"],
        cwd=CIRCUITS_DIR, timeout=300,
    )
    _run(["npx", "snarkjs", "zkey", "export", "verificationkey", str(paths.zkey_final_path), str(paths.vkey_path)], cwd=CIRCUITS_DIR, timeout=300)

    # Clean up intermediate (non-final) ptau/zkey files -- only the
    # _final artifacts are needed for Prove/Verify.
    for intermediate in (pot_0, pot_1, paths.zkey_0_path):
        intermediate.unlink(missing_ok=True)

    return paths


def groth16_prove(paths: CircuitPaths, input_json: dict, work_dir: Path) -> tuple[dict, list]:
    """Witness generation + Groth16 Prove. Returns (proof, public_signals)
    exactly as snarkjs wrote them -- never post-processed or filtered."""
    work_dir.mkdir(parents=True, exist_ok=True)
    input_path = work_dir / "input.json"
    witness_path = work_dir / "witness.wtns"
    proof_path = work_dir / "proof.json"
    public_path = work_dir / "public.json"

    input_path.write_text(json.dumps(input_json))
    _run(["node", str(paths.witness_gen_js), str(paths.wasm_path), str(input_path), str(witness_path)], cwd=CIRCUITS_DIR)
    _run(["npx", "snarkjs", "groth16", "prove", str(paths.zkey_final_path), str(witness_path), str(proof_path), str(public_path)], cwd=CIRCUITS_DIR)

    proof = json.loads(proof_path.read_text())
    public_signals = json.loads(public_path.read_text())
    return proof, public_signals


def groth16_verify(paths: CircuitPaths, proof: dict, public_signals: list, work_dir: Path) -> bool:
    """Groth16 Verify. Returns True/False based on snarkjs's OWN exit
    code (0 = valid proof, nonzero = invalid) -- never a text-substring
    match on stdout, which would be fragile to snarkjs version drift."""
    work_dir.mkdir(parents=True, exist_ok=True)
    proof_path = work_dir / "verify_proof.json"
    public_path = work_dir / "verify_public.json"
    proof_path.write_text(json.dumps(proof))
    public_path.write_text(json.dumps(public_signals))

    result = subprocess.run(
        ["npx", "snarkjs", "groth16", "verify", str(paths.vkey_path), str(public_path), str(proof_path)],
        capture_output=True, text=True, cwd=CIRCUITS_DIR,
    )
    return result.returncode == 0
