"""BFV context management with a structural LPU/FLA key-separation boundary
(Phase 2, reviewer2_phase2_bfv_migration_report.md).

Mirrors ``fairlend.crypto.ckks``'s API and key-separation contract exactly
(``build_fla_context``, ``derive_lpu_context``, ``context_can_decrypt``),
using BFV instead of CKKS: the ACTIVE encrypted-audit-aggregation path
(``fairlend.audit.aggregation.compute_encrypted_audit``, Phase 2) performs
only exact integer addition over one-hot protected-attribute ciphertexts
and releases exact integer counts -- BFV's native domain, with no
approximation, no rescaling, and (for this addition-only workload) no
relinearisation or rotation capability required at all.

BFV-SPECIFIC KEY-MATERIAL DIFFERENCE FROM CKKS (verified empirically):
SEAL auto-generates relinearisation keys at BFV context construction time
(``has_relin_keys()`` is ``True`` immediately after ``ts.context(...)``,
before any explicit ``generate_relin_keys()`` call) -- unlike CKKS, where
this codebase's own Galois-key generation is the only auto-created
evaluation key. Because the direct-addition path never multiplies
ciphertexts, it never needs relinearisation (or Galois/rotation) capability
at all. ``derive_lpu_context`` below therefore round-trips through a
serialize/deserialize cycle with ``save_relin_keys=False`` and
``save_galois_keys=False`` (rather than merely copying and stripping the
secret key, as CKKS's ``derive_lpu_context`` does) -- this produces an LPU
context object whose OWN structural capabilities
(``has_relin_keys()``/``has_galois_keys()``, both ``False``) match exactly
what would actually be transmitted over the wire in a real deployment,
not a superset that happens to still carry unused key material in this
process's memory. This was verified to reduce the serialized LPU-facing
public context from ~2.71 MB to ~0.54 MB at this codebase's parameters
(see reviewer2_phase2_bfv_migration_report.md), and addition still works
correctly on the fully-stripped context.
"""
from __future__ import annotations

import tenseal as ts

from fairlend.core.config import BFVConfig
from fairlend.core.exceptions import KeyBoundaryError


def build_fla_context(config: BFVConfig | None = None) -> ts.Context:
    """Build the FLA's private BFV context (holds the BFV secret key).

    Args:
        config: BFV parameters. Defaults to this codebase's derived
            values (see ``fairlend.core.config.BFVConfig`` for the full
            derivation and justification); do not override this without
            an explicit, separately documented reason.

    Returns:
        A private ``tenseal.Context``. Relinearisation keys are present
        (SEAL auto-generates them for BFV at construction -- there is no
        constructor flag to suppress this), but this codebase never uses
        them and never transmits them (see ``derive_lpu_context``).
    """
    config = config or BFVConfig()
    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=config.poly_modulus_degree,
        plain_modulus=config.plain_modulus,
        coeff_mod_bit_sizes=list(config.coeff_mod_bit_sizes),
    )
    return context


def derive_lpu_context(fla_context: ts.Context) -> ts.Context:
    """Derive the LPU's public BFV evaluation context from the FLA's
    private one.

    Unlike CKKS's ``derive_lpu_context`` (copy + strip secret key only,
    because Galois keys ARE needed for compSim's ``.dot()``/``.sum()``),
    this round-trips through serialization with BOTH
    ``save_relin_keys=False`` and ``save_galois_keys=False``, since the
    direct-addition path needs neither -- the returned context's own
    ``has_relin_keys()``/``has_galois_keys()`` are both ``False``,
    matching exactly what is actually transmittable, not a superset.

    Args:
        fla_context: The FLA's private context, as returned by
            ``build_fla_context``.

    Returns:
        A public ``tenseal.Context`` with ``has_secret_key() is False``,
        ``has_relin_keys() is False``, ``has_galois_keys() is False``.

    Raises:
        KeyBoundaryError: If ``fla_context`` does not itself hold a secret
            key (i.e. this was called on an already-public context).
    """
    if not fla_context.has_secret_key():
        raise KeyBoundaryError(
            "derive_lpu_context() requires the FLA's private context "
            "(holding the BFV secret key) as input; received a context "
            "that already has no secret key. This usually means an "
            "LPU-derived context was passed in by mistake."
        )
    working_copy = fla_context.copy()
    working_copy.make_context_public()
    public_bytes = working_copy.serialize(
        save_secret_key=False, save_galois_keys=False, save_relin_keys=False
    )
    return ts.context_from(public_bytes)


def context_can_decrypt(context: ts.Context) -> bool:
    """Structural decryption-capability check -- identical contract to
    ``fairlend.crypto.ckks.context_can_decrypt``, just for a BFV context."""
    return bool(context.has_secret_key())
