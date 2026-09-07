"""CKKS context management with a structural LPU/FLA key-separation boundary.

Per the manuscript (Sec. 4.2 "Initialisation", Table 1, Sec. 4.8), the FLA is
the sole holder of ``sk_HE``:

    FLA: (pk_HE, sk_HE, evk_HE) <- HE.KeyGen(1^lambda)
    FLA: store(sk_HE)
    FLA -> LPU: send(pk_HE, evk_HE, HE.r_m, HE.r_f)

The LPU receives ``pk_HE`` and the evaluation-key material (``evk_HE``)
required for the permitted homomorphic operations (compSim, Sec. 4.6) but
must never be able to construct a context that can decrypt a CKKS
ciphertext (Threat 1; Security Goal 1: "Protected-attribute confidentiality
from the LPU").

This module enforces that boundary structurally rather than by convention:

- ``build_fla_context`` is the only function in this codebase that creates a
  private (secret-key-bearing) CKKS context.
- ``derive_lpu_context`` is the only sanctioned way to obtain an LPU-side
  context, and it requires an FLA private context as input, from which it
  strips the secret key via TenSEAL's ``make_context_public``.
- ``context_can_decrypt`` reports the structural fact (``has_secret_key()``),
  not a separately-maintained boolean flag, so it cannot drift out of sync
  with what the context actually is.

There is deliberately no function in this module that takes an arbitrary
context and "makes it private" (i.e. that fabricates or injects a secret
key), so a context that has been stripped by ``derive_lpu_context`` can
never regain decryption capability within this codebase.
"""
from __future__ import annotations

import tenseal as ts

from fairlend.core.config import CKKSConfig
from fairlend.core.exceptions import KeyBoundaryError


def build_fla_context(config: CKKSConfig | None = None) -> ts.Context:
    """Build the FLA's private CKKS context (holds sk_HE, pk_HE, evk_HE).

    Corresponds to the FLA's key-generation step in Algorithm 1
    (Initialisation): ``(pk_HE, sk_HE, evk_HE) <- HE.KeyGen(1^lambda)``.

    Args:
        config: CKKS parameters. Defaults to the manuscript's exact values
            (see ``fairlend.core.config.CKKSConfig``); do not override this
            without an explicit, separately documented reason.

    Returns:
        A private ``tenseal.Context`` with Galois keys generated (required
        for the vector rotations TenSEAL uses internally for ``.sum()``,
        which compSim relies on).
    """
    config = config or CKKSConfig()
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=config.poly_modulus_degree,
        coeff_mod_bit_sizes=list(config.coeff_mod_bit_sizes),
    )
    context.global_scale = config.global_scale
    context.generate_galois_keys()
    return context


def derive_lpu_context(fla_context: ts.Context) -> ts.Context:
    """Derive the LPU's public evaluation context from the FLA's private one.

    Corresponds to ``FLA -> LPU: send(pk_HE, evk_HE, HE.r_m, HE.r_f)`` in
    Algorithm 1. The returned context carries the public key and
    evaluation-key material (relinearisation/Galois keys) needed for
    compSim, but has no secret key: ``result.has_secret_key() is False``.

    Args:
        fla_context: The FLA's private context, as returned by
            ``build_fla_context``.

    Returns:
        A public ``tenseal.Context`` suitable for constructing an
        ``LoanProcessingUnit`` (see ``fairlend.roles.lpu``).

    Raises:
        KeyBoundaryError: If ``fla_context`` does not itself hold a secret
            key (i.e. this was called on an already-public context), which
            would indicate a caller error rather than a valid derivation.
    """
    if not fla_context.has_secret_key():
        raise KeyBoundaryError(
            "derive_lpu_context() requires the FLA's private context "
            "(holding sk_HE) as input; received a context that already "
            "has no secret key. This usually means an LPU-derived context "
            "was passed in by mistake."
        )
    lpu_context = fla_context.copy()
    lpu_context.make_context_public(generate_galois_keys=False)
    return lpu_context


def context_can_decrypt(context: ts.Context) -> bool:
    """Structural decryption-capability check.

    Returns True only if ``context`` actually holds ``sk_HE``. This wraps
    TenSEAL's own ``has_secret_key()`` rather than tracking a separate flag,
    so that "can this context decrypt" is always answered from the
    context's real internal state.
    """
    return bool(context.has_secret_key())
