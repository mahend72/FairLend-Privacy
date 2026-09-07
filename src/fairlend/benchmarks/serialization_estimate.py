"""Analytical CKKS ciphertext size estimates (Phase 11 Sec. 11).

Every function here returns an ``analytical_estimate_bytes`` value derived
PURELY from CKKS parameters (polynomial modulus degree, the active
modulus chain, ciphertext polynomial count) -- it never inspects, calls,
or depends on TenSEAL/SEAL's actual serialized output. It must never be
labelled, or silently compared as if it were, a measured size --
``evaluation/run_benchmarks.py`` reports this ALONGSIDE (never instead
of) the real ``len(ciphertext.serialize())`` measurement, with an
explicit percentage-difference column.

FORMULA AND ITS KNOWN LIMITATIONS: a fresh CKKS ciphertext in RNS
(residue number system) form is ``num_polys`` degree-``(poly_modulus_
degree - 1)`` polynomials, each coefficient represented once per active
modulus in the chain. This estimate is:

    bytes_per_coefficient = sum(ceil(bits / 8) for bits in active_moduli)
    analytical_estimate_bytes = num_polys * poly_modulus_degree * bytes_per_coefficient

This deliberately OMITS: SEAL/TenSEAL's own container format overhead
(headers, versioning, optional compression), the fact that a real library
may serialize coefficients in a packed/compressed form rather than one
full-width word per coefficient, and any framework-specific metadata. It
is therefore expected to disagree with the measured size by a
non-negligible margin -- see the "measured-vs-analytical" comparison this
module's output feeds, which exists precisely to surface that gap rather
than paper over it.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class AnalyticalCiphertextEstimate:
    poly_modulus_degree: int
    active_moduli_bit_sizes: tuple
    num_polys: int
    bytes_per_coefficient: int
    analytical_estimate_bytes: int


def analytical_ciphertext_bytes(
    poly_modulus_degree: int, active_moduli_bit_sizes: Sequence[int], num_polys: int = 2
) -> AnalyticalCiphertextEstimate:
    """``active_moduli_bit_sizes``: the bit-widths of the moduli STILL
    IN THE CHAIN for this particular ciphertext -- a "fresh" (just
    encrypted, unmultiplied) ciphertext uses the FULL configured chain
    (e.g. this codebase's ``[60, 40, 40, 60]``); a ciphertext that has
    gone through one CKKS multiplication + automatic rescale (e.g. a
    post-``comp_sim`` similarity score -- see
    ``fairlend.audit.aggregation``'s module docstring) has consumed one
    modulus from the chain and so has one FEWER active modulus. Callers
    must pass the chain actually applicable to the ciphertext being
    estimated, never always the full configured chain.

    ``num_polys``: 2 for a standard (non-relinearised-away) ciphertext
    (the ``(c0, c1)`` pair); pass 1 only when estimating a single
    polynomial in isolation (not a realistic wire object on its own).
    """
    if poly_modulus_degree <= 0:
        raise ValueError(f"poly_modulus_degree must be positive, got {poly_modulus_degree!r}")
    if not active_moduli_bit_sizes:
        raise ValueError("active_moduli_bit_sizes must be non-empty")
    if num_polys <= 0:
        raise ValueError(f"num_polys must be positive, got {num_polys!r}")

    bytes_per_coefficient = sum(math.ceil(bits / 8) for bits in active_moduli_bit_sizes)
    estimate = num_polys * poly_modulus_degree * bytes_per_coefficient
    return AnalyticalCiphertextEstimate(
        poly_modulus_degree=poly_modulus_degree,
        active_moduli_bit_sizes=tuple(active_moduli_bit_sizes),
        num_polys=num_polys,
        bytes_per_coefficient=bytes_per_coefficient,
        analytical_estimate_bytes=estimate,
    )


def percentage_difference(measured_bytes: int, analytical_estimate_bytes: int) -> float:
    """``(measured - analytical) / analytical * 100`` -- positive means
    the real implementation's serialized output is LARGER than this
    simplified analytical model predicted (expected, given the omissions
    documented in this module's docstring); returns NaN if the analytical
    estimate is zero (undefined percentage base)."""
    if analytical_estimate_bytes == 0:
        return float("nan")
    return (measured_bytes - analytical_estimate_bytes) / analytical_estimate_bytes * 100.0
