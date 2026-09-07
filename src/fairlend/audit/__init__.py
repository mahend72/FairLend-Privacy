"""Encrypted audit pipeline: similarity computation (compSim), aggregate
construction, fairness metrics, and plaintext/encrypted reconstruction
comparison."""
from __future__ import annotations

from fairlend.audit.fairness import (
    DemographicParityResult,
    EqualisedOddsResult,
    compute_demographic_parity,
    compute_equalised_odds,
)

__all__ = [
    "compute_demographic_parity",
    "compute_equalised_odds",
    "DemographicParityResult",
    "EqualisedOddsResult",
]
