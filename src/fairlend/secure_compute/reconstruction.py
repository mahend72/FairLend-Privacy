"""Public facade over plaintext/encrypted fairness reconstruction.

This module re-exports the canonical implementation in
``fairlend.audit.reconstruction`` unchanged. There is no second
implementation here -- only a stable import path for library consumers.
"""
from __future__ import annotations

from fairlend.audit.reconstruction import (
    AggregateReconstructionResult,
    FairnessReconstructionResult,
    compute_aggregate_reconstruction,
    compute_fairness_reconstruction,
)

__all__ = [
    "AggregateReconstructionResult",
    "FairnessReconstructionResult",
    "compute_aggregate_reconstruction",
    "compute_fairness_reconstruction",
]
