"""Public facade over BFV context management (Phase 2, ACTIVE protocol).

This module re-exports the canonical implementation in
``fairlend.crypto.bfv`` unchanged; see that module's docstring for the
LPU/FLA key-separation contract these functions enforce, and for the
BFV-specific relinearisation/Galois-key stripping behaviour. There is no
second implementation here -- only a stable import path for library
consumers.
"""
from __future__ import annotations

from fairlend.crypto.bfv import (
    build_fla_context,
    context_can_decrypt,
    derive_lpu_context,
)

__all__ = [
    "build_fla_context",
    "derive_lpu_context",
    "context_can_decrypt",
]
