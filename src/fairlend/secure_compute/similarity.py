"""Public facade over encrypted group-similarity computation (compSim).

This module re-exports the canonical implementation in
``fairlend.audit.similarity`` unchanged. There is no second implementation
here -- only a stable import path for library consumers.
"""
from __future__ import annotations

from fairlend.audit.similarity import (
    EncryptedReferenceVectors,
    EncryptedSimilarityPair,
    LoadedReferenceVectors,
    SerializedSimilarityPair,
    comp_sim,
    decrypt_similarity_pair_for_diagnostics,
    generate_encrypted_references,
    load_reference_vectors,
)

__all__ = [
    "EncryptedReferenceVectors",
    "LoadedReferenceVectors",
    "EncryptedSimilarityPair",
    "SerializedSimilarityPair",
    "generate_encrypted_references",
    "load_reference_vectors",
    "comp_sim",
    "decrypt_similarity_pair_for_diagnostics",
]
