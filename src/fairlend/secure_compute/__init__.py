"""Reusable privacy-preserving computation primitives -- the public facade
over FairLend's encrypted-compute path.

``fairlend.secure_compute`` is a re-export layer, not a second
implementation: every name below is imported unchanged from its canonical
home (``fairlend.crypto.ckks``, ``fairlend.audit.similarity``,
``fairlend.audit.aggregation``, ``fairlend.audit.reconstruction``). Prefer
importing from here when building on FairLend as a library; the canonical
modules remain available for code that is already tied to them.

Typical flow::

    from fairlend.secure_compute import (
        build_fla_context,
        derive_lpu_context,
        generate_encrypted_references,
        load_reference_vectors,
        comp_sim,
        compute_encrypted_audit,
        build_encrypted_aggregate_packet,
        decrypt_audit_packet_for_diagnostics,
        compute_fairness_reconstruction,
    )

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    assert fla_context.has_secret_key()
    assert not lpu_context.has_secret_key()
"""
from __future__ import annotations

from fairlend.secure_compute.ckks import (
    build_fla_context,
    context_can_decrypt,
    derive_lpu_context,
)
from fairlend.secure_compute.encrypted_aggregation import (
    DecryptedAuditPacket,
    DecryptedGroupAuditCounts,
    EncryptedAuditPacket,
    EncryptedAuditResult,
    EncryptedGroupAuditCounts,
    EncryptedTestRecord,
    build_encrypted_aggregate_packet,
    compute_encrypted_audit,
    decrypt_audit_packet_for_diagnostics,
)
from fairlend.secure_compute.reconstruction import (
    AggregateReconstructionResult,
    FairnessReconstructionResult,
    compute_aggregate_reconstruction,
    compute_fairness_reconstruction,
)
from fairlend.secure_compute.similarity import (
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
    # crypto/ckks.py
    "build_fla_context",
    "derive_lpu_context",
    "context_can_decrypt",
    # audit/similarity.py
    "EncryptedReferenceVectors",
    "LoadedReferenceVectors",
    "EncryptedSimilarityPair",
    "SerializedSimilarityPair",
    "generate_encrypted_references",
    "load_reference_vectors",
    "comp_sim",
    "decrypt_similarity_pair_for_diagnostics",
    # audit/aggregation.py
    "EncryptedTestRecord",
    "EncryptedGroupAuditCounts",
    "EncryptedAuditResult",
    "EncryptedAuditPacket",
    "DecryptedGroupAuditCounts",
    "DecryptedAuditPacket",
    "compute_encrypted_audit",
    "build_encrypted_aggregate_packet",
    "decrypt_audit_packet_for_diagnostics",
    # audit/reconstruction.py
    "AggregateReconstructionResult",
    "FairnessReconstructionResult",
    "compute_aggregate_reconstruction",
    "compute_fairness_reconstruction",
]
