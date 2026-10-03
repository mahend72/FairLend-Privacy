"""Public facade over encrypted per-group aggregate construction.

This module re-exports the canonical implementation in
``fairlend.audit.aggregation`` unchanged. There is no second
implementation here -- only a stable import path for library consumers.

PHASE 2: the production names below (``compute_encrypted_audit``,
``EncryptedAuditResult``, ``EncryptedAuditPacket``, ``EncryptedAuditCounts``)
now refer to the BFV direct-additive aggregation path (no compSim, no
reference vectors, no approximation, multiplicative depth 0, exact
integer output). The Phase 1 CKKS-direct baseline remains importable
under its explicit ``*_ckks_direct``/``CKKSDirect*`` names, and the
legacy compSim-based implementation remains importable under its
explicit ``_legacy_compsim``/``Legacy*`` names -- see
``fairlend.audit.aggregation``'s module docstring,
reviewer2_phase1_compsim_removal_report.md, and
reviewer2_phase2_bfv_migration_report.md.
"""
from __future__ import annotations

from fairlend.audit.aggregation import (
    BFVAuditCounts,
    BFVAuditResult,
    CKKSDirectAuditCounts,
    CKKSDirectAuditPacket,
    CKKSDirectAuditResult,
    DecryptedAuditPacket,
    DecryptedGroupAuditCounts,
    EncryptedAuditCounts,
    EncryptedAuditPacket,
    EncryptedAuditResult,
    EncryptedTestRecord,
    LegacyEncryptedAuditPacket,
    LegacyEncryptedAuditResult,
    LegacyEncryptedGroupAuditCounts,
    LegacySerializedGroupAuditCounts,
    SerializedCKKSDirectAuditCounts,
    assert_population_within_bfv_safe_bound,
    build_encrypted_aggregate_packet,
    build_encrypted_aggregate_packet_ckks_direct,
    build_encrypted_aggregate_packet_legacy_compsim,
    compute_encrypted_audit,
    compute_encrypted_audit_ckks_direct,
    compute_encrypted_audit_legacy_compsim,
    decrypt_audit_packet_for_diagnostics,
    decrypt_audit_packet_for_diagnostics_ckks_direct,
    decrypt_audit_packet_for_diagnostics_legacy_compsim,
)

__all__ = [
    "EncryptedTestRecord",
    # ACTIVE (Phase 2, BFV direct addition) -- canonical names.
    "EncryptedAuditCounts",
    "EncryptedAuditResult",
    "EncryptedAuditPacket",
    "BFVAuditCounts",
    "BFVAuditResult",
    "DecryptedGroupAuditCounts",
    "DecryptedAuditPacket",
    "compute_encrypted_audit",
    "build_encrypted_aggregate_packet",
    "decrypt_audit_packet_for_diagnostics",
    "assert_population_within_bfv_safe_bound",
    # PHASE 1 BASELINE (CKKS direct addition) -- retained for the
    # CKKS-vs-BFV differential comparison.
    "CKKSDirectAuditCounts",
    "CKKSDirectAuditResult",
    "CKKSDirectAuditPacket",
    "SerializedCKKSDirectAuditCounts",
    "compute_encrypted_audit_ckks_direct",
    "build_encrypted_aggregate_packet_ckks_direct",
    "decrypt_audit_packet_for_diagnostics_ckks_direct",
    # LEGACY (Phase 5, compSim-based) -- retained for equivalence testing.
    "LegacyEncryptedGroupAuditCounts",
    "LegacyEncryptedAuditResult",
    "LegacyEncryptedAuditPacket",
    "LegacySerializedGroupAuditCounts",
    "compute_encrypted_audit_legacy_compsim",
    "build_encrypted_aggregate_packet_legacy_compsim",
    "decrypt_audit_packet_for_diagnostics_legacy_compsim",
]
