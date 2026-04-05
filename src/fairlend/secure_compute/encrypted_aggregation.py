"""Public facade over encrypted per-group aggregate construction.

This module re-exports the canonical implementation in
``fairlend.audit.aggregation`` unchanged. There is no second
implementation here -- only a stable import path for library consumers.

PHASE 1: the production names below (``compute_encrypted_audit``,
``EncryptedAuditResult``, ``EncryptedAuditPacket``, ``EncryptedAuditCounts``)
now refer to the direct encrypted-additive aggregation path (no compSim,
no reference vectors, multiplicative depth 0). The legacy compSim-based
implementation remains importable under its explicit ``_legacy_compsim``/
``Legacy*`` names -- see ``fairlend.audit.aggregation``'s module
docstring and reviewer2_phase1_compsim_removal_report.md.
"""
from __future__ import annotations

from fairlend.audit.aggregation import (
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
    build_encrypted_aggregate_packet,
    build_encrypted_aggregate_packet_legacy_compsim,
    compute_encrypted_audit,
    compute_encrypted_audit_legacy_compsim,
    decrypt_audit_packet_for_diagnostics,
    decrypt_audit_packet_for_diagnostics_legacy_compsim,
)

__all__ = [
    "EncryptedTestRecord",
    "EncryptedAuditCounts",
    "EncryptedAuditResult",
    "EncryptedAuditPacket",
    "DecryptedGroupAuditCounts",
    "DecryptedAuditPacket",
    "compute_encrypted_audit",
    "build_encrypted_aggregate_packet",
    "decrypt_audit_packet_for_diagnostics",
    # Legacy (Phase 5, compSim-based) -- retained for equivalence testing.
    "LegacyEncryptedGroupAuditCounts",
    "LegacyEncryptedAuditResult",
    "LegacyEncryptedAuditPacket",
    "LegacySerializedGroupAuditCounts",
    "compute_encrypted_audit_legacy_compsim",
    "build_encrypted_aggregate_packet_legacy_compsim",
    "decrypt_audit_packet_for_diagnostics_legacy_compsim",
]
