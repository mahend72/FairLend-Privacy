"""Public facade over encrypted per-group aggregate construction.

This module re-exports the canonical implementation in
``fairlend.audit.aggregation`` unchanged. There is no second
implementation here -- only a stable import path for library consumers.
"""
from __future__ import annotations

from fairlend.audit.aggregation import (
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

__all__ = [
    "EncryptedTestRecord",
    "EncryptedGroupAuditCounts",
    "EncryptedAuditResult",
    "EncryptedAuditPacket",
    "DecryptedGroupAuditCounts",
    "DecryptedAuditPacket",
    "compute_encrypted_audit",
    "build_encrypted_aggregate_packet",
    "decrypt_audit_packet_for_diagnostics",
]
