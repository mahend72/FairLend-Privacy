"""Communication-cost tables and projections (Phase 11 Sec. 12-14) --
built PURELY from actual serialized-byte measurements
(``evaluation/run_benchmarks.py`` supplies these); nothing here measures
or claims network latency/bandwidth. Every projected total is a "derived
communication projection" (a serialized-payload-size calculation), never
a network-transfer-time claim.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Sequence

ONE_TIME = "one_time_setup"
PER_APPLICATION = "per_application"
PER_AUDIT_BATCH = "per_audit_batch"
CATEGORIES = (ONE_TIME, PER_APPLICATION, PER_AUDIT_BATCH)


@dataclass(frozen=True)
class CommunicationPathEntry:
    """One row of the communication-cost table (Phase 11 Sec. 12): a
    named protocol flow (``path``), which object(s) it carries, the
    measured byte size, and which cost category it belongs to."""

    path: str
    object_name: str
    measured_bytes: int
    category: str
    notes: str = ""

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"category must be one of {CATEGORIES!r}, got {self.category!r}")
        if self.measured_bytes < 0:
            raise ValueError(f"measured_bytes must be >= 0, got {self.measured_bytes!r}")


def total_bytes_by_category(entries: Sequence[CommunicationPathEntry]) -> Dict[str, int]:
    """Sums measured bytes per category -- the ONE-TIME total must never
    be silently folded into the per-application total (Phase 11 Sec. 12:
    "Do not add one-time key distribution into every application
    cost.")."""
    totals = {category: 0 for category in CATEGORIES}
    for entry in entries:
        totals[entry.category] += entry.measured_bytes
    return totals


def project_total_communication_bytes(
    *, fixed_setup_bytes: int, per_application_bytes: int, audit_packet_bytes: int, n_applications: int
) -> int:
    """Transparent linear formula (Phase 11 Sec. 13): one fixed setup
    payload, ``n_applications`` per-application payloads, and ONE audit
    packet covering the whole batch of ``n_applications`` (matching this
    implementation's actual design -- ``fairlend.audit.aggregation.
    compute_encrypted_audit`` produces exactly one aggregate packet per
    audit run, regardless of population size).

    This is a DERIVED COMMUNICATION PROJECTION (a serialized-payload-size
    calculation), not a network-transfer-time estimate and not a directly
    measured multi-application transfer.
    """
    if n_applications < 0:
        raise ValueError(f"n_applications must be >= 0, got {n_applications!r}")
    return fixed_setup_bytes + n_applications * per_application_bytes + audit_packet_bytes
