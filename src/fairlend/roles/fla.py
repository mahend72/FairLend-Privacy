"""Fair Lending Auditor (FLA) role.

The FLA is the sole holder of ``sk_HE`` (manuscript Sec. 4.2 Algorithm 1:
``FLA: store(sk_HE)``; Sec. 4.8). This module currently implements only key
ownership (Phase 4); aggregate decryption and fairness-metric computation
are added in later phases.
"""
from __future__ import annotations

import tenseal as ts

from fairlend.core.exceptions import KeyBoundaryError
from fairlend.crypto.ckks import context_can_decrypt


class FairLendingAuditor:
    """The FLA. Constructible only with the private CKKS context (sk_HE,
    pk_HE, evk_HE)."""

    def __init__(self, he_context: ts.Context) -> None:
        if not context_can_decrypt(he_context):
            raise KeyBoundaryError(
                "FairLendingAuditor must be constructed with the private "
                "CKKS context that holds sk_HE. Use "
                "fairlend.crypto.ckks.build_fla_context() to create it."
            )
        self._he_context = he_context

    @property
    def he_context(self) -> ts.Context:
        """The FLA's private CKKS context (sk_HE, pk_HE, evk_HE)."""
        return self._he_context
