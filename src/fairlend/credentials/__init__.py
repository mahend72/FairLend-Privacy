"""Credential construction: account, credit-score, and protected-attribute
credentials."""
from __future__ import annotations

from fairlend.credentials.account import AccountCredential, issue_account_credential
from fairlend.credentials.protected_attribute import (
    ProtectedAttributeCredential,
    issue_protected_attribute_credential,
)
from fairlend.credentials.score import ScoreCredential, issue_score_credential

__all__ = [
    "AccountCredential",
    "issue_account_credential",
    "ScoreCredential",
    "issue_score_credential",
    "ProtectedAttributeCredential",
    "issue_protected_attribute_credential",
]
