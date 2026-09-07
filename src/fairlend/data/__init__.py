"""LendingClub data loading, repayment-outcome mapping, leakage-safe
splitting, proxy-feature extraction, and synthetic protected-attribute
generation (manuscript Sec. 6.1).

This package is evaluation-support code: it prepares the records that
feed the credit-decision models and the FairLend audit path, but it is not
part of the cryptographic protocol implementation in ``fairlend.crypto`` /
``fairlend.roles`` / ``fairlend.audit``.
"""
