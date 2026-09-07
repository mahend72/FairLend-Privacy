"""LendingClub-specific schema handling: header inspection, non-data
("footer") row removal, and issue-date period filtering.

Public LendingClub re-exports (e.g. Kaggle's
``accepted_2007_to_2018Q4.csv``) have two properties this module handles
explicitly, as documented, reviewable steps rather than silent
heuristics:

1. **Trailing non-data rows.** Some exports append one or more summary
   rows such as ``"Total amount funded in policy code 1: 1465324575,,,..."``
   after the real data. These are not loan records: they have a
   non-numeric ``id``. ``remove_non_data_rows`` filters them out and
   reports exactly how many were removed, rather than assuming they don't
   exist (as the manuscript's own preprocessing description --
   "removing incomplete or inconsistent records" -- suggests some such
   cleaning step was applied).

2. **Date coverage beyond the manuscript's stated period.** The
   manuscript's evaluation (Sec. 6.1.1) states "LendingClub Loan Data,
   2007-2015." Public re-exports frequently cover a longer period (the
   file named ``accepted_2007_to_2018Q4.csv`` covers through 2018Q4 by
   its own filename). ``filter_to_issue_year_range`` restricts to the
   configured ``[start_year, end_year]`` window (inclusive) using the
   ``issue_d`` column (format ``"Mon-YYYY"``, e.g. ``"Dec-2015"``), and
   reports how many rows were excluded for being outside it. This
   filtering is driven by ``configs/evaluation.yaml``'s
   ``dataset_period`` block, never a hidden constant.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import List, Tuple

import pandas as pd

# The only raw columns any current FairLend evaluation component reads.
# Restricting to these via `usecols` when loading the full multi-GB
# LendingClub export keeps memory usage proportional to what is actually
# used, rather than materialising all ~151 raw columns.
REQUIRED_COLUMNS: List[str] = [
    "id",
    "loan_status",
    "annual_inc",
    "emp_length",
    "dti",
    "home_ownership",
    "addr_state",
    "issue_d",
]


def read_csv_header(path: str | Path) -> List[str]:
    """The literal header row of the raw CSV, independent of any
    ``usecols`` restriction used when actually loading data -- this is how
    ``raw_column_count`` can be reported truthfully even when only a
    subset of columns is read into memory."""
    with open(path, "r", newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        return next(reader)


def remove_non_data_rows(df: pd.DataFrame, id_column: str = "id") -> Tuple[pd.DataFrame, int]:
    """Remove rows whose ``id_column`` is not a plain integer string (the
    trailing summary/footer rows described in the module docstring).

    Returns:
        (cleaned_df, n_removed)
    """
    is_valid_id = df[id_column].astype(str).str.strip().str.fullmatch(r"\d+")
    is_valid_id = is_valid_id.fillna(False)
    n_removed = int((~is_valid_id).sum())
    return df.loc[is_valid_id].copy(), n_removed


def parse_issue_date(issue_d: pd.Series) -> pd.Series:
    """Parse LendingClub's ``issue_d`` format ("Mon-YYYY", e.g.
    "Dec-2015") into ``datetime64``."""
    return pd.to_datetime(issue_d, format="%b-%Y")


def date_coverage(issue_d: pd.Series) -> Tuple[str, str]:
    """(min, max) of ``issue_d``, formatted back as "Mon-YYYY" strings for
    human-readable reporting."""
    parsed = parse_issue_date(issue_d)
    return (
        parsed.min().strftime("%b-%Y"),
        parsed.max().strftime("%b-%Y"),
    )


def filter_to_issue_year_range(
    df: pd.DataFrame, issue_date_column: str, start_year: int, end_year: int
) -> Tuple[pd.DataFrame, int]:
    """Restrict ``df`` to rows whose ``issue_date_column`` year is in
    ``[start_year, end_year]`` (inclusive).

    Returns:
        (filtered_df, n_removed_outside_period)
    """
    parsed = parse_issue_date(df[issue_date_column])
    mask = (parsed.dt.year >= start_year) & (parsed.dt.year <= end_year)
    n_removed = int((~mask).sum())
    return df.loc[mask].copy(), n_removed
