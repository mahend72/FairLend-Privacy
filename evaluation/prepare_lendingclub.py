#!/usr/bin/env python3
"""Load a raw LendingClub (or fixture) CSV, verify its schema, restrict it
to the manuscript's stated 2007-2015 observation period, map repayment
outcomes, classify outcome-eligible populations, and write a dataset
manifest.

Usage (real data):
    python evaluation/prepare_lendingclub.py \\
        --input data/raw/accepted_2007_to_2018Q4.csv \\
        --output data/processed/ \\
        --data-scope real_lendingclub

Usage (synthetic fixture, for pipeline validation only):
    python evaluation/prepare_lendingclub.py \\
        --input tests/fixtures/lendingclub_sample.csv \\
        --output /some/scratch/dir \\
        --data-scope synthetic_fixture

Processing stages, each counted and reported in dataset_summary.json (see
that file's "note" field for the exact accounting):

  1. raw_row_count / raw_column_count: the literal file contents (all data
     rows and all columns, from the true CSV header -- independent of
     which columns are actually loaded into memory).
  2. Only fairlend.data.lendingclub_schema.REQUIRED_COLUMNS are loaded
     into memory (``usecols``), to keep memory proportional to what this
     pipeline actually uses rather than materialising all raw columns of
     a multi-gigabyte export.
  3. Non-data ("footer") rows -- identified by a non-numeric ``id`` -- are
     removed (fairlend.data.lendingclub_schema.remove_non_data_rows).
  4. The TRUE date coverage (min/max ``issue_d``) of the remaining valid
     rows is computed and reported BEFORE any period filtering, so it is
     possible to see whether the supplied file extends beyond the
     manuscript's stated 2007-2015 window.
  5. Rows outside ``configs/evaluation.yaml``'s ``dataset_period``
     ([start_year, end_year], inclusive) are removed
     (fairlend.data.lendingclub_schema.filter_to_issue_year_range) -- this
     is an explicit, documented filtering rule, not a silent truncation.
  6. The repayment-outcome mapping and MODEL_ELIGIBLE/UNRESOLVED_OUTCOME/
     AUDIT_ELIGIBLE population classification are applied to the
     period-filtered result -- this is the "cleaned" population that
     downstream scripts (split_dataset.py etc.) consume.

This script does NOT force the manuscript's stated ~890,000 cleaned-row
figure; every count above is reported as actually observed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fairlend.core.config import load_evaluation_config
from fairlend.data.lendingclub_schema import (
    REQUIRED_COLUMNS,
    date_coverage,
    filter_to_issue_year_range,
    read_csv_header,
    remove_non_data_rows,
)
from fairlend.data.loader import (
    VALID_DATA_SCOPES,
    build_raw_manifest,
    load_raw_lendingclub,
    results_subdir,
    save_json,
    stamp_data_scope,
)
from fairlend.data.outcomes import map_repayment_outcome, unmapped_statuses
from fairlend.data.populations import classify_outcome_populations

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "evaluation.yaml"

# Manuscript Sec. 6.1.1 states "over two million loan records from 2007 to
# 2015 ... approximately 890,000 observations with 75 variables" after
# preprocessing -- reported here for comparison only, never enforced.
MANUSCRIPT_REPORTED_CLEANED_ROWS_APPROX = 890_000
MANUSCRIPT_REPORTED_COLUMNS_APPROX = 75


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the raw LendingClub (or fixture) CSV (not committed to git).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Directory to write the outcome-mapped, period-filtered processed table into.",
    )
    parser.add_argument(
        "--data-scope",
        required=True,
        choices=VALID_DATA_SCOPES,
        help="Whether this run is over the real LendingClub file or the "
        "synthetic test fixture. No default -- must be stated explicitly.",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to evaluation.yaml (default: {DEFAULT_CONFIG_PATH}).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_evaluation_config(args.config)

    print(f"[{args.data_scope}] Inspecting schema of: {args.input}")
    header = read_csv_header(args.input)
    print(f"Raw column count (true file header): {len(header)}")

    missing_required = [c for c in REQUIRED_COLUMNS if c not in header]
    if missing_required:
        print(
            f"ERROR: required column(s) not found in the supplied file: "
            f"{missing_required!r}. This may be a different LendingClub "
            "export schema than the one this pipeline expects -- refusing "
            "to guess a substitute column.",
            file=sys.stderr,
        )
        return 1
    print(f"All required columns present: {REQUIRED_COLUMNS}")

    print(f"Loading only {REQUIRED_COLUMNS} into memory (usecols)...")
    df = load_raw_lendingclub(args.input, usecols=REQUIRED_COLUMNS)
    manifest = build_raw_manifest(args.input, df, columns=header)
    print(
        f"raw_row_count={manifest.raw_row_count} "
        f"raw_column_count={manifest.raw_column_count} sha256={manifest.sha256}"
    )

    df_valid, n_footer_removed = remove_non_data_rows(df, id_column="id")
    print(f"Removed {n_footer_removed} non-data (footer/summary) row(s).")

    true_min_date, true_max_date = date_coverage(df_valid["issue_d"])
    period = config.dataset_period
    covers_beyond_manuscript_period = (
        pd_year(true_max_date) > period.end_year or pd_year(true_min_date) < period.start_year
    )
    print(
        f"True date coverage (post footer-removal, pre period-filter): "
        f"{true_min_date} .. {true_max_date}"
    )
    if covers_beyond_manuscript_period:
        print(
            f"NOTE: supplied file's date coverage extends beyond the "
            f"manuscript's stated {period.start_year}-{period.end_year} "
            f"period. Filtering to issue_d in [{period.start_year}, "
            f"{period.end_year}] per configs/evaluation.yaml -- see "
            "dataset_summary.json's 'manuscript_period_filter' field."
        )

    df_period, n_out_of_period_removed = filter_to_issue_year_range(
        df_valid, period.issue_date_column, period.start_year, period.end_year
    )
    print(
        f"Removed {n_out_of_period_removed} row(s) outside "
        f"[{period.start_year}, {period.end_year}]. "
        f"Rows remaining (cleaned population): {len(df_period)}"
    )

    if "loan_status" not in df_period.columns:
        print("ERROR: 'loan_status' missing after loading -- should be unreachable.", file=sys.stderr)
        return 1

    unmapped = unmapped_statuses(df_period["loan_status"], config.outcome_mapping)
    if len(unmapped) > 0:
        print(
            "WARNING: the following loan_status values are not covered by "
            "configs/evaluation.yaml's outcome_mapping (positive/negative/"
            "excluded) and will be treated as unresolved outcomes until the "
            "config is updated:",
            file=sys.stderr,
        )
        print(unmapped.to_string(), file=sys.stderr)

    df_period = df_period.copy()
    df_period["fairlend_outcome"] = map_repayment_outcome(
        df_period["loan_status"], config.outcome_mapping
    )
    outcome_counts = df_period["fairlend_outcome"].value_counts(dropna=False).to_dict()
    outcome_counts = {str(k): int(v) for k, v in outcome_counts.items()}

    populations = classify_outcome_populations(df_period["fairlend_outcome"])
    population_counts = populations.counts()
    print(
        f"model_eligible={population_counts['model_eligible']} "
        f"unresolved_outcome={population_counts['unresolved_outcome']} "
        f"audit_eligible={population_counts['audit_eligible']}"
    )

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    processed_path = output_dir / "loan_with_outcome.parquet"
    df_period.to_parquet(processed_path, index=False)
    print(f"Wrote processed table (loaded columns + fairlend_outcome) to {processed_path}")

    dataset_summary = stamp_data_scope(
        {
            "input_path": manifest.input_path,
            "sha256": manifest.sha256,
            "raw_row_count": manifest.raw_row_count,
            "raw_column_count": manifest.raw_column_count,
            "columns_loaded": REQUIRED_COLUMNS,
            "footer_rows_removed": n_footer_removed,
            "valid_data_row_count": len(df_valid),
            "true_date_coverage": {"min": true_min_date, "max": true_max_date},
            "covers_dates_beyond_manuscript_period": covers_beyond_manuscript_period,
            "manuscript_period_filter": {
                "issue_date_column": period.issue_date_column,
                "start_year": period.start_year,
                "end_year": period.end_year,
            },
            "rows_outside_manuscript_period_removed": n_out_of_period_removed,
            "cleaned_row_count": len(df_period),
            "outcome_counts": outcome_counts,
            "population_counts": population_counts,
            "unmapped_loan_status_values": {
                str(k): int(v) for k, v in unmapped.to_dict().items()
            },
            "manuscript_reported_cleaned_rows_approx": MANUSCRIPT_REPORTED_CLEANED_ROWS_APPROX,
            "manuscript_reported_columns_approx": MANUSCRIPT_REPORTED_COLUMNS_APPROX,
            "note": (
                "raw_row_count/raw_column_count are the literal file "
                "contents (all data rows incl. footer rows; the true CSV "
                "header's column count). footer_rows_removed rows are "
                "excluded as non-data (non-numeric id). valid_data_row_count "
                "is post-footer-removal, pre-period-filter. "
                "rows_outside_manuscript_period_removed rows are then "
                "excluded per manuscript_period_filter. cleaned_row_count "
                "= valid_data_row_count - rows_outside_manuscript_period_removed "
                "is what is compared to manuscript_reported_cleaned_rows_approx "
                "and is the population outcome_counts/population_counts "
                "describe. population_counts.model_eligible is eligible for "
                "supervised credit-model train/validation/test fitting; "
                "population_counts.audit_eligible is the full cleaned "
                "population (see fairlend.data.populations for rationale)."
            ),
        },
        args.data_scope,
    )
    summary_path = results_subdir(REPO_ROOT, args.data_scope, "evaluation") / "dataset_summary.json"
    save_json(dataset_summary, summary_path)
    print(f"Wrote dataset summary to {summary_path}")

    manifest_dict = stamp_data_scope(manifest.to_dict(), args.data_scope)
    manifest_path = results_subdir(REPO_ROOT, args.data_scope, "metadata") / "dataset_manifest.json"
    save_json(manifest_dict, manifest_path)
    print(f"Wrote dataset manifest to {manifest_path}")

    return 0


def pd_year(month_year_str: str) -> int:
    """Parse "Mon-YYYY" -> YYYY as int (small local helper to avoid a
    pandas import just for this one comparison)."""
    return int(month_year_str.split("-")[1])


if __name__ == "__main__":
    raise SystemExit(main())
