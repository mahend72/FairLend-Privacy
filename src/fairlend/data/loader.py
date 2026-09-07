"""Raw LendingClub CSV loading, hashing, and dataset manifest construction.

Manuscript Sec. 6.1.1: "over two million loan records from 2007 to 2015 ...
After standard preprocessing ... approximately 890,000 observations with 75
variables." This module does not assume, force, or hardcode those figures;
it loads whatever file it is given, reports what is actually there, and
records enough metadata (a SHA-256 of the input file, in particular) that a
later comparison to the manuscript's stated scale can be made honestly (see
docs/MANUSCRIPT_EVIDENCE_STATUS.md).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd


def compute_sha256(path: str | Path, chunk_size: int = 1 << 20) -> str:
    """SHA-256 of the raw file at ``path``, streamed so this works on
    multi-gigabyte LendingClub exports without loading the whole file into
    memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class RawDatasetManifest:
    """Facts about the raw file actually supplied, independent of any
    manuscript claim about what those facts "should" be."""

    input_path: str
    sha256: str
    raw_row_count: int
    raw_column_count: int
    columns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_path": self.input_path,
            "sha256": self.sha256,
            "raw_row_count": self.raw_row_count,
            "raw_column_count": self.raw_column_count,
            "columns": self.columns,
        }


def load_raw_lendingclub(
    input_path: str | Path,
    usecols: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Load the raw LendingClub CSV at ``input_path`` exactly as supplied.

    No column is invented if missing: if ``usecols`` names columns not
    present in the file, pandas raises rather than silently proceeding
    with a subset, so a schema mismatch against a different LendingClub
    export vintage surfaces immediately instead of producing a quietly
    incomplete run.

    Some public LendingClub exports include trailing summary/footer rows
    or a leading disclaimer row; this loader does not attempt to detect or
    strip those heuristically -- if present, they must be handled by the
    caller (e.g. via ``skiprows``/``skipfooter`` supplied explicitly), so
    that no row is silently dropped without it being a documented,
    reviewable decision.
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(
            f"LendingClub input file not found at {input_path}. This "
            "repository does not redistribute the dataset -- see "
            "data/README.md for how to obtain it and the expected local "
            "path."
        )
    return pd.read_csv(input_path, usecols=usecols, low_memory=False)


def build_raw_manifest(
    input_path: str | Path,
    df: pd.DataFrame,
    columns: Optional[List[str]] = None,
) -> RawDatasetManifest:
    """Build the manifest for the raw file at ``input_path``.

    Args:
        df: The loaded (possibly ``usecols``-restricted) DataFrame, used
            for ``raw_row_count`` (accurate regardless of column
            restriction -- ``usecols`` never drops rows) and, if
            ``columns`` is not given, for ``columns``/``raw_column_count``.
        columns: The TRUE full header of the raw file (e.g. from
            ``fairlend.data.lendingclub_schema.read_csv_header``), to use
            when ``df`` was loaded with a ``usecols`` restriction smaller
            than the file's actual schema. If omitted, ``df.columns`` is
            assumed to already be the full raw schema.
    """
    input_path = Path(input_path)
    resolved_columns = columns if columns is not None else list(df.columns)
    return RawDatasetManifest(
        input_path=str(input_path),
        sha256=compute_sha256(input_path),
        raw_row_count=len(df),
        raw_column_count=len(resolved_columns),
        columns=resolved_columns,
    )


def save_json(data: Dict[str, Any], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


# --- Data-scope labelling -------------------------------------------------
#
# Fixture-derived (synthetic, non-LendingClub) result artifacts must never
# be mistaken for results computed on the real dataset. Every JSON result
# this codebase writes is stamped via `stamp_data_scope`, and every such
# result is routed to a physically separate directory tree via
# `results_subdir`, so a fixture run cannot silently populate (or be
# confused with) `results/evaluation/`, `results/metadata/`, or
# `results/benchmarks/`, which are reserved for real-data runs.

REAL_DATA_SCOPE = "real_lendingclub"
FIXTURE_DATA_SCOPE = "synthetic_fixture"
VALID_DATA_SCOPES = (REAL_DATA_SCOPE, FIXTURE_DATA_SCOPE)


def stamp_data_scope(data: Dict[str, Any], data_scope: str) -> Dict[str, Any]:
    """Return a copy of ``data`` with explicit ``data_scope`` /
    ``is_real_lendingclub`` keys added.

    Args:
        data_scope: One of ``REAL_DATA_SCOPE`` ("real_lendingclub") or
            ``FIXTURE_DATA_SCOPE`` ("synthetic_fixture"). There is no
            default -- every caller must say which one this run is.
    """
    if data_scope not in VALID_DATA_SCOPES:
        raise ValueError(
            f"data_scope must be one of {VALID_DATA_SCOPES!r}, got {data_scope!r}"
        )
    stamped = dict(data)
    stamped["data_scope"] = data_scope
    stamped["is_real_lendingclub"] = data_scope == REAL_DATA_SCOPE
    return stamped


def results_subdir(repo_root: str | Path, data_scope: str, kind: str) -> Path:
    """The correct output directory for a result of the given ``kind``
    (e.g. "evaluation", "metadata", "benchmarks"), routed by
    ``data_scope`` so fixture and real-data outputs can never land in the
    same directory.
    """
    if data_scope not in VALID_DATA_SCOPES:
        raise ValueError(
            f"data_scope must be one of {VALID_DATA_SCOPES!r}, got {data_scope!r}"
        )
    repo_root = Path(repo_root)
    if data_scope == REAL_DATA_SCOPE:
        return repo_root / "results" / kind
    return repo_root / "results" / "fixture_validation" / kind
