"""Configuration objects for FairLend cryptographic and protocol parameters.

CKKS parameters are fixed at the manuscript-specified values (Sec. 4.6 and
Sec. 6.1.4 of the manuscript: polynomial modulus degree 8192, coefficient
modulus bit sizes [60, 40, 40, 60], global scale 2**40) and must not be
silently changed by later code (see docs/IMPLEMENTATION_GAPS.md, "DO NOT ...
silently change CKKS parameters"). If a different configuration is ever
needed, it must be an explicit, separately named config with its own
justification, not a mutation of these defaults.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


@dataclass(frozen=True)
class CKKSConfig:
    """CKKS parameters exactly as specified in the manuscript.

    Attributes:
        poly_modulus_degree: CKKS ring dimension (manuscript: 8192).
        coeff_mod_bit_sizes: Coefficient-modulus chain bit sizes
            (manuscript: [60, 40, 40, 60]).
        global_scale_power: Exponent such that ``global_scale = 2 **
            global_scale_power`` (manuscript: 40, i.e. scale = 2**40).
    """

    poly_modulus_degree: int = 8192
    coeff_mod_bit_sizes: List[int] = field(default_factory=lambda: [60, 40, 40, 60])
    global_scale_power: int = 40

    @property
    def global_scale(self) -> float:
        return float(2 ** self.global_scale_power)


@dataclass(frozen=True)
class BFVConfig:
    """BFV parameters for the Phase 2 active (direct-addition) aggregation
    path (reviewer2_phase2_bfv_migration_report.md).

    Derived from the actual FairLend workload, not copied from an
    unrelated example:

    - ``poly_modulus_degree=8192`` matches the CKKS configuration above,
      for direct comparability between the two schemes at the same ring
      dimension. This codebase never needs more than 2 SIMD slots (one
      per protected-attribute group), so 8192 is not a batching-capacity
      requirement -- it is kept equal to CKKS's setting solely so a
      CKKS-vs-BFV benchmark/serialization comparison holds the ring
      dimension fixed and varies only the scheme.
    - ``plain_modulus=33832961`` is the smallest prime >= 2**25 that is
      ALSO congruent to 1 mod (2 * poly_modulus_degree) = 16384, i.e. the
      smallest batching-compatible ("NTT-friendly") prime at or above a
      2**25 safety target. TenSEAL's ``bfv_vector`` raises
      ``ValueError: encryption parameters are not valid for batching`` for
      any non-batching-compatible plain_modulus -- verified empirically,
      not assumed (see reviewer2_phase2_bfv_migration_report.md's
      "Confirm BFV support" section).
    - ``coeff_mod_bit_sizes`` is deliberately left unset (empty list):
      TenSEAL/SEAL then selects its own default coefficient-modulus
      chain for ``poly_modulus_degree``, which targets SEAL's default
      128-bit security level (``sec_level_type::tc128``) -- this
      codebase does not hand-pick a coefficient modulus for BFV
      precisely so it never accidentally weakens (or gratuitously
      strengthens, at a size/performance cost) that default. This
      default's exact bit-length could not be introspected via the
      installed TenSEAL 0.3.17 Python API (no accessor exposes SEAL's
      ``EncryptionParameters``/``SEALContext`` internals) -- documented
      as a verified LIMITATION, not silently assumed away.

    IMPORTANT -- BFV plaintext decoding is SIGNED, not unsigned (verified
    empirically): a value ``v`` in ``[0, plain_modulus)`` decodes as ``v``
    if ``v <= (plain_modulus - 1) // 2``, and as ``v - plain_modulus``
    (a negative number) otherwise. The SAFE representable range for a
    non-negative aggregate count is therefore ``[0, max_safe_count]``,
    NOT ``[0, plain_modulus - 1]`` -- see ``max_safe_count`` below, and
    ``tests/scientific/test_bfv_overflow.py`` for the empirical
    verification this codebase relies on rather than assumes.
    """

    poly_modulus_degree: int = 8192
    plain_modulus: int = 33832961
    coeff_mod_bit_sizes: List[int] = field(default_factory=list)

    @property
    def max_safe_count(self) -> int:
        """The largest non-negative integer aggregate count guaranteed to
        decrypt as itself (not wrap into a negative number) under this
        plaintext modulus's SIGNED decoding -- ``(plain_modulus - 1) //
        2``, not ``plain_modulus - 1``. At the default parameters this is
        16,916,480: roughly 19x the largest population this codebase has
        ever processed (887,440, the full cleaned LendingClub audit-
        eligible population -- see docs/FINAL_REPRODUCIBLE_RESULTS.md)
        and roughly 7.5x the raw, unfiltered dataset row count
        (2,260,701)."""
        return (self.plain_modulus - 1) // 2


@dataclass(frozen=True)
class DatasetSplitConfig:
    """Dataset location and train/validation/test split settings.

    Manuscript Sec. 6.1.4/6.2.8: 70% train / 10% validation / 20% test,
    stratified by repayment-outcome label, fixed reproducible seed.
    """

    input_path: Optional[str]
    split_seed: int
    train_fraction: float
    validation_fraction: float
    test_fraction: float


@dataclass(frozen=True)
class DatasetPeriodConfig:
    """The manuscript-stated observation period and the raw column used to
    determine it (Sec. 6.1.1: "LendingClub Loan Data, 2007-2015").

    Public LendingClub re-exports (e.g. Kaggle's "accepted_2007_to_2018Q4.csv")
    cover a longer period than the manuscript's stated window. This config
    makes the filtering rule explicit and inspectable rather than a hidden
    constant -- see ``fairlend.data.lendingclub_schema.filter_to_issue_year_range``.
    """

    issue_date_column: str
    start_year: int
    end_year: int


@dataclass(frozen=True)
class OutcomeMappingConfig:
    """Explicit LendingClub ``loan_status`` -> realised-outcome mapping.

    Values not listed in ``positive`` or ``negative`` are excluded from the
    realised-outcome population (see configs/evaluation.yaml for the
    rationale); they are not silently coerced into either class.
    """

    positive: List[str]
    negative: List[str]
    excluded: List[str]


@dataclass(frozen=True)
class SyntheticAttributeConfig:
    """Synthetic protected-attribute generation settings (manuscript
    Sec. 6.1.1)."""

    alpha0: float
    primary_alpha1: float
    alpha1_values: List[float]
    seeds: List[int]
    winsorize_lower_percentile: float
    winsorize_upper_percentile: float


@dataclass(frozen=True)
class FairnessConfig:
    """Fairness-audit configuration.

    ``minimum_cell_size`` is intentionally ``Optional[int] = None`` by
    default: the manuscript defines k_min but never states its numeric
    value, so no default is invented here. Code that requires k_min must
    check for ``None`` and fail with a clear message rather than silently
    substituting a number (see docs/IMPLEMENTATION_GAPS.md).
    """

    minimum_cell_size: Optional[int]


@dataclass(frozen=True)
class EvaluationConfig:
    """Top-level evaluation configuration, loaded from
    ``configs/evaluation.yaml``."""

    dataset: DatasetSplitConfig
    dataset_period: DatasetPeriodConfig
    outcome_mapping: OutcomeMappingConfig
    synthetic_attribute: SyntheticAttributeConfig
    ckks: CKKSConfig
    fairness: FairnessConfig


def load_evaluation_config(path: str | Path) -> EvaluationConfig:
    """Load ``configs/evaluation.yaml`` (or an equivalent file) into typed
    config objects.

    This is the only sanctioned way evaluation code should obtain these
    settings; do not re-declare any of these values as a Python literal
    elsewhere.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    dataset = DatasetSplitConfig(
        input_path=raw["dataset"].get("input_path"),
        split_seed=raw["dataset"]["split_seed"],
        train_fraction=raw["dataset"]["train_fraction"],
        validation_fraction=raw["dataset"]["validation_fraction"],
        test_fraction=raw["dataset"]["test_fraction"],
    )
    period_raw = raw["dataset_period"]
    dataset_period = DatasetPeriodConfig(
        issue_date_column=period_raw["issue_date_column"],
        start_year=period_raw["start_year"],
        end_year=period_raw["end_year"],
    )
    outcome_mapping = OutcomeMappingConfig(
        positive=list(raw["outcome_mapping"]["positive"]),
        negative=list(raw["outcome_mapping"]["negative"]),
        excluded=list(raw["outcome_mapping"]["excluded"]),
    )
    synth = raw["synthetic_attribute"]
    synthetic_attribute = SyntheticAttributeConfig(
        alpha0=synth["alpha0"],
        primary_alpha1=synth["primary_alpha1"],
        alpha1_values=list(synth["alpha1_values"]),
        seeds=list(synth["seeds"]),
        winsorize_lower_percentile=synth["winsorize_lower_percentile"],
        winsorize_upper_percentile=synth["winsorize_upper_percentile"],
    )
    ckks_raw = raw["ckks"]
    ckks = CKKSConfig(
        poly_modulus_degree=ckks_raw["poly_modulus_degree"],
        coeff_mod_bit_sizes=list(ckks_raw["coeff_mod_bit_sizes"]),
        global_scale_power=ckks_raw["global_scale_bits"],
    )
    fairness = FairnessConfig(
        minimum_cell_size=raw["fairness"].get("minimum_cell_size"),
    )

    total_fraction = (
        dataset.train_fraction + dataset.validation_fraction + dataset.test_fraction
    )
    if abs(total_fraction - 1.0) > 1e-9:
        raise ValueError(
            "dataset train/validation/test fractions must sum to 1.0, got "
            f"{total_fraction} (train={dataset.train_fraction}, "
            f"validation={dataset.validation_fraction}, "
            f"test={dataset.test_fraction})"
        )

    return EvaluationConfig(
        dataset=dataset,
        dataset_period=dataset_period,
        outcome_mapping=outcome_mapping,
        synthetic_attribute=synthetic_attribute,
        ckks=ckks,
        fairness=fairness,
    )
