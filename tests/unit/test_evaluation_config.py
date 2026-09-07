"""Unit tests for loading configs/evaluation.yaml."""
from __future__ import annotations

from pathlib import Path

import pytest

from fairlend.core.config import load_evaluation_config

CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "evaluation.yaml"


def test_evaluation_config_loads():
    config = load_evaluation_config(CONFIG_PATH)
    assert config.dataset.train_fraction == 0.70
    assert config.dataset.validation_fraction == 0.10
    assert config.dataset.test_fraction == 0.20
    assert config.dataset.input_path is None  # no default dataset path assumed


def test_evaluation_config_synthetic_attribute_matches_manuscript_primary_setting():
    config = load_evaluation_config(CONFIG_PATH)
    assert config.synthetic_attribute.alpha0 == 0.0
    assert config.synthetic_attribute.primary_alpha1 == 0.7
    assert config.synthetic_attribute.alpha1_values == [0.0, 0.4, 0.7, 1.0, 1.3]
    assert config.synthetic_attribute.seeds == list(range(10))


def test_evaluation_config_ckks_matches_manuscript_parameters():
    config = load_evaluation_config(CONFIG_PATH)
    assert config.ckks.poly_modulus_degree == 8192
    assert config.ckks.coeff_mod_bit_sizes == [60, 40, 40, 60]
    assert config.ckks.global_scale == 2 ** 40


def test_evaluation_config_dataset_period_matches_manuscript():
    config = load_evaluation_config(CONFIG_PATH)
    assert config.dataset_period.issue_date_column == "issue_d"
    assert config.dataset_period.start_year == 2007
    assert config.dataset_period.end_year == 2015


def test_evaluation_config_does_not_invent_minimum_cell_size():
    config = load_evaluation_config(CONFIG_PATH)
    assert config.fairness.minimum_cell_size is None


def test_evaluation_config_rejects_fractions_not_summing_to_one(tmp_path):
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text(
        """
dataset:
  input_path: null
  split_seed: 1
  train_fraction: 0.5
  validation_fraction: 0.1
  test_fraction: 0.2
dataset_period:
  issue_date_column: issue_d
  start_year: 2007
  end_year: 2015
outcome_mapping:
  positive: []
  negative: []
  excluded: []
synthetic_attribute:
  alpha0: 0.0
  primary_alpha1: 0.7
  alpha1_values: [0.7]
  seeds: [0]
  winsorize_lower_percentile: 1.0
  winsorize_upper_percentile: 99.0
ckks:
  poly_modulus_degree: 8192
  coeff_mod_bit_sizes: [60, 40, 40, 60]
  global_scale_bits: 40
fairness:
  minimum_cell_size: null
"""
    )
    with pytest.raises(ValueError):
        load_evaluation_config(bad_config)
