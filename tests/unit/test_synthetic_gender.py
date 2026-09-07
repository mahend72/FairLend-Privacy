"""Unit tests for synthetic protected-attribute generation (manuscript
Sec. 6.1.1)."""
from __future__ import annotations

import numpy as np
import pytest

from fairlend.data.synthetic_gender import generate_synthetic_gender, sigmoid


def test_sigmoid_basic_values():
    assert sigmoid(np.array([0.0]))[0] == pytest.approx(0.5)
    assert sigmoid(np.array([100.0]))[0] == pytest.approx(1.0, abs=1e-9)
    assert sigmoid(np.array([-100.0]))[0] == pytest.approx(0.0, abs=1e-9)


def test_one_hot_encoding_matches_label():
    z = np.zeros(50)
    result = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=0)
    male_mask = result.label == 0
    female_mask = result.label == 1
    assert np.all(result.one_hot[male_mask] == np.array([1.0, 0.0]))
    assert np.all(result.one_hot[female_mask] == np.array([0.0, 1.0]))
    # one-hot rows sum to exactly 1 (a valid one-hot vector)
    assert np.all(result.one_hot.sum(axis=1) == 1.0)


def test_alpha1_zero_gives_constant_probability_independent_of_z():
    """alpha1=0.0 is the manuscript's no-proxy-signal control: probability
    must be constant (sigmoid(alpha0)) regardless of z."""
    z = np.array([-5.0, -1.0, 0.0, 1.0, 5.0, 100.0])
    result = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.0, seed=0)
    assert np.allclose(result.probability_female, 0.5)


def test_alpha1_nonzero_probability_increases_with_z():
    z = np.array([-3.0, -1.0, 0.0, 1.0, 3.0])
    result = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=0)
    assert np.all(np.diff(result.probability_female) > 0)


def test_fixed_seed_reproduces_identical_labels():
    z = np.linspace(-2, 2, 200)
    result_a = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=42)
    result_b = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=42)
    assert np.array_equal(result_a.label, result_b.label)
    assert np.array_equal(result_a.one_hot, result_b.one_hot)


def test_different_seeds_produce_different_labels_with_high_probability():
    z = np.linspace(-2, 2, 500)
    result_a = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=1)
    result_b = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=2)
    assert not np.array_equal(result_a.label, result_b.label)


def test_metadata_reports_alpha_and_seed():
    z = np.zeros(10)
    result = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=3)
    meta = result.metadata()
    assert meta["alpha0"] == 0.0
    assert meta["alpha1"] == 0.7
    assert meta["seed"] == 3
    assert meta["n_records"] == 10
