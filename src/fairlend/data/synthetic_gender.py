"""Synthetic binary protected-attribute generation (manuscript Sec. 6.1.1).

    Pr(g_i = female | x_i) = sigmoid(alpha0 + alpha1 * z_i)
    g_i ~ Bernoulli(Pr(g_i = female | x_i))

where ``z_i`` is the standardised proxy score from
``fairlend.data.proxy_features`` (``z_standardized`` /
``ProxyFeaturePreprocessor.transform(...)["z_standardized"]``).

THIS IS A CONTROLLED PROXY-DISCRIMINATION EXPERIMENT, NOT AN OBSERVED
DEMOGRAPHIC ATTRIBUTE. The LendingClub dataset contains no gender field;
``g_i`` produced here is a synthetic label correlated with non-sensitive
proxy features by construction, used only to exercise and evaluate
FairLend's encrypted gender-matching and fairness-auditing components. It
must never be interpreted as, or substituted for, real observed gender, and
it must never be used as an input feature to the credit-decision model
(``fairlend.data`` does not import anything from a model-training module,
and callers must not pass this output into model fitting -- see the
scientific test ``tests/scientific/test_no_leakage.py::
test_synthetic_gender_excluded_from_credit_model_features``, added once the
credit-decision models exist).
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


@dataclass(frozen=True)
class SyntheticGenderResult:
    """Output of one (alpha0, alpha1, seed) synthetic-gender draw.

    Attributes:
        alpha0, alpha1: The generating parameters used.
        seed: The RNG seed used (a fixed seed reproduces an identical
            ``label``/``one_hot`` for the same ``z``, ``alpha0``,
            ``alpha1``).
        probability_female: Pr(g_i = female | x_i) for each record.
        label: 0 = male, 1 = female (the realised Bernoulli draw).
        one_hot: shape (n, 2); row is (1, 0) for male, (0, 1) for female --
            the manuscript's g_i in {(1,0),(0,1)}.
    """

    alpha0: float
    alpha1: float
    seed: int
    probability_female: np.ndarray
    label: np.ndarray
    one_hot: np.ndarray

    @property
    def female_fraction(self) -> float:
        return float(self.label.mean())

    def metadata(self) -> dict:
        return {
            "alpha0": self.alpha0,
            "alpha1": self.alpha1,
            "seed": self.seed,
            "female_fraction": self.female_fraction,
            "n_records": int(self.label.shape[0]),
        }


def generate_synthetic_gender(
    z_standardized: np.ndarray, alpha0: float, alpha1: float, seed: int
) -> SyntheticGenderResult:
    """Draw the synthetic protected attribute for every record in
    ``z_standardized``.

    Args:
        z_standardized: The manuscript's z_i (already standardised using
            TRAIN-only statistics; see
            ``fairlend.data.proxy_features.ProxyFeaturePreprocessor``).
        alpha0, alpha1: Sigmoid parameters. Manuscript primary setting:
            alpha0=0.0, alpha1=0.7. alpha1=0.0 is the no-proxy-signal
            control (probability_female is then constant at
            sigmoid(alpha0), independent of z).
        seed: RNG seed. Uses ``numpy.random.default_rng(seed)`` exclusively
            (no global numpy random state is touched), so calling this
            twice with the same inputs and seed is guaranteed to reproduce
            identical output.
    """
    z = np.asarray(z_standardized, dtype=float)
    probability_female = sigmoid(alpha0 + alpha1 * z)

    rng = np.random.default_rng(seed)
    draws = rng.random(z.shape[0])
    label = (draws < probability_female).astype(int)

    one_hot = np.zeros((z.shape[0], 2), dtype=float)
    one_hot[label == 0, 0] = 1.0  # male   -> (1, 0)
    one_hot[label == 1, 1] = 1.0  # female -> (0, 1)

    return SyntheticGenderResult(
        alpha0=alpha0,
        alpha1=alpha1,
        seed=seed,
        probability_female=probability_female,
        label=label,
        one_hot=one_hot,
    )
