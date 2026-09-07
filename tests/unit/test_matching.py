"""Unit tests for fairlend.audit.matching using hand-built
PairedSimilarityScore objects (no CKKS, no credentials) -- pure
argmax/delta*/metrics logic, mirroring tests/unit/test_fairness.py's
style."""
from __future__ import annotations

import inspect

import pytest

from fairlend.audit.aggregation import GROUP_FEMALE, GROUP_MALE
from fairlend.audit.matching import (
    DELTA_STAR_GRID,
    UNMATCHED_LABEL,
    MatchingPrediction,
    PairedSimilarityScore,
    classify_paired_score,
    compute_matching_metrics,
    compute_score_distribution_stats,
    select_delta_star,
)


def _pair(identifier, male, female, expected) -> PairedSimilarityScore:
    return PairedSimilarityScore(identifier=identifier, male_score=male, female_score=female, expected_group=expected)


# --- classify_paired_score: argmax + delta* ---------------------------------


def test_male_score_dominant_classified_as_male():
    prediction = classify_paired_score(_pair("1", 0.99, 0.01, GROUP_MALE), delta_star=0.5)
    assert prediction.predicted_group == GROUP_MALE
    assert prediction.unmatched is False
    assert prediction.correct is True


def test_female_score_dominant_classified_as_female():
    prediction = classify_paired_score(_pair("2", 0.02, 0.98, GROUP_FEMALE), delta_star=0.5)
    assert prediction.predicted_group == GROUP_FEMALE
    assert prediction.unmatched is False


def test_both_scores_below_delta_star_is_unmatched():
    prediction = classify_paired_score(_pair("3", 0.3, 0.2, GROUP_MALE), delta_star=0.5)
    assert prediction.unmatched is True
    assert prediction.predicted_group is None
    assert prediction.correct is False


def test_unmatched_requires_BOTH_scores_below_delta_not_just_the_nonmatching_one():
    """The manuscript requires paired interpretation (task Sec. 12): a
    high male_score with a near-zero female_score must NOT be rejected
    merely because female_score is close to zero."""
    prediction = classify_paired_score(_pair("4", 0.99, 0.0001, GROUP_MALE), delta_star=0.5)
    assert prediction.unmatched is False
    assert prediction.predicted_group == GROUP_MALE


def test_exactly_at_delta_star_counts_as_matched():
    prediction = classify_paired_score(_pair("5", 0.5, 0.1, GROUP_MALE), delta_star=0.5)
    assert prediction.unmatched is False  # max == delta_star, not < delta_star


def test_tie_breaks_toward_male_deterministically():
    prediction = classify_paired_score(_pair("6", 0.7, 0.7, GROUP_MALE), delta_star=0.5)
    assert prediction.predicted_group == GROUP_MALE


def test_predicted_label_sentinel_for_unmatched():
    prediction = classify_paired_score(_pair("7", 0.1, 0.1, GROUP_MALE), delta_star=0.5)
    assert prediction.predicted_label == UNMATCHED_LABEL


def test_predicted_label_matches_predicted_group_when_matched():
    prediction = classify_paired_score(_pair("8", 0.9, 0.1, GROUP_MALE), delta_star=0.5)
    assert prediction.predicted_label == GROUP_MALE


# --- compute_matching_metrics -----------------------------------------------


def test_accuracy_computed_correctly_hand_calculated():
    predictions = [
        classify_paired_score(_pair("1", 0.9, 0.1, GROUP_MALE), 0.5),    # correct
        classify_paired_score(_pair("2", 0.1, 0.9, GROUP_FEMALE), 0.5),  # correct
        classify_paired_score(_pair("3", 0.9, 0.1, GROUP_FEMALE), 0.5),  # wrong (predicted male)
        classify_paired_score(_pair("4", 0.1, 0.1, GROUP_MALE), 0.5),    # unmatched (wrong)
    ]
    metrics = compute_matching_metrics(predictions)
    assert metrics.n == 4
    assert metrics.correct == 2
    assert metrics.accuracy == pytest.approx(0.5)


def test_macro_f1_computed_correctly_for_perfect_predictions():
    predictions = [
        classify_paired_score(_pair("1", 0.9, 0.1, GROUP_MALE), 0.5),
        classify_paired_score(_pair("2", 0.1, 0.9, GROUP_FEMALE), 0.5),
    ]
    metrics = compute_matching_metrics(predictions)
    assert metrics.macro_f1 == pytest.approx(1.0)


def test_macro_f1_hand_calculated_for_imperfect_predictions():
    # 2 male expected, 2 female expected; 1 male misclassified as female.
    predictions = [
        classify_paired_score(_pair("1", 0.9, 0.1, GROUP_MALE), 0.5),    # TP male
        classify_paired_score(_pair("2", 0.1, 0.9, GROUP_MALE), 0.5),    # FN male / FP female
        classify_paired_score(_pair("3", 0.1, 0.9, GROUP_FEMALE), 0.5),  # TP female
        classify_paired_score(_pair("4", 0.1, 0.9, GROUP_FEMALE), 0.5),  # TP female
    ]
    metrics = compute_matching_metrics(predictions)
    # male: precision=1/1=1, recall=1/2=0.5 -> F1=2*1*0.5/1.5=0.6667
    # female: precision=2/3=0.6667, recall=2/2=1 -> F1=2*0.6667*1/1.6667=0.8
    # macro = (0.6667+0.8)/2 = 0.7333
    assert metrics.macro_f1 == pytest.approx((2 / 3 + 0.8) / 2, abs=1e-4)


def test_unmatched_rate_computed_correctly():
    predictions = [
        classify_paired_score(_pair("1", 0.9, 0.1, GROUP_MALE), 0.5),
        classify_paired_score(_pair("2", 0.1, 0.1, GROUP_MALE), 0.5),
        classify_paired_score(_pair("3", 0.2, 0.2, GROUP_FEMALE), 0.5),
        classify_paired_score(_pair("4", 0.9, 0.1, GROUP_MALE), 0.5),
    ]
    metrics = compute_matching_metrics(predictions)
    assert metrics.unmatched_count == 2
    assert metrics.unmatched_rate == pytest.approx(0.5)


def test_compute_matching_metrics_raises_on_empty():
    with pytest.raises(ValueError):
        compute_matching_metrics([])


# --- select_delta_star: validation-only threshold selection -----------------


def test_select_delta_star_picks_largest_threshold_achieving_max_accuracy():
    # Perfectly separated scores: every threshold in (0.2, 0.8) achieves
    # 100% validation accuracy -- the largest grid value <= 0.8 wins.
    pairs = [
        _pair("1", 0.9, 0.05, GROUP_MALE),
        _pair("2", 0.05, 0.9, GROUP_FEMALE),
        _pair("3", 0.85, 0.02, GROUP_MALE),
    ]
    delta_star, metrics = select_delta_star(pairs)
    assert delta_star == max(d for d in DELTA_STAR_GRID if d <= 0.85)
    assert metrics.accuracy == pytest.approx(1.0)


def test_select_delta_star_lower_when_imperfect_separation_requires_it():
    # One record only separable at a low threshold -- forces a smaller
    # delta* to keep it matched (unmatched would count as wrong, per
    # compute_matching_metrics, only if it were the accuracy-maximiser;
    # here we construct a case where a small delta* is REQUIRED to
    # correctly classify a low-confidence record).
    pairs = [
        _pair("1", 0.9, 0.05, GROUP_MALE),
        _pair("2", 0.08, 0.06, GROUP_MALE),  # only classifiable (as male) if delta* <= 0.08
    ]
    delta_star, metrics = select_delta_star(pairs)
    assert delta_star <= 0.08
    assert metrics.accuracy == pytest.approx(1.0)


def test_select_delta_star_raises_on_empty_validation_set():
    with pytest.raises(ValueError):
        select_delta_star([])


def test_select_delta_star_signature_has_no_test_data_parameter():
    params = list(inspect.signature(select_delta_star).parameters)
    assert params == ["validation_pairs", "grid"]
    assert not any("test" in p.lower() for p in params)


# --- compute_score_distribution_stats ---------------------------------------


def test_score_distribution_stats_hand_calculated():
    scores = [1.0, 1.0, 0.98, 1.02]
    stats = compute_score_distribution_stats(scores, expected_value=1.0)
    assert stats.n == 4
    assert stats.mean == pytest.approx(1.0)
    assert stats.min == pytest.approx(0.98)
    assert stats.max == pytest.approx(1.02)
    assert stats.mae == pytest.approx((0 + 0 + 0.02 + 0.02) / 4)
    assert stats.max_abs_error == pytest.approx(0.02)


def test_score_distribution_stats_raises_on_empty():
    with pytest.raises(ValueError):
        compute_score_distribution_stats([], expected_value=1.0)


def test_score_distribution_stats_not_rounded():
    scores = [0.999999123456]
    stats = compute_score_distribution_stats(scores, expected_value=1.0)
    assert stats.mean == pytest.approx(0.999999123456, abs=1e-12)
