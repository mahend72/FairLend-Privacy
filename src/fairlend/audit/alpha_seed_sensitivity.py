"""Phase 10: real-data alpha1 x seed sensitivity analysis -- PLAINTEXT ONLY.

Evaluates how the controlled proxy-correlation strength (``alpha1``) and
the synthetic-gender RNG ``seed`` used to generate the SYNTHETIC
protected attribute (``fairlend.data.synthetic_gender``) affect
protected-group balance, proxy recoverability, and the plaintext fairness
audit (`fairlend.audit.fairness`) of the ALREADY-FROZEN LR/RF decision
vectors -- while holding the dataset, split, trained models, credit
probabilities, and decision threshold (tau=0.80,
``validation_balanced_accuracy_max``) fixed.

This module performs NO CKKS/cryptography, NO model refitting, and NO
threshold reselection -- see ``evaluation/run_alpha1_seed_sensitivity.py``
for the orchestration script that calls this once per (alpha1, seed)
configuration. FairLend's encrypted-fidelity claim is NOT re-established
here; this phase measures a different, purely statistical question (how
sensitive is the plaintext fairness RESULT to the controlled synthetic-
attribute generation process), using the SAME plaintext formulas
(``fairlend.audit.aggregation``/``fairlend.audit.fairness``) the primary
real-data plaintext audit already used.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score

from fairlend.audit.aggregation import build_audit_frame, compute_plaintext_audit
from fairlend.audit.fairness import compute_demographic_parity, compute_equalised_odds

STAT_KEYS = ("C_m", "C_f", "A_m", "A_f", "P_m", "P_f", "TP_m", "TP_f", "N_m", "N_f", "FP_m", "FP_f")


@dataclass(frozen=True)
class ProxyDiagnosticResult:
    """One (alpha1, seed) configuration's proxy-recoverability diagnostic:
    a small logistic-regression classifier predicting the SYNTHETIC
    protected-attribute label from the five proxy features, fit on TRAIN
    ONLY and evaluated on TEST ONLY -- identical methodology to
    ``evaluation/run_proxy_diagnostic.py``, factored out here so it can be
    called once per configuration without re-deriving the (fixed) proxy
    features every time."""

    roc_auc: float
    accuracy: float
    n_train: int
    n_test: int


def compute_proxy_diagnostic(
    X_train: pd.DataFrame, y_train: np.ndarray, X_test: pd.DataFrame, y_test: np.ndarray, random_state: int
) -> ProxyDiagnosticResult:
    """Fits on TRAIN, evaluates on TEST. ``X_train``/``X_test`` (the five
    proxy features) are FIXED across every configuration; only
    ``y_train``/``y_test`` (this configuration's synthetic label) vary."""
    model = LogisticRegression(max_iter=1000, random_state=random_state)
    model.fit(X_train, y_train)
    proba_test = model.predict_proba(X_test)[:, 1]
    pred_test = model.predict(X_test)
    return ProxyDiagnosticResult(
        roc_auc=float(roc_auc_score(y_test, proba_test)),
        accuracy=float(accuracy_score(y_test, pred_test)),
        n_train=int(len(X_train)),
        n_test=int(len(X_test)),
    )


@dataclass(frozen=True)
class ConfigurationModelRow:
    """One (alpha1, seed, model) row of the sensitivity sweep."""

    alpha1: float
    seed: int
    model: str
    tau: float
    approval_rate_overall: float
    female_n: int
    male_n: int
    female_fraction: float
    male_fraction: float
    mean_probability_female: float
    proxy_auc: float
    proxy_accuracy: float
    stats: Dict[str, int]
    approval_rate_m: float
    approval_rate_f: float
    tpr_m: float
    tpr_f: float
    fpr_m: float
    fpr_f: float
    dp: float
    eo: float


def compute_configuration_model_row(
    *,
    alpha1: float,
    seed: int,
    model_name: str,
    tau: float,
    frozen_predictions: pd.DataFrame,
    synthetic_gender_frame: pd.DataFrame,
    probability_female_full: np.ndarray,
    test_dp_index: pd.Index,
    test_eo_index: pd.Index,
    train_index: pd.Index,
    validation_index: pd.Index,
    proxy_result: ProxyDiagnosticResult,
) -> ConfigurationModelRow:
    """Builds one model's row for one (alpha1, seed) configuration.

    ``frozen_predictions`` (columns: ``row_index``, ``y_true``,
    ``y_pred``) is the SAME frozen decision vector for every
    configuration -- only ``synthetic_gender_frame`` (this configuration's
    group assignment) changes what ``build_audit_frame``/
    ``compute_plaintext_audit`` compute from it. No model fitting, no
    threshold selection, and no cryptography occurs here.
    """
    audit_frame = build_audit_frame(
        frozen_predictions, synthetic_gender_frame, test_dp_index, test_eo_index, train_index, validation_index
    )
    plaintext_result = compute_plaintext_audit(audit_frame, model_name=model_name)
    dp = compute_demographic_parity(plaintext_result)
    eo = compute_equalised_odds(plaintext_result)
    m, f = plaintext_result.male(), plaintext_result.female()

    label = synthetic_gender_frame.set_index("row_index")["synthetic_gender_label"]
    female_n = int((label == 1).sum())
    male_n = int((label == 0).sum())
    n_total = female_n + male_n

    return ConfigurationModelRow(
        alpha1=alpha1,
        seed=seed,
        model=model_name,
        tau=tau,
        approval_rate_overall=float(frozen_predictions["y_pred"].mean()),
        female_n=female_n,
        male_n=male_n,
        female_fraction=female_n / n_total,
        male_fraction=male_n / n_total,
        mean_probability_female=float(np.mean(probability_female_full)),
        proxy_auc=proxy_result.roc_auc,
        proxy_accuracy=proxy_result.accuracy,
        stats={
            "C_m": m.C, "C_f": f.C, "A_m": m.A, "A_f": f.A,
            "P_m": m.P, "P_f": f.P, "TP_m": m.TP, "TP_f": f.TP,
            "N_m": m.N, "N_f": f.N, "FP_m": m.FP, "FP_f": f.FP,
        },
        approval_rate_m=dp.approval_rate_m.value,
        approval_rate_f=dp.approval_rate_f.value,
        tpr_m=eo.tpr_m.value,
        tpr_f=eo.tpr_f.value,
        fpr_m=eo.fpr_m.value,
        fpr_f=eo.fpr_f.value,
        dp=dp.dp_gap.value,
        eo=eo.eo_gap.value,
    )


def row_to_flat_dict(row: ConfigurationModelRow, *, data_scope: str, dataset_sha256: str, threshold_policy: str) -> dict:
    """Flattens one ``ConfigurationModelRow`` into the exact column set
    ``results/evaluation/alpha1_seed_sensitivity_runs.csv`` requires."""
    d = {
        "alpha1": row.alpha1,
        "seed": row.seed,
        "model": row.model,
        "tau": row.tau,
        "approval_rate_overall": row.approval_rate_overall,
        "female_n": row.female_n,
        "male_n": row.male_n,
        "female_fraction": row.female_fraction,
        "male_fraction": row.male_fraction,
        "mean_probability_female": row.mean_probability_female,
        "proxy_auc": row.proxy_auc,
        "proxy_accuracy": row.proxy_accuracy,
    }
    d.update(row.stats)
    d.update(
        {
            "approval_rate_m": row.approval_rate_m,
            "approval_rate_f": row.approval_rate_f,
            "TPR_m": row.tpr_m,
            "TPR_f": row.tpr_f,
            "FPR_m": row.fpr_m,
            "FPR_f": row.fpr_f,
            "DP": row.dp,
            "EO": row.eo,
            "data_scope": data_scope,
            "dataset_sha256": dataset_sha256,
            "threshold_policy": threshold_policy,
        }
    )
    return d


def assert_frozen_predictions_unchanged(
    frozen_predictions: pd.DataFrame, canonical_y_pred: np.ndarray, model_name: str
) -> None:
    """Structural proof (Phase 10 Sec. 4) that a configuration's decision
    vector was never touched: compares the exact array used to build this
    configuration's audit frame against the canonical array captured once,
    before the sensitivity loop began."""
    actual = frozen_predictions["y_pred"].to_numpy()
    if not np.array_equal(actual, canonical_y_pred):
        raise AssertionError(
            f"{model_name}: y_pred changed across configurations -- expected the frozen "
            "decision vector to be invariant to alpha1/seed (only protected-group "
            "assignment should vary)."
        )


def summarise_runs(runs_df: pd.DataFrame) -> pd.DataFrame:
    """Phase 10 Sec. 9: for each (alpha1, model), across the 10 seeds --
    female_fraction mean/std, proxy_auc mean/std, DP mean/std/min/max, EO
    mean/std/min/max. Returns one row per (alpha1, model): 5 alpha1 x 2
    models = 10 rows for the standard grid."""
    grouped = runs_df.groupby(["alpha1", "model"], as_index=False)
    summary = grouped.agg(
        n_seeds=("seed", "nunique"),
        female_fraction_mean=("female_fraction", "mean"),
        female_fraction_std=("female_fraction", "std"),
        proxy_auc_mean=("proxy_auc", "mean"),
        proxy_auc_std=("proxy_auc", "std"),
        DP_mean=("DP", "mean"),
        DP_std=("DP", "std"),
        DP_min=("DP", "min"),
        DP_max=("DP", "max"),
        EO_mean=("EO", "mean"),
        EO_std=("EO", "std"),
        EO_min=("EO", "min"),
        EO_max=("EO", "max"),
    )
    return summary.sort_values(["model", "alpha1"]).reset_index(drop=True)


def pearson_correlation(x: Mapping[int, float] | np.ndarray, y: np.ndarray) -> float:
    """Plain Pearson correlation coefficient (no scipy dependency) --
    used for the alpha1-vs-proxy_auc / alpha1-vs-DP / alpha1-vs-EO trend
    reporting (Phase 10 Sec. 10). Returns NaN if either series has zero
    variance (undefined correlation), never raises."""
    x_arr = np.asarray(list(x) if not isinstance(x, np.ndarray) else x, dtype=float)
    y_arr = np.asarray(y, dtype=float)
    # np.allclose (rather than an exact `== 0.0` on .std()) correctly
    # treats floating-point-identical-looking values (e.g. every entry
    # being the literal 0.7) as constant, even though their std() is a
    # tiny nonzero float rather than exactly 0.0.
    if np.allclose(x_arr, x_arr[0]) or np.allclose(y_arr, y_arr[0]):
        return float("nan")
    return float(np.corrcoef(x_arr, y_arr)[0, 1])
