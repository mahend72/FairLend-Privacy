"""Shared fixtures for the encrypted aggregation scientific/privacy test
suites (test_encrypted_aggregation.py and
test_encrypted_aggregation_privacy.py).

The `pipeline` fixture builds the hermetic, self-contained audit pipeline
from tests/fixtures/lendingclub_sample.csv via library calls -- no
dependency on the (gitignored) data/processed/ directory, so it is
portable to a fresh clone/CI.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from fairlend.audit.aggregation import (
    EncryptedTestRecord,
    build_audit_frame,
    compute_plaintext_audit,
)
from fairlend.core.config import load_evaluation_config
from fairlend.crypto.ckks import build_fla_context, derive_lpu_context
from fairlend.data.audit_scope import compute_final_audit_populations
from fairlend.data.loader import load_raw_lendingclub
from fairlend.data.outcomes import map_repayment_outcome
from fairlend.data.populations import classify_outcome_populations
from fairlend.data.proxy_features import compute_train_emp_length_median, fit_proxy_preprocessor
from fairlend.data.splitting import assign_full_population_split
from fairlend.data.synthetic_gender import generate_synthetic_gender
from fairlend.models.credit_models import (
    LOGISTIC_REGRESSION,
    build_feature_frame,
    select_best_logistic_regression,
)
from fairlend.audit.similarity import generate_encrypted_references, load_reference_vectors
from fairlend.roles.identity_provider import IdentityProvider

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "lendingclub_sample.csv"
CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "evaluation.yaml"
OUTCOME_COLUMN = "fairlend_outcome"


@pytest.fixture(scope="module")
def pipeline():
    config = load_evaluation_config(CONFIG_PATH)
    df = load_raw_lendingclub(FIXTURE_PATH)
    df[OUTCOME_COLUMN] = map_repayment_outcome(df["loan_status"], config.outcome_mapping)
    populations = classify_outcome_populations(df[OUTCOME_COLUMN])
    split = assign_full_population_split(
        df,
        outcome_column=OUTCOME_COLUMN,
        train_fraction=config.dataset.train_fraction,
        validation_fraction=config.dataset.validation_fraction,
        test_fraction=config.dataset.test_fraction,
        seed=config.dataset.split_seed,
    )
    final = compute_final_audit_populations(df, split, populations)

    df_train = df.loc[final.train_model_fit_index]
    df_validation = df.loc[final.validation_model_select_index]
    df_test = df.loc[split.test_index]

    emp_length_train_median = compute_train_emp_length_median(df_train["emp_length"])
    X_train = build_feature_frame(df_train, emp_length_train_median)
    X_validation = build_feature_frame(df_validation, emp_length_train_median)
    X_test = build_feature_frame(df_test, emp_length_train_median)
    y_train = df_train[OUTCOME_COLUMN].astype(int).to_numpy()
    y_validation = df_validation[OUTCOME_COLUMN].astype(int).to_numpy()

    model = select_best_logistic_regression(X_train, y_train, X_validation, y_validation, random_state=0)
    predictions = pd.DataFrame(
        {
            "row_index": df_test.index,
            "id": df_test["id"].to_numpy(),
            "y_true": df_test[OUTCOME_COLUMN].to_numpy(),
            "y_pred": model.predict_decision(X_test),
            "model": LOGISTIC_REGRESSION,
        }
    )

    proxy_preprocessor = fit_proxy_preprocessor(
        df_train,
        winsorize_lower_percentile=config.synthetic_attribute.winsorize_lower_percentile,
        winsorize_upper_percentile=config.synthetic_attribute.winsorize_upper_percentile,
    )
    z = proxy_preprocessor.transform(df)["z_standardized"].to_numpy()
    gender_result = generate_synthetic_gender(z, alpha0=0.0, alpha1=0.7, seed=0)
    synthetic_gender = pd.DataFrame({"row_index": df.index, "synthetic_gender_label": gender_result.label})

    fla_context = build_fla_context()
    lpu_context = derive_lpu_context(fla_context)
    ip = IdentityProvider(lpu_context)
    references = load_reference_vectors(generate_encrypted_references(fla_context), lpu_context)

    audit_frame = build_audit_frame(
        predictions,
        synthetic_gender,
        test_dp_index=split.test_index,
        test_eo_index=final.test_eo_index,
        train_index=split.train_index,
        validation_index=split.validation_index,
    )
    plaintext_result = compute_plaintext_audit(audit_frame, model_name=LOGISTIC_REGRESSION)

    records = []
    for row in audit_frame.itertuples(index=False):
        credential = ip.issue_credential(str(row.id), row.group)
        y_true = None if pd.isna(row.y_true) else int(row.y_true)
        records.append(
            EncryptedTestRecord(row_index=int(row.row_index), credential=credential, y_pred=int(row.y_pred), y_true=y_true)
        )

    return {
        "fla_context": fla_context,
        "lpu_context": lpu_context,
        "ip": ip,
        "references": references,
        "records": records,
        "audit_frame": audit_frame,
        "plaintext_result": plaintext_result,
    }
