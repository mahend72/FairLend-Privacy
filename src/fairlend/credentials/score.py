"""Credit-Agency-issued credit-score credential (manuscript Sec. 4.3,
Table 1):

    sigma_c_i = Sign(sk_c_sig, uid_i || s_i)

``s_i`` (the credit score) is an integer here, matching the manuscript's
score-as-integer framing and this codebase's Credit Agency role (see
``fairlend.roles.credit_agency``); ``canonical_encode`` serialises it via
JSON's native integer encoding, which is deterministic for a fixed
integer value regardless of how that value was computed -- see
``tests/unit/test_credentials_score.py::
test_score_encoding_is_deterministic``.

This credential is the protocol's AUTHENTICATED SCORE INPUT (``s_i``,
Threshold: ``Y-hat_i = I[s_i >= tau]``) -- it is unrelated to, and does
not change, the plaintext fixture credit-decision models or their frozen
TEST predictions from Phase 1/2 (``fairlend.models.credit_models``,
``results/fixture_validation/evaluation/model_predictions.parquet``).
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from fairlend.crypto.serialization import canonical_encode
from fairlend.crypto.signatures import sign, verify

DOMAIN = "fairlend/score/v1"
CREDENTIAL_VERSION = 1


def _score_message(uid: str, score: int) -> bytes:
    return canonical_encode({"domain": DOMAIN, "uid": uid, "score": score})


@dataclass(frozen=True)
class ScoreCredential:
    """The Credit-Agency-issued score credential, as forwarded by the
    borrower and verified by the LPU."""

    uid: str
    score: int
    signature: bytes
    credential_version: int = CREDENTIAL_VERSION

    def verify(self, ca_public_key: Ed25519PublicKey) -> bool:
        """VerifySig(pk_c_sig, uid_i || s_i, sigma_c_i)."""
        message = _score_message(self.uid, self.score)
        return verify(ca_public_key, message, self.signature)


def issue_score_credential(
    ca_private_key: Ed25519PrivateKey, uid: str, score: int
) -> ScoreCredential:
    """sigma_c_i = Sign(sk_c_sig, uid_i || s_i)."""
    signature = sign(ca_private_key, _score_message(uid, score))
    return ScoreCredential(uid=uid, score=score, signature=signature)
