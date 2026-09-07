"""Identity-Provider-issued protected-attribute credential (manuscript
Sec. 4.3, Sec. 4.6, Table 1):

    HE.g_i    = Enc(pk_HE, one_hot(gender))     -- male=(1,0), female=(0,1)
    d_g_i     = SHA256(Serialize(HE.g_i))
    sigma_g_i = Sign(sk_IP_sig, uid_i || d_g_i)

Binary one-hot encoding only (Sec. 4.6, Table 1) -- the legacy four-
category representation (Male/Female/Transgender/Other;
``legacy/secureloan_2023/source_code/*``) is not reused here.

The IP is the only entity in this codebase that ever constructs
``HE.g_i`` from a plaintext label (Threat 3: the borrower must not be
able to fabricate or alter it) -- see ``fairlend.roles.identity_provider.
IdentityProvider.issue_credential``, the sole caller of
``issue_protected_attribute_credential``. This module itself takes only
already-produced ciphertext bytes; it never sees or handles a plaintext
gender label.

CKKS SERIALIZATION STABILITY (read before touching this file): CKKS
encryption is randomised -- encrypting the SAME plaintext twice under the
SAME public key produces DIFFERENT ciphertext bytes each time. ``d_g_i``
is therefore only ever computed from, and ``verify()`` only ever
re-hashes, the ACTUAL ISSUED ciphertext bytes retained on the credential
object (``self.ciphertext_bytes``) -- never a freshly re-encrypted copy of
the same plaintext, and never a value obtained by decrypting anything.
Re-encrypting the same plaintext to get a "fresh" comparison ciphertext
and hashing THAT would almost certainly produce a different digest and
incorrectly reject a perfectly valid, unmodified credential -- see
``tests/scientific/test_protected_attribute_credential.py::
test_fresh_reencryption_does_not_invalidate_original_credential``.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from fairlend.crypto.hashing import sha256_bytes
from fairlend.crypto.serialization import canonical_encode
from fairlend.crypto.signatures import sign, verify

DOMAIN = "fairlend/protected-attribute/v1"
CREDENTIAL_VERSION = 1


def _protected_attribute_message(uid: str, digest: bytes) -> bytes:
    return canonical_encode({"domain": DOMAIN, "uid": uid, "digest": digest})


@dataclass(frozen=True)
class ProtectedAttributeCredential:
    """The LPU-facing protected-attribute credential.

    Deliberately carries NO plaintext gender field of any kind -- only
    ``uid``, the issued ciphertext bytes, its digest, and the IP's
    signature. Every field is either an identifier, ciphertext, a hash, or
    a signature; none is, or is derived in a reversible way from,
    plaintext gender within this codebase. See
    ``tests/scientific/test_protected_attribute_credential.py::
    test_no_plaintext_gender_field_anywhere_in_credential``, which
    enumerates every field on this dataclass and fails loudly if a new
    field is ever added without being checked against this invariant.
    """

    uid: str
    ciphertext_bytes: bytes
    digest: bytes
    signature: bytes
    credential_version: int = CREDENTIAL_VERSION

    def verify(self, ip_public_key: Ed25519PublicKey) -> bool:
        """Two checks, both against the RETAINED issued ciphertext bytes:

        1. ``self.digest`` must equal ``SHA256(self.ciphertext_bytes)`` --
           this is a plain consistency re-hash, not itself authentication
           (see ``fairlend.crypto.hashing``'s module docstring).
        2. ``sigma_g_i`` must verify as ``Sign(sk_IP_sig, uid_i ||
           digest)`` under ``ip_public_key`` -- this is the actual
           authentication, and is what an attacker who tampers with
           ``ciphertext_bytes`` (and recomputes a matching digest) cannot
           forge without ``sk_IP_sig``.

        This never decrypts ``ciphertext_bytes`` and never re-encrypts the
        plaintext to compare -- see the module docstring.
        """
        if sha256_bytes(self.ciphertext_bytes) != self.digest:
            return False
        message = _protected_attribute_message(self.uid, self.digest)
        return verify(ip_public_key, message, self.signature)


def issue_protected_attribute_credential(
    ip_private_key: Ed25519PrivateKey, uid: str, ciphertext_bytes: bytes
) -> ProtectedAttributeCredential:
    """d_g_i = SHA256(Serialize(HE.g_i)); sigma_g_i = Sign(sk_IP_sig, uid_i || d_g_i).

    Args:
        ciphertext_bytes: The ALREADY-SERIALIZED issued ``HE.g_i``
            (``ts.CKKSVector.serialize()`` output) -- this function signs
            over whatever bytes it is given; it does not itself encrypt
            anything (see ``fairlend.roles.identity_provider``, which
            performs the encryption and is the only caller).
    """
    digest = sha256_bytes(ciphertext_bytes)
    signature = sign(ip_private_key, _protected_attribute_message(uid, digest))
    return ProtectedAttributeCredential(
        uid=uid, ciphertext_bytes=ciphertext_bytes, digest=digest, signature=signature
    )
