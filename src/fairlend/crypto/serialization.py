"""Canonical message encoding for signing/verification.

Every message this codebase signs or hashes for authentication purposes
(``fairlend.credentials.*``) is built with ``canonical_encode``, never by
concatenating stringified fields (``str(uid) + str(account)``), because
naive concatenation is ambiguous at field boundaries: ``uid="AB",
account="C"`` and ``uid="A", account="BC"`` would produce the identical
string ``"ABC"`` and therefore the identical signature under a
concatenation scheme, letting a forger who controls one field's boundary
substitute a different logical message that verifies under the same
signature.

``canonical_encode`` instead produces deterministic, unambiguous UTF-8
JSON:

    canonical_encode({"domain": "fairlend/account/v1", "uid": "AB", "account": "C"})
    != canonical_encode({"domain": "fairlend/account/v1", "uid": "A", "account": "BC"})

because JSON's own quoting/delimiters (``","``, ``":"``, the quotes around
each string) preserve field boundaries that a bare concatenation would
lose. Determinism comes from ``sort_keys=True`` (field order never
affects the encoding) and a fixed, whitespace-free separator style
(``json.dumps(..., separators=(",", ":"))``).

Every canonical message signed by this codebase also carries an explicit
``"domain"`` field (e.g. ``"fairlend/account/v1"``) naming the credential
type and a version -- this is protocol-domain separation, an
implementation-hardening choice and NOT a manuscript-specified mechanism
(see docs/MANUSCRIPT_EVIDENCE_STATUS.md): it prevents a signature valid
for one credential type/version from ever being replayed as valid input
for a different type or a future incompatible version, since the signed
bytes differ even if the non-domain fields happened to coincide.

This is versionable: a future encoding change ships as a NEW top-level
key or a bumped ``credential_version``/``domain`` value alongside this
function, never as a silent change to how existing signed messages were
encoded (which would invalidate every previously-issued credential's
verifiability without warning).
"""
from __future__ import annotations

import json
from typing import Any, Mapping


def canonical_encode(fields: Mapping[str, Any]) -> bytes:
    """Deterministic, unambiguous UTF-8 JSON encoding of ``fields``.

    Args:
        fields: A mapping of JSON-safe values (str, int, float, bool,
            None, bytes, nested Mapping/list/tuple of the same). ``bytes``
            values are encoded as ``{"__bytes_hex__": "<hex>"}`` so raw
            byte strings never need to pass through JSON's text encoding
            directly and so a bytes value can never be confused with a
            string that happens to look similar.

    Returns:
        UTF-8-encoded canonical JSON bytes. Keys are sorted and there is
        no incidental whitespace, so two calls with logically identical
        (but differently key-ordered) mappings produce byte-identical
        output.

    Raises:
        TypeError: if ``fields`` (recursively) contains a value that is
            not one of the JSON-safe types listed above -- this function
            never silently falls back to ``str(value)`` for an
            unsupported type, since that would reintroduce exactly the
            ambiguity this function exists to avoid.
    """
    safe = _json_safe(fields)
    return json.dumps(safe, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _json_safe(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes_hex__": bytes(value).hex()}
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bool) or value is None or isinstance(value, (str, int, float)):
        return value
    raise TypeError(
        f"canonical_encode cannot serialize value of type {type(value)!r}; "
        "add explicit, documented support rather than falling back to str()."
    )
