"""FairLend: privacy-preserving protected-attribute fairness auditing for
loan processing.

Reference implementation of the architecture described in
"FairLend: Privacy-Preserving Gender-Fairness Auditing for Loan Processing"
(``manuscript.tex`` at the repository root). This package supersedes the
unrelated 2023 prototype preserved under ``legacy/secureloan_2023/`` (see
that directory's README for why it is not reused here).

This package is being built incrementally against the manuscript as the
scientific source of truth; see ``docs/MANUSCRIPT_TO_CODE_TRACEABILITY.md``
for the current per-component implementation status. Modules and functions
that are not yet implemented raise ``NotImplementedError`` with a pointer to
the implementation phase that will fill them in, rather than silently
stubbing out manuscript behaviour.
"""

from importlib import metadata as _metadata

try:
    __version__ = _metadata.version("fairlend-privacy")
except _metadata.PackageNotFoundError:  # pragma: no cover - not installed
    __version__ = "0.0.0+unknown"

del _metadata
