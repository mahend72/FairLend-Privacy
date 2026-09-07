"""Typed representations of the manuscript's NIZKP relations R_acc, R_score,
R_bind (Sec. 4.5.1).

Not yet implemented (Phase 9). This module will define dataclasses for the
public statement and private witness of each relation, and a description of
its principal constraints, WITHOUT implementing Setup/Prove/Verify -- the
manuscript explicitly states that concrete NIZKP proving and verification
are outside the current prototype (see docs/NIZKP_SCOPE.md, to be written
alongside this module).

Do not add a `prove()`/`verify()` that returns a hardcoded True, does a bare
hash comparison, or reuses a digital signature and calls it a NIZKP -- see
docs/IMPLEMENTATION_GAPS.md item B.4 and the legacy prototype's broken
`NIZKP()` function (legacy/secureloan_2023/source_code/Account open.py),
which this package must not resemble.
"""
