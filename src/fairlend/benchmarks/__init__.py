"""Phase 11: reproducible runtime and communication-size benchmarking.

Every submodule here is measurement-only: nothing in this package fits a
model, selects a threshold, or changes any protocol/cryptographic
behaviour in ``fairlend.audit``/``fairlend.crypto``/``fairlend.roles`` --
see ``evaluation/run_benchmarks.py`` for the orchestration script that
calls the real implementation and records how long it took / how many
bytes it produced.
"""
