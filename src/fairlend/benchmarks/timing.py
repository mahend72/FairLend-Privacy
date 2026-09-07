"""Microbenchmark timing harness: monotonic, high-resolution
(``time.perf_counter_ns``), explicit warm-up, every raw observation
retained (Phase 11 Sec. 4-6). Never uses a wall-clock timestamp
(``datetime``) to measure a duration.
"""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, List


@dataclass(frozen=True)
class TimingResult:
    """One operation's repeated-measurement result. ``raw_ns`` retains
    EVERY observation (Phase 11 Sec. 4: "Record every raw observation."),
    not just the summary statistics derived from it."""

    component: str
    operation: str
    batch_size: int
    n_warmup: int
    raw_ns: List[int] = field(default_factory=list)

    @property
    def n(self) -> int:
        return len(self.raw_ns)

    @property
    def mean_ns(self) -> float:
        return statistics.fmean(self.raw_ns)

    @property
    def std_ns(self) -> float:
        return statistics.pstdev(self.raw_ns) if len(self.raw_ns) > 1 else 0.0

    @property
    def median_ns(self) -> float:
        return statistics.median(self.raw_ns)

    @property
    def min_ns(self) -> int:
        return min(self.raw_ns)

    @property
    def max_ns(self) -> int:
        return max(self.raw_ns)

    @property
    def p95_ns(self) -> float:
        """Nearest-rank 95th percentile -- meaningful only for n >= ~20;
        callers should treat this as approximate for small n (Phase 11
        Sec. 4: "p95 where meaningful")."""
        if not self.raw_ns:
            return float("nan")
        ordered = sorted(self.raw_ns)
        rank = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
        return float(ordered[rank])

    @property
    def mean_ms_per_record(self) -> float:
        """Only meaningful for batch_size >= 1 record-processing
        operations -- callers must not use this for a fixed-size,
        record-count-independent operation (e.g. one packet
        serialization regardless of how many records fed it)."""
        return (self.mean_ns / 1e6) / self.batch_size

    @property
    def records_per_second(self) -> float:
        per_batch_seconds = self.mean_ns / 1e9
        return self.batch_size / per_batch_seconds if per_batch_seconds > 0 else float("inf")


def time_repeated(
    fn: Callable[[], None],
    *,
    component: str,
    operation: str,
    batch_size: int = 1,
    n_repeats: int = 30,
    n_warmup: int = 3,
) -> TimingResult:
    """Runs ``fn`` (which should perform exactly ``batch_size`` records'
    worth of work per call, or a single fixed-cost operation if
    ``batch_size=1`` and the operation is not record-count-dependent)
    ``n_warmup`` times (untimed, discarded) then ``n_repeats`` times
    (timed via ``time.perf_counter_ns``, monotonic and high-resolution --
    never ``datetime``). Every timed observation is kept in the returned
    ``TimingResult.raw_ns``.
    """
    for _ in range(n_warmup):
        fn()

    raw_ns: List[int] = []
    for _ in range(n_repeats):
        start = time.perf_counter_ns()
        fn()
        end = time.perf_counter_ns()
        raw_ns.append(end - start)

    return TimingResult(
        component=component, operation=operation, batch_size=batch_size, n_warmup=n_warmup, raw_ns=raw_ns
    )
