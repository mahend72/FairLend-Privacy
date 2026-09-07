"""Environment metadata collection for benchmark provenance (Phase 11
Sec. 7) -- stdlib only (no new hard dependency), best-effort on fields
that are not portably obtainable (e.g. physical core count on a
non-Linux host), which are reported as ``None`` with an explanatory note
rather than guessed.
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[3]


def _git_commit() -> Optional[str]:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return None


def _git_dirty() -> Optional[bool]:
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout
        return len(status.strip()) > 0
    except Exception:
        return None


def _cpu_model() -> Optional[str]:
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def _physical_core_count() -> Optional[int]:
    try:
        pairs = set()
        physical_id = core_id = None
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("physical id"):
                    physical_id = line.split(":", 1)[1].strip()
                elif line.lower().startswith("core id"):
                    core_id = line.split(":", 1)[1].strip()
                    if physical_id is not None:
                        pairs.add((physical_id, core_id))
        return len(pairs) if pairs else None
    except Exception:
        return None


def _total_ram_gb() -> Optional[float]:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return round(kb / (1024 * 1024), 2)
    except Exception:
        pass
    return None


def _is_wsl() -> bool:
    try:
        with open("/proc/version", "r", encoding="utf-8") as fh:
            return "microsoft" in fh.read().lower()
    except Exception:
        return "microsoft" in platform.uname().release.lower()


def _load_average_note() -> Optional[str]:
    """Best-effort, Phase 11 Sec. 7: "record whether the machine was
    under obvious competing load if detectable." Returns a human-readable
    note comparing the 1-minute load average to the logical core count,
    or None if load averages are unavailable (e.g. not POSIX)."""
    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        return None
    n_cpu = os.cpu_count() or 1
    ratio = load1 / n_cpu
    if ratio > 1.5:
        severity = "HIGH -- load average exceeds logical core count; benchmark timings may be inflated"
    elif ratio > 0.8:
        severity = "moderate"
    else:
        severity = "low"
    return f"load average (1/5/15 min) = {load1:.2f}/{load5:.2f}/{load15:.2f}, {n_cpu} logical cores, competing load: {severity}"


def collect_environment_metadata(ckks_config_dict: dict) -> dict:
    """Everything Phase 11 Sec. 7 asks to be saved, plus the CKKS
    configuration actually used for this benchmark run (passed in by the
    caller rather than re-derived here, so this module has no dependency
    on ``fairlend.core.config``)."""
    import cryptography
    import tenseal

    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "platform_full": platform.platform(),
        "kernel": platform.uname().release,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "tenseal_version": getattr(tenseal, "__version__", None),
        "cryptography_version": getattr(cryptography, "__version__", None),
        "cpu_model": _cpu_model(),
        "logical_cores": os.cpu_count(),
        "physical_cores": _physical_core_count(),
        "total_ram_gb": _total_ram_gb(),
        "is_wsl": _is_wsl(),
        "git_commit": _git_commit(),
        "git_dirty": _git_dirty(),
        "competing_load_note": _load_average_note(),
        "ckks_config": ckks_config_dict,
    }
