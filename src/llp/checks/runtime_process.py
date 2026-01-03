from __future__ import annotations
from pathlib import Path
from typing import List, Tuple
import os

from llp.core.models import Evidence, Finding
from llp.core.utils import run_cmd

RISKY_RUNTIME_PATHS = (
    "/tmp/",
    "/dev/shm/",
    "/run/user/",
    "/var/tmp/",
)

def _list_process_exec_paths() -> List[Tuple[int, str]]:
    """Return (pid, exe_path) for running processes where resolvable."""
    procs: List[Tuple[int, str]] = []
    proc = Path("/proc")
    if not proc.exists():
        return procs

    for p in proc.iterdir():
        if not p.is_dir() or not p.name.isdigit():
            continue
        pid = int(p.name)
        exe = p / "exe"
        try:
            exe_path = os.readlink(exe)
            procs.append((pid, exe_path))
        except Exception:
            continue
    return procs


def _runtime_flags(exe_path: str) -> List[Tuple[str, str]]:
    flags: List[Tuple[str, str]] = []
    for hint in RISKY_RUNTIME_PATHS:
        if exe_path.startswith(hint):
            flags.append(("high", f"Process executing from risky runtime path: {hint}"))
            return flags
    if "/." in exe_path:
        flags.append(("medium", "Process executable located in hidden directory"))
    return flags


def run() -> List[Finding]:
    findings: List[Finding] = []

    processes = _list_process_exec_paths()
    if not processes:
        return findings

    for pid, exe_path in processes:
        flags = _runtime_flags(exe_path)
        if not flags:
            continue

        rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
        severity = max((s for s, _ in flags), key=lambda s: rank[s])

        evidence = [
            Evidence("procfs", "pid", pid),
            Evidence("procfs", "exe", exe_path),
            Evidence("heuristics", "flags", [r for _, r in flags]),
        ]

        findings.append(
            Finding(
                check_id="runtime.process",
                title=f"Review runtime process: PID {pid}",
                severity=severity,
                description=(
                    "Process executable path suggests runtime-only or memory-backed execution. "
                    "This can indicate ephemeral or fileless persistence techniques."
                ),
                evidence=evidence,
                remediation=(
                    "Verify process legitimacy and parent chain. If unexpected, terminate the process "
                    "and investigate how it was launched."
                ),
            )
        )

    return findings
