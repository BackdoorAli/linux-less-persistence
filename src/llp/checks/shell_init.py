from __future__ import annotations
from pathlib import Path
from typing import List, Tuple

from llp.core.models import Evidence, Finding
from llp.core.utils import read_text

SHELL_INIT_FILES = [
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
]

SUSPICIOUS_HINTS = (
    "/tmp/",
    "/dev/shm/",
    "curl ",
    "wget ",
    "nc ",
    "bash -c",
    "python -c",
    "base64",
)

def _scan_file(path: Path) -> List[Tuple[str, str]]:
    flags: List[Tuple[str, str]] = []
    text = read_text(path)
    if not text:
        return flags

    lowered = text.lower()
    for hint in SUSPICIOUS_HINTS:
        if hint in lowered:
            flags.append(("medium", f"Shell init contains suspicious token: {hint.strip()}"))
            break

    if "/." in text:
        flags.append(("low", "Shell init references hidden paths; verify intent"))

    return flags


def run() -> List[Finding]:
    findings: List[Finding] = []

    home = Path.home()
    for name in SHELL_INIT_FILES:
        p = home / name
        if not p.exists() or not p.is_file():
            continue

        flags = _scan_file(p)
        if not flags:
            continue

        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
        severity = max((s for s, _ in flags), key=lambda s: severity_rank[s])

        text = read_text(p)
        evidence = [
            Evidence("filesystem", "path", str(p)),
            Evidence("heuristics", "flags", [r for _, r in flags]),
        ]

        if text:
            evidence.append(
                Evidence(
                    "filesystem",
                    "snippet",
                    "\n".join(text.splitlines()[:60]),
                )
            )

        findings.append(
            Finding(
                check_id="shell.init",
                title=f"Review shell initialization file: {p.name}",
                severity=severity,
                description=(
                    "Shell initialization files execute on login or shell start and are "
                    "a common persistence surface. Flags are heuristic-only."
                ),
                evidence=evidence,
                remediation=(
                    "Verify each command is expected. Remove or comment unexpected entries "
                    "and review recent user changes."
                ),
            )
        )

    return findings
