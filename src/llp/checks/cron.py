from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from llp.core.models import Evidence, Finding
from llp.core.utils import read_text, run_cmd


SUSPICIOUS_PATH_HINTS = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    "/.cache/",
    "/.local/share/",
)

# Common cron locations on Debian/Kali-like systems.
SYSTEM_CRON_LOCATIONS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
]

USER_CRON_SPOOL_DIRS = [
    Path("/var/spool/cron/crontabs"),  # Debian/Ubuntu/Kali
    Path("/var/spool/cron"),           # RHEL/CentOS/Fedora
]


@dataclass
class CronArtifact:
    kind: str                 # "file" | "dir_entry" | "user_spool"
    path: Path
    owner: Optional[str] = None


def _path_owner(path: Path) -> Optional[str]:
    """Best-effort owner lookup (name), without requiring extra deps."""
    try:
        st = path.stat()
        # Use `id -nu <uid>` to avoid importing pwd in restricted envs.
        rc, out, _ = run_cmd(["id", "-nu", str(st.st_uid)], timeout=2)
        return out if rc == 0 and out else str(st.st_uid)
    except Exception:
        return None


def _collect_system_artifacts() -> List[CronArtifact]:
    artifacts: List[CronArtifact] = []

    for p in SYSTEM_CRON_LOCATIONS:
        if p.is_file():
            artifacts.append(CronArtifact(kind="file", path=p, owner=_path_owner(p)))
        elif p.is_dir():
            for child in sorted(p.glob("*")):
                # cron.* dirs can contain scripts; /etc/cron.d contains cron files.
                if child.is_file():
                    artifacts.append(CronArtifact(kind="dir_entry", path=child, owner=_path_owner(child)))

    return artifacts


def _collect_user_spool_artifacts() -> List[CronArtifact]:
    artifacts: List[CronArtifact] = []
    for d in USER_CRON_SPOOL_DIRS:
        if not d.exists() or not d.is_dir():
            continue
        for child in sorted(d.glob("*")):
            # Debian uses per-user files with strict perms; still treat as artifacts.
            if child.is_file():
                artifacts.append(CronArtifact(kind="user_spool", path=child, owner=_path_owner(child)))
    return artifacts


def _looks_suspicious(text: str) -> List[Tuple[str, str]]:
    """Heuristic-only flags; returns list of (severity, reason)."""
    flags: List[Tuple[str, str]] = []

    # Cron can run anything; we focus on review triggers, not conclusions.
    lowered = text.lower()

    # URLs in cron sometimes indicate download/execute patterns (also legit for backups).
    if "http://" in lowered or "https://" in lowered:
        flags.append(("medium", "Cron content includes URL(s); review for unexpected network retrieval."))

    # Risky temp/memory-backed paths.
    for hint in SUSPICIOUS_PATH_HINTS:
        if hint in text:
            flags.append(("medium", f"Cron references potentially risky location: {hint}"))
            break

    # Obfuscation-ish markers (still can be legit).
    if "base64" in lowered:
        flags.append(("low", "Cron content references 'base64'; verify intent and source."))

    # Hidden file/dot-dir references can be normal, but worth review.
    if "/." in text:
        flags.append(("low", "Cron references hidden path(s) (dot-files/dirs); verify intent."))

    return flags


def _severity_from(flags: List[Tuple[str, str]]) -> str:
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    return max((s for s, _ in flags), key=lambda s: rank.get(s, 0)) if flags else "info"


def run() -> List[Finding]:
    findings: List[Finding] = []

    artifacts = _collect_system_artifacts() + _collect_user_spool_artifacts()
    if not artifacts:
        return [
            Finding(
                check_id="cron.artifacts",
                title="Cron artifacts",
                severity="info",
                description="No cron artifacts were found in common locations, or access was restricted.",
                evidence=[],
            )
        ]

    for a in artifacts:
        content = read_text(a.path)
        if content is None:
            findings.append(
                Finding(
                    check_id="cron.artifacts",
                    title=f"Review cron artifact (unreadable/large): {a.path}",
                    severity="info",
                    description="Cron artifact exists but could not be read (permission, binary, or too large).",
                    evidence=[
                        Evidence("filesystem", "path", str(a.path)),
                        Evidence("filesystem", "kind", a.kind),
                        Evidence("filesystem", "owner", a.owner),
                    ],
                    remediation="Verify permissions and inspect the file contents using appropriate privileges.",
                )
            )
            continue

        flags = _looks_suspicious(content)
        # We still emit a finding for visibility, but lower severity when no flags.
        severity = _severity_from(flags)
        if not flags:
            # Keep noise manageable: only emit 'info' for a small subset (e.g., /etc/crontab).
            if a.path != Path("/etc/crontab"):
                continue

        evidence = [
            Evidence("filesystem", "path", str(a.path)),
            Evidence("filesystem", "kind", a.kind),
            Evidence("filesystem", "owner", a.owner),
            Evidence("filesystem", "snippet", "\n".join(content.splitlines()[:80])),
        ]
        if flags:
            evidence.append(Evidence("heuristics", "flags", [r for _, r in flags]))

        findings.append(
            Finding(
                check_id="cron.artifacts",
                title=f"Review cron artifact: {a.path}",
                severity=severity if flags else "info",
                description=(
                    "Module 2 checks cron-related locations for entries that deserve review. "
                    "Flags are heuristic and not a determination of compromise."
                ),
                evidence=evidence,
                remediation=(
                    "Confirm the artifact's purpose and provenance. If unexpected, disable/remove it per policy, "
                    "and review referenced scripts/binaries and recent account changes."
                ),
            )
        )

    return findings
