from __future__ import annotations
from pathlib import Path
from typing import List, Tuple

from llp.core.models import Evidence, Finding
from llp.core.utils import read_text

# XDG autostart locations (user-level and system-level).
XDG_AUTOSTART_DIRS = [
    Path.home() / ".config" / "autostart",
    Path("/etc/xdg/autostart"),
]

SUSPICIOUS_HINTS = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "curl ",
    "wget ",
    "bash -c",
    "sh -c",
    "python -c",
    "base64",
)


def _scan_desktop_file(path: Path) -> List[Tuple[str, str]]:
    flags: List[Tuple[str, str]] = []
    text = read_text(path)
    if not text:
        return flags

    lowered = text.lower()

    # Look specifically at Exec= lines, but keep it simple/robust.
    exec_lines = [l for l in lowered.splitlines() if l.strip().startswith("exec=")]
    joined = "\n".join(exec_lines) if exec_lines else lowered

    for hint in SUSPICIOUS_HINTS:
        if hint in joined:
            flags.append(("medium", f"Autostart Exec contains suspicious token: {hint.strip()}"))
            break

    if "/." in joined:
        flags.append(("low", "Autostart Exec references hidden paths; verify intent"))

    return flags


def run() -> List[Finding]:
    findings: List[Finding] = []

    for base in XDG_AUTOSTART_DIRS:
        if not base.exists() or not base.is_dir():
            continue

        for desktop_file in sorted(base.glob("*.desktop")):
            flags = _scan_desktop_file(desktop_file)
            if not flags:
                continue

            rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
            severity = max((s for s, _ in flags), key=lambda s: rank[s])

            text = read_text(desktop_file)
            evidence = [
                Evidence("filesystem", "path", str(desktop_file)),
                Evidence("filesystem", "scope", "user" if str(desktop_file).startswith(str(Path.home())) else "system"),
                Evidence("heuristics", "flags", [r for _, r in flags]),
            ]

            if text:
                evidence.append(
                    Evidence(
                        "filesystem",
                        "snippet",
                        "\n".join(text.splitlines()[:80]),
                    )
                )

            findings.append(
                Finding(
                    check_id="xdg.autostart",
                    title=f"Review XDG autostart entry: {desktop_file.name}",
                    severity=severity,
                    description=(
                        "XDG autostart entries execute automatically on desktop login "
                        "and are a common user-level persistence surface. Flags are heuristic-only."
                    ),
                    evidence=evidence,
                    remediation=(
                        "Confirm the entry is expected for this system/user. "
                        "Disable or remove unexpected autostart files and review referenced executables."
                    ),
                )
            )

    return findings
