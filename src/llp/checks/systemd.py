from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Dict

from llp.core.models import Evidence, Finding
from llp.core.utils import run_cmd, read_text

SUSPICIOUS_PATH_HINTS = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    "/.cache/",
    "/.local/share/",
)

VENDOR_UNIT_DIR_HINTS = (
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
)

LOCAL_UNIT_DIR_HINTS = (
    "/etc/systemd/system/",
    "/run/systemd/system/",
)

@dataclass
class UnitInfo:
    name: str
    scope: str
    enabled_state: str
    unit_file: Optional[Path]
    exec_start: Optional[str]
    drop_in_paths: List[Path]

def _parse_kv(out: str) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv

def _extract_exec_path(execstart_raw: str) -> Optional[str]:
    if "path=" in execstart_raw:
        idx = execstart_raw.find("path=")
        sub = execstart_raw[idx + 5 :]
        for sep in [" ", ";", "}", ","]:
            if sep in sub:
                sub = sub.split(sep, 1)[0]
        return sub if sub.startswith("/") else None
    parts = execstart_raw.split()
    return parts[0] if parts and parts[0].startswith("/") else None

def _list_units(scope: str) -> List[str]:
    cmd = ["systemctl"]
    if scope == "user":
        cmd.append("--user")
    cmd += ["list-unit-files", "--type=service", "--no-pager", "--no-legend"]
    rc, out, _ = run_cmd(cmd, timeout=10)
    return sorted({l.split()[0] for l in out.splitlines()}) if rc == 0 else []

def _enabled_state(name: str, scope: str) -> str:
    cmd = ["systemctl"]
    if scope == "user":
        cmd.append("--user")
    cmd += ["is-enabled", name]
    rc, out, _ = run_cmd(cmd, timeout=5)
    return out or "unknown"

def _unit_props(name: str, scope: str) -> Dict[str, str]:
    cmd = ["systemctl"]
    if scope == "user":
        cmd.append("--user")
    cmd += ["show", name, "--property=FragmentPath", "--property=ExecStart", "--property=DropInPaths"]
    rc, out, _ = run_cmd(cmd, timeout=10)
    return _parse_kv(out) if rc == 0 else {}

def _dropins(props: Dict[str, str]) -> List[Path]:
    v = props.get("DropInPaths", "")
    paths: List[Path] = []
    for p in v.split():
        pp = Path(p)
        if pp.exists():
            paths.append(pp)
    return paths

def _heuristics(u: UnitInfo) -> List[Tuple[str, str]]:
    flags: List[Tuple[str, str]] = []

    if u.scope == "user" and u.enabled_state == "enabled":
        flags.append(("low", "Enabled user-level service"))

    if u.drop_in_paths:
        flags.append(("low", "Service has drop-in override snippets"))

    if u.unit_file:
        p = str(u.unit_file)
        if any(h in p for h in LOCAL_UNIT_DIR_HINTS) and u.enabled_state == "enabled":
            flags.append(("medium", "Enabled unit from local override directory"))
        if u.scope == "user" and "/.config/systemd/user/" in p and u.enabled_state == "enabled":
            flags.append(("medium", "Enabled unit in user config directory"))
    else:
        flags.append(("info", "FragmentPath unavailable"))

    if u.exec_start:
        exec_path = _extract_exec_path(u.exec_start)
        for hint in SUSPICIOUS_PATH_HINTS:
            if hint in u.exec_start:
                flags.append(("medium", f"ExecStart references risky path: {hint}"))
                break
        if exec_path and exec_path.startswith(("/tmp/", "/dev/shm/")):
            flags.append(("high", "Executable path in temp or memory-backed directory"))

    return flags

def run() -> List[Finding]:
    findings: List[Finding] = []

    for scope in ("system", "user"):
        for name in _list_units(scope):
            props = _unit_props(name, scope)
            fragment = props.get("FragmentPath", "")
            unit_file = Path(fragment) if fragment and Path(fragment).exists() else None
            exec_start = props.get("ExecStart") or None
            drop_in_paths = _dropins(props)

            u = UnitInfo(
                name=name,
                scope=scope,
                enabled_state=_enabled_state(name, scope),
                unit_file=unit_file,
                exec_start=exec_start,
                drop_in_paths=drop_in_paths,
            )

            flags = _heuristics(u)
            if not flags:
                continue

            rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
            severity = max((s for s, _ in flags), key=lambda s: rank[s])

            evidence = [
                Evidence("systemctl", "unit", u.name),
                Evidence("systemctl", "scope", u.scope),
                Evidence("systemctl", "enabled_state", u.enabled_state),
                Evidence("heuristics", "flags", [r for _, r in flags]),
            ]

            if u.unit_file:
                evidence.append(Evidence("systemctl", "FragmentPath", str(u.unit_file)))
                txt = read_text(u.unit_file)
                if txt:
                    evidence.append(Evidence("filesystem", "unit_file_snippet", "\n".join(txt.splitlines()[:40])))

            if u.exec_start:
                evidence.append(Evidence("systemctl", "ExecStart", u.exec_start))

            findings.append(
                Finding(
                    check_id="systemd.units",
                    title=f"Review systemd service: {u.name} ({u.scope})",
                    severity=severity,
                    description="Heuristic indicators suggest review. This is not a determination of compromise.",
                    evidence=evidence,
                    remediation="Verify service origin, overrides, and ExecStart paths. Disable if unexpected.",
                )
            )

    return findings
