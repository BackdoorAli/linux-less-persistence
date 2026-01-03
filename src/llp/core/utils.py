from __future__ import annotations
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple


def run_cmd(cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
    """Run a command safely (read-only intent). Returns (rc, stdout, stderr)."""
    p = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def read_text(path: Path, max_bytes: int = 200_000) -> Optional[str]:
    """Safely read small text files; returns None on error or oversize."""
    try:
        data = path.read_bytes()
        if len(data) > max_bytes:
            return None
        return data.decode(errors="replace")
    except Exception:
        return None
