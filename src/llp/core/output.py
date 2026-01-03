from __future__ import annotations
import json
from typing import List
from llp.core.models import Finding


def to_json(findings: List[Finding]) -> str:
    """Serialize findings to JSON."""
    return json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False)


def to_text(findings: List[Finding]) -> str:
    """Human-readable text output."""
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.title}")
        lines.append(f"  {f.description}")
        for e in f.evidence[:8]:
            lines.append(f"  - {e.source}:{e.key} = {str(e.value)[:200]}")
        if f.remediation:
            lines.append(f"  Remediation: {f.remediation}")
        lines.append("")
    return "\n".join(lines).rstrip()
