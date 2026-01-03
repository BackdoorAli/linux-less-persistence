from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Evidence:
    source: str
    key: str
    value: Any


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str  # info | low | medium | high
    description: str
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": [e.__dict__ for e in self.evidence],
            "remediation": self.remediation,
            "references": self.references,
        }
