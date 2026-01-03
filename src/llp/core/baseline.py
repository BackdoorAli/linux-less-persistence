from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List

from llp.core.models import Finding


def _stable_id(f: Finding) -> str:
    """Create a stable identifier for a finding using its anchor evidence."""
    anchors: List[str] = []
    for e in f.evidence:
        if e.key in ("FragmentPath", "path"):
            anchors.append(str(e.value))
    anchor = anchors[0] if anchors else f.title
    raw = f"{f.check_id}|{anchor}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class Baseline:
    version: str
    findings: Dict[str, Dict]

    def to_json(self) -> str:
        return json.dumps(
            {"version": self.version, "findings": self.findings},
            indent=2,
            ensure_ascii=False,
        )

    @staticmethod
    def from_json(text: str) -> "Baseline":
        obj = json.loads(text)
        return Baseline(
            version=obj.get("version", "unknown"),
            findings=obj.get("findings", {}),
        )


def make_baseline(findings: List[Finding], version: str = "0.1.0") -> Baseline:
    mapped: Dict[str, Dict] = {}
    for f in findings:
        fid = _stable_id(f)
        mapped[fid] = f.to_dict()
    return Baseline(version=version, findings=mapped)


def diff_baseline(old: Baseline, new_findings: List[Finding]) -> Dict[str, List[Dict]]:
    """Return added / removed / changed findings compared to baseline."""
    new_base = make_baseline(new_findings, version=old.version)
    old_ids = set(old.findings.keys())
    new_ids = set(new_base.findings.keys())

    added = [new_base.findings[i] for i in sorted(new_ids - old_ids)]
    removed = [old.findings[i] for i in sorted(old_ids - new_ids)]

    changed: List[Dict] = []
    for i in sorted(old_ids & new_ids):
        o = old.findings[i]
        n = new_base.findings[i]
        if o.get("severity") != n.get("severity") or o.get("description") != n.get("description"):
            changed.append({"id": i, "old": o, "new": n})

    return {"added": added, "removed": removed, "changed": changed}
