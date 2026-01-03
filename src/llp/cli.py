from __future__ import annotations
import argparse
from pathlib import Path as _Path
import json as _json

from llp.checks import (
    cron,
    systemd,
    shell_init,
    xdg_autostart,
    runtime_process,
)
from llp.core.baseline import Baseline, diff_baseline, make_baseline
from llp.core.output import to_json, to_text


def _run_checks(selected: set[str]):
    run_all = "all" in selected or not selected
    findings = []
    if run_all or "systemd" in selected:
        findings.extend(systemd.run())
    if run_all or "cron" in selected:
        findings.extend(cron.run())
    if run_all or "shell_init" in selected:
        findings.extend(shell_init.run())
    if run_all or "xdg_autostart" in selected:
        findings.extend(xdg_autostart.run())
    if run_all or "runtime_process" in selected:
        findings.extend(runtime_process.run())
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="llp",
        description="Linux Less-Persistence (defensive audit toolkit)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--checks",
        default="all",
        help=(
            "Comma-separated list of checks to run: "
            "all,systemd,cron,shell_init,xdg_autostart,runtime_process"
        ),
    )
    parser.add_argument(
        "--baseline-save",
        metavar="PATH",
        help="Save a baseline JSON file to PATH based on current findings.",
    )
    parser.add_argument(
        "--baseline-compare",
        metavar="PATH",
        help="Compare current findings to an existing baseline JSON at PATH.",
    )
    args = parser.parse_args()

    selected = {c.strip().lower() for c in args.checks.split(",") if c.strip()}
    findings = _run_checks(selected)

    if args.baseline_save:
        b = make_baseline(findings, version="0.1.0")
        _Path(args.baseline_save).write_text(b.to_json(), encoding="utf-8")
        print(f"Baseline written to: {args.baseline_save}")
        return 0

    if args.baseline_compare:
        old_text = _Path(args.baseline_compare).read_text(encoding="utf-8")
        old = Baseline.from_json(old_text)
        diff = diff_baseline(old, findings)
        print(_json.dumps(diff, indent=2, ensure_ascii=False))
        return 0

    print(to_json(findings) if args.format == "json" else to_text(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
