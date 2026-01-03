# Linux Less-Persistence  
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active%20development-orange.svg)
**Defensive Audit Toolkit for Low‑Artifact Persistence on Linux**

---

## Author

**BackdoorAli**  
GitHub: https://github.com/BackdoorAli

---

## Overview

**Linux Less‑Persistence** is a modular, defensive security toolkit designed to help security professionals examine *low‑artifact persistence mechanisms* on Linux systems.

It focuses on persistence surfaces frequently abused by attackers, while deliberately avoiding operational or step‑by‑step instructions. The goal is **visibility and understanding**, not enablement.

This project is intended for:
- Defensive security engineering
- Incident response and threat hunting
- Red teams performing detection‑aware assessments
- Linux hardening and security research

This is **not** a persistence deployment framework.  
It is a **heuristic audit and analysis toolkit**.

---

## Ethical Use & Disclaimer

This project is published with **explicit defensive and educational intent**.

It is designed to help identify *signals* and *patterns* that may indicate persistence abuse, without providing actionable guidance on how to establish or maintain persistence.

You must only use this software on systems you:
- own,
- administer, or
- are explicitly authorized to assess.

By using this tool, you agree to comply with all applicable laws and regulations.

> Knowing how persistence mechanisms behave conceptually is not wrongdoing.  
> Using that knowledge irresponsibly is.

**Linux Less‑Persistence does not contain offensive tooling, payloads, or exploitation workflows.**

---

## Threat Model

Attackers seeking long‑term access to Linux systems increasingly avoid obvious persistence mechanisms such as:
- conspicuous daemons
- well‑known startup scripts
- clearly identifiable binaries

Instead, they favor **low‑artifact persistence**, where legitimate system behavior overlaps with persistence potential.

Common attacker considerations include:
- What executes implicitly without user interaction?
- What blends into normal configuration?
- What survives reboots without obvious binaries?
- What is rarely inspected during routine audits?

This project mirrors that reasoning from a **defender’s perspective**, identifying areas where persistence *could* hide — without demonstrating how to place it there.

Understanding attacker tradecraft at a conceptual level is essential for effective defense, detection engineering, and incident response.

---

## Installation

```bash
git clone https://github.com/BackdoorAli/linux-less-persistence.git
cd linux-less-persistence
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Modules & Detection Surfaces

### systemd Units
Inspects system‑level and user‑level services for:
- unexpected local overrides
- drop‑in configuration snippets
- risky or unusual execution paths

### Cron Artifacts
Audits cron tables and spool entries for scheduled execution that warrants review.

### Shell Initialization
Examines shell startup files (e.g. `.bashrc`, `.profile`, `.zshrc`) that execute implicitly on login or shell start.

### XDG Autostart
Reviews desktop autostart `.desktop` entries that execute on graphical session launch.

### Runtime / Memory‑Only Processes
Flags running processes whose executables originate from ephemeral or memory‑backed locations.

All findings are **heuristic signals**, not conclusions. Context and analyst judgment are required.

---

## Limitations

This toolkit does **not** guarantee:
- deterministic identification of malicious activity
- complete detection of fully fileless attacks
- coverage of kernel‑level or firmware‑level persistence

Limitations exist because:
- some legitimate software exhibits similar patterns
- advanced attackers may use techniques outside user‑space visibility
- context is required to distinguish misconfiguration from compromise

Treat findings as **investigative starting points**, not final verdicts.

---

## Baseline Comparison

Linux Less‑Persistence supports baseline generation and comparison to detect drift over time.

```bash
# Save a known‑good baseline
llp --baseline-save baseline.json

# Compare current state to baseline
llp --baseline-compare baseline.json
```

This is useful for:
- system hardening validation
- post‑incident comparison
- change monitoring

---

## Usage Examples

```bash
# Run all modules
llp

# Run selected modules
llp --checks systemd,cron

# Output results as JSON
llp --format json
```

---

## Red Team Perspective (Conceptual)

From a red team standpoint, effective persistence is rarely about complexity — it is about **invisibility**.

Attackers often evaluate:
- which execution paths are trusted
- which configurations are rarely audited
- which mechanisms appear benign when slightly altered

This project acknowledges those realities without crossing into operational guidance.

The intent is to help defenders — and responsible red teams — reason about **detection risk**, not exploitation success.

---

## License

Distributed under the MIT License. Read LICENSE.md for more.

---

## Status

This project is under active development.  
Additional modules, refinements, and documentation may be added over time.
