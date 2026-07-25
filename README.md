# outcats

**Enterprise-grade DEFENSIVE security platform.** `outcats` unifies four things
security teams actually need into one clean, offline-capable CLI:

| Module | Command | What it does |
|--------|---------|--------------|
| Hardening audit | `outcats harden` | CIS/STIG-style configuration audit with severity + remediation |
| Vulnerability scanner | `outcats scan` | Read-only service fingerprint + CVE correlation (no exploitation) |
| CTF / lab trainer | `outcats lab` | Methodology checklists, notes, and progress tracking for practice labs |
| Blue-team detection | `outcats detect` | Log ingestion, detection-rule engine, and alerting |

## Authorized use only

`outcats` is a **defensive and educational** tool. It performs **auditing,
reporting, read-only fingerprinting, and detection** — it does **not** perform
exploitation, credential attacks, denial-of-service, or social engineering.

You may only point it at:

1. Systems you **own**, or
2. Systems you have **explicit written authorization** to assess, or
3. **Intentionally-vulnerable practice labs** (HackTheBox, TryHackMe, your own VMs).

Every scanning command is gated behind `outcats authorize`, which records an
attestation and an explicit host scope. Targets outside that scope are refused.

## Quick start

```bash
# 1. Attest authorization and declare your scope (one time)
outcats authorize

# 2. Guided intake — tell it what you know (or nothing) and it guides you
outcats guide

# 3. Run modules
outcats harden --level 1 --format html --out report.html
outcats scan --target 127.0.0.1 --ports common
outcats lab start "HTB - Blue" --template smb
outcats detect run --rules data/detection_rules.json --log /var/log/auth.log
```

## Design principles

- **Offline-first.** Ships with a local CVE dataset and CIS mappings; no network
  calls required to run.
- **Read-only by default.** Nothing changes state on a target. Remediation is
  emitted as guidance/scripts for *you* to review and apply.
- **Auditable.** Every run is scoped, timestamped, and reproducible.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
