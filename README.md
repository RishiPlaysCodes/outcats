# outcats

**Enterprise-grade DEFENSIVE security platform.** `outcats` unifies four things
security teams actually need into one clean, offline-capable CLI:

| Module | Command | What it does |
|--------|---------|--------------|
| Hardening audit | `outcats harden` | Cross-platform (Linux/macOS/Windows) CIS/STIG-style audit with severity + remediation |
| Vulnerability scanner | `outcats scan` | Read-only service fingerprint + CVE correlation (no exploitation) |
| CTF / lab trainer | `outcats lab` | Methodology checklists (incl. red-team ATT&CK study plan), notes, progress tracking |
| Blue-team detection | `outcats detect` | Log ingestion, 10+ detection rules with MITRE mapping, alerting |
| Web GUI | `outcats gui` | Zero-dependency dashboard in any browser — Windows, Linux, macOS, phone/tablet |

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

# 3. Run modules from the CLI
outcats harden --level 1 --format html --out report.html
outcats harden --platform macos          # preview another platform's checks
outcats scan --target 127.0.0.1 --ports common
outcats lab start "HTB - Blue" --template smb
outcats lab start "ATT&CK study" --template redteam
outcats detect run --log /var/log/auth.log

# 4. ...or launch the cross-platform web dashboard
outcats gui                               # then open http://127.0.0.1:8787
```

## Cross-platform GUI

`outcats gui` starts a local, dependency-free web dashboard served straight from
the Python standard library. Open the printed URL in **any** browser — a laptop
on Windows/macOS/Linux, or a phone/tablet on the same network. It exposes the
hardening audit, authorized scan, and detection modules with the same read-only
guarantees and the same authorization gate as the CLI. It binds to `127.0.0.1`
by default; binding elsewhere requires an explicit `--host` and prints a warning.

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
