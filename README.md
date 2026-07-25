# outcats

**Enterprise-grade DEFENSIVE security platform.** `outcats` unifies four things
security teams actually need into one clean, offline-capable CLI:

| Module | Command | What it does |
|--------|---------|--------------|
| Hardening audit | `outcats harden` | Cross-platform (Linux/macOS/Windows) CIS/STIG-style audit with severity + remediation |
| Password audit | `outcats passwords` | Credential hygiene: empty passwords, no-expiry accounts, duplicate UIDs |
| Vulnerability scanner | `outcats scan` | Read-only service fingerprint + CVE correlation (no exploitation) |
| Network mapper | `outcats netmap` | Multi-host service scan with host×port matrix visualization |
| SSL/TLS checker | `outcats tls` | Certificate validity, expiry, protocol, cipher strength assessment |
| OSINT recon | `outcats osint` | Passive recon for your own domains: DNS, headers, subdomains |
| CTF / lab trainer | `outcats lab` | Methodology checklists (incl. red-team ATT&CK study plan), notes, progress tracking |
| Blue-team detection | `outcats detect` | Log ingestion, 10+ detection rules with MITRE mapping, alerting |
| Web GUI | `outcats gui` | Zero-dependency dashboard in any browser — Windows, Linux, macOS, phone/tablet |
| Interactive TUI | `outcats interactive` | Menu-driven shell, no flags to remember |

**Export formats:** text, JSON, CSV (for SIEM/spreadsheets), HTML, PDF (print-ready HTML → Save as PDF).

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
outcats passwords                         # credential hygiene audit
outcats scan --target 127.0.0.1 --ports common
outcats netmap --targets 10.0.0.1,10.0.0.2 --ports common
outcats tls --targets mysite.com,api.mysite.com
outcats osint --domain mydomain.com
outcats lab start "HTB - Blue" --template smb
outcats lab start "ATT&CK study" --template redteam
outcats detect run --log /var/log/auth.log

# 4. Export any report as CSV (for SIEM) or PDF
outcats harden --format csv --out audit.csv
outcats scan --target 10.0.0.1 --format pdf --out scan.pdf.html

# 5. ...or launch the cross-platform web dashboard
outcats gui                               # then open http://127.0.0.1:8787

# 6. ...or use the interactive TUI (no flags needed!)
outcats interactive
```

## Cross-platform GUI

`outcats gui` starts a local, dependency-free web dashboard served straight from
the Python standard library. Open the printed URL in **any** browser — a laptop
on Windows/macOS/Linux, or a phone/tablet on the same network. It exposes the
hardening audit, authorized scan, and detection modules with the same read-only
guarantees and the same authorization gate as the CLI. It binds to `127.0.0.1`
by default; binding elsewhere requires an explicit `--host` and prints a warning.

## Deploying the dashboard (free)

The GUI reads `PORT`, `HOST`, and `OUTCATS_TOKEN` from the environment, so it
runs on most free hosts with no code changes. A `Dockerfile`, `Procfile`, and
`render.yaml` are included.

> **Heads up:** deployed to the cloud, the hardening audit reflects the *server's*
> posture, not your own machine. Great for demoing the UI; run it locally to
> audit your own hosts. Always set `OUTCATS_TOKEN` before exposing it publicly.

**Render.com (Docker blueprint):**
1. Push this repo to GitHub.
2. Render -> **New + -> Blueprint** -> pick the repo (`render.yaml` is detected).
3. Render builds the Dockerfile, injects `PORT`, and generates `OUTCATS_TOKEN`.
4. Open `https://<your-app>.onrender.com/?token=<the-generated-token>`.

**Any Docker host / Fly.io / Cloud Run:**
```bash
docker build -t outcats .
docker run -p 8787:8787 -e OUTCATS_TOKEN=please-change-me outcats
# then open http://localhost:8787/?token=please-change-me
```

**Local test (no deploy, fully free):**
```bash
outcats gui                       # localhost only, no token needed
outcats gui --host 0.0.0.0 --token mytoken --port 8080   # LAN / phone testing
```

The `/healthz` endpoint is unauthenticated (returns only `{"status":"ok"}`) for
platform health probes.

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
