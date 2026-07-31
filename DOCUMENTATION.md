# outcats - Complete Technical Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Module Reference](#module-reference)
   - [Authorization Gate](#1-authorization-gate)
   - [Hardening Audit](#2-hardening-audit)
   - [Password Policy Audit](#3-password-policy-audit)
   - [Vulnerability Scanner](#4-vulnerability-scanner)
   - [Network Mapper](#5-network-mapper)
   - [SSL/TLS Checker](#6-ssltls-checker)
   - [OSINT Passive Recon](#7-osint-passive-recon)
   - [Blue-Team Detection](#8-blue-team-detection)
   - [CTF/Lab Companion](#9-ctflab-companion)
   - [Web GUI Dashboard](#10-web-gui-dashboard)
   - [Interactive TUI](#11-interactive-tui)
   - [Guided Intake](#12-guided-intake)
6. [Report Engine & Export Formats](#report-engine--export-formats)
7. [Deployment Guide](#deployment-guide)
8. [File-by-File Code Reference](#file-by-file-code-reference)
9. [Data Files Reference](#data-files-reference)
10. [Security Model](#security-model)

---


## Project Overview

**outcats** is an enterprise-grade, zero-dependency defensive security platform
written entirely in Python's standard library. It provides 12 CLI subcommands
covering hardening audits, vulnerability scanning, network mapping, TLS
inspection, OSINT reconnaissance, blue-team log detection, and offensive-security
learning methodology — all behind a mandatory authorization gate that refuses to
operate on targets outside a declared scope.

### Key Design Decisions

- **Zero external dependencies.** Runs on any system with Python 3.10+. No pip
  install of third-party packages required.
- **Read-only by design.** Never modifies state on any target. Remediation is
  emitted as guidance for the operator to review and apply.
- **Authorization-first.** Every network-touching command validates the target
  against an attested scope before opening any socket.
- **Offline-capable.** Ships with bundled CVE data, CIS benchmarks, detection
  rules, and methodology templates.
- **Cross-platform.** Runs on Linux, macOS, and Windows. Platform-specific checks
  auto-detect the OS and route accordingly.

---

## Architecture

```
outcats/
├── __init__.py              # Package metadata, version
├── cli.py                   # Unified argparse CLI (12 subcommands)
├── authorization.py         # Scope attestation, enforcement, persistence
├── guide.py                 # Guided intake advisor
├── interactive.py           # Menu-driven TUI shell
├── common/
│   ├── __init__.py
│   ├── system.py            # Local system fingerprinting
│   ├── report.py            # Finding/Report model + text/JSON/HTML renderers
│   └── export.py            # CSV and PDF (print-ready HTML) exporters
├── harden/
│   ├── __init__.py
│   ├── checks.py            # CIS/STIG check registry (Linux/macOS/Windows)
│   ├── audit.py             # Audit runner
│   └── passwords.py         # Credential hygiene auditor
├── scan/
│   ├── __init__.py
│   ├── fingerprint.py       # TCP connect-scan + banner grab
│   ├── cve.py               # Offline CVE correlation engine
│   └── scanner.py           # Orchestrator → Report
├── netmap/
│   ├── __init__.py
│   └── mapper.py            # Multi-host network mapper + matrix renderer
├── tlscheck/
│   ├── __init__.py
│   └── checker.py           # SSL/TLS certificate + protocol auditor
├── osint/
│   ├── __init__.py
│   └── recon.py             # Passive DNS/header/subdomain recon
├── detect/
│   ├── __init__.py
│   ├── engine.py            # Regex + threshold detection engine
│   └── runner.py            # Log file ingestion → Report
├── lab/
│   ├── __init__.py
│   └── companion.py         # CTF methodology + engagement tracking
├── gui/
│   ├── __init__.py
│   └── server.py            # stdlib HTTP dashboard (zero deps)
└── data/
    ├── cve_sample.json      # Offline CVE dataset
    ├── detection_rules.json # Blue-team detection rules (MITRE-mapped)
    └── methodologies.json   # Study plan templates (generic/web/smb/redteam)
```

---


## Installation

```bash
# From source (recommended for development)
git clone https://github.com/RishiPlaysCodes/outcats.git
cd outcats
pip install -e .

# Verify
outcats --version
# outcats 0.1.0
```

### Requirements

- Python 3.10 or later
- No external packages (stdlib only)
- Root/admin recommended for full hardening checks (reads /etc/shadow, sysctl)

---

## Configuration

### Authorization Scope (`~/.outcats/scope.json`)

Created by `outcats authorize`. Contains:

```json
{
  "operator": "RishiPlaysCodes",
  "authorization_ref": "I own these hosts",
  "attested_at": 1785020266.0,
  "allowed_hosts": ["127.0.0.1", "10.0.0.0/24", "mydomain.com"],
  "lab_mode": false
}
```

**Fields:**
- `operator` — Your name/handle
- `authorization_ref` — Why you're authorized (engagement ID, ownership, etc.)
- `attested_at` — Unix timestamp of attestation
- `allowed_hosts` — List of IPs, hostnames, or CIDR ranges you may scan
- `lab_mode` — True if targeting intentionally-vulnerable labs

### Environment Variables (for deployment)

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | 8787 | HTTP port (injected by cloud platforms) |
| `HOST` | 127.0.0.1 | Bind address (use 0.0.0.0 for containers) |
| `OUTCATS_TOKEN` | (none) | Access token required on every request |

---


## Module Reference

### 1. Authorization Gate

**File:** `outcats/authorization.py`

**Purpose:** Ensures every network-touching operation is scoped to hosts the
operator owns or is authorized to assess. Refuses all out-of-scope targets.

**Key Classes & Functions:**

| Name | Type | Description |
|------|------|-------------|
| `Scope` | dataclass | Holds operator, auth reference, timestamp, allowed hosts, lab mode |
| `Scope.load()` | classmethod | Load scope from `~/.outcats/scope.json` |
| `Scope.save()` | method | Persist scope to disk |
| `is_in_scope(host, scope)` | function | Check if a host falls within the allowed scope (supports CIDR) |
| `enforce_target(host, scope)` | function | Raise `AuthorizationError` if host is not in scope |
| `require_scope()` | function | Load scope or raise if none exists |
| `interactive_authorize()` | function | Walk user through attestation and scope declaration |
| `AuthorizationError` | exception | Raised when an action is attempted outside scope |

**How CIDR matching works:**
```python
# Uses ipaddress module to check if a host IP falls within a CIDR block
ipaddress.ip_address("10.0.0.55") in ipaddress.ip_network("10.0.0.0/24")
# → True
```

**Loopback hosts** (127.0.0.1, ::1, localhost) are always allowed without
explicit listing.

---

### 2. Hardening Audit

**Files:** `outcats/harden/checks.py`, `outcats/harden/audit.py`

**Purpose:** CIS/STIG-style configuration audit of the local system. Checks are
registered via a decorator, auto-discovered, and routed by platform.

**CLI:**
```bash
outcats harden [--level 1|2] [--platform linux|macos|windows|all] [--format text|json|html|csv|pdf] [--out FILE]
```

**Check Registry (`checks.py`):**

The `@check` decorator registers a function into `_REGISTRY`:

```python
@check("OC-FS-001", "World-writable /etc/passwd", severity=Severity.HIGH, platforms={LINUX, MACOS})
def _passwd_perms() -> Finding:
    # Read-only inspection → return Finding with PASS/FAIL
```

**All registered checks:**

| ID | Title | Level | Severity | Platforms |
|----|-------|-------|----------|-----------|
| OC-FS-001 | World-writable /etc/passwd | 1 | HIGH | Linux, macOS |
| OC-FS-002 | /etc/shadow restricted to root | 1 | CRITICAL | Linux |
| OC-FS-003 | No world-writable files in PATH | 2 | MEDIUM | Linux, macOS |
| OC-SSH-001 | SSH root login disabled | 1 | HIGH | Linux, macOS |
| OC-SSH-002 | SSH password auth disabled | 2 | MEDIUM | Linux, macOS |
| OC-SSH-003 | SSH X11 forwarding disabled | 2 | LOW | Linux, macOS |
| OC-NET-001 | IP forwarding disabled | 1 | MEDIUM | Linux |
| OC-NET-002 | ICMP redirects not accepted | 1 | MEDIUM | Linux |
| OC-NET-003 | Reverse-path filtering enabled | 2 | LOW | Linux |
| OC-ACC-001 | No non-root UID 0 accounts | 1 | CRITICAL | Linux |
| OC-ACC-002 | Password max-age configured | 1 | LOW | Linux |
| OC-MAC-FW | Application firewall enabled | 1 | HIGH | macOS |
| OC-MAC-GATEKEEPER | Gatekeeper enabled | 1 | HIGH | macOS |
| OC-MAC-SIP | System Integrity Protection on | 1 | CRITICAL | macOS |
| OC-MAC-FILEVAULT | FileVault encryption on | 2 | HIGH | macOS |
| OC-WIN-DEFENDER | Defender real-time protection | 1 | HIGH | Windows |
| OC-WIN-FIREWALL | All firewall profiles enabled | 1 | HIGH | Windows |
| OC-WIN-BITLOCKER | BitLocker on system drive | 2 | HIGH | Windows |

**Platform routing (`all_checks`):**
```python
def all_checks(level=2, plat=None) -> list[CheckMeta]:
    if plat is None:
        plat = current_platform()  # auto-detect via platform.system()
    return [c for c in _REGISTRY if c.level <= level and plat in c.platforms]
```

**Audit runner (`audit.py`):**
```python
def run_audit(level=2, plat=None) -> Report:
    # 1. Collect system info
    # 2. Select checks by level + platform
    # 3. Execute each check, catch errors
    # 4. Build and return Report
```

---


### 3. Password Policy Audit

**File:** `outcats/harden/passwords.py`

**Purpose:** Checks local credential hygiene — password policies, empty
passwords, no-expiry accounts, duplicate UIDs. Cross-platform.

**CLI:**
```bash
outcats passwords [--format text|json|html|csv|pdf] [--out FILE]
```

**Checks performed (Linux):**

| ID | What it checks | Source |
|----|---------------|--------|
| OC-PW-MAXAGE | PASS_MAX_DAYS ≤ 365 | /etc/login.defs |
| OC-PW-MINAGE | PASS_MIN_DAYS ≥ 1 | /etc/login.defs |
| OC-PW-MINLEN | PASS_MIN_LEN ≥ 8 | /etc/login.defs |
| OC-PW-EMPTY | Accounts with empty password hash | /etc/shadow |
| OC-PW-NOEXPIRY | Accounts with no password expiry | /etc/shadow |
| OC-PW-SYSUNLOCKED | System accounts not locked | /etc/shadow |
| OC-PW-DUPUID | Duplicate UIDs | /etc/passwd |

**macOS:** Checks `pwpolicy getaccountpolicies` for configured policies.
**Windows:** Checks `Get-ADDefaultDomainPasswordPolicy` via PowerShell.

---

### 4. Vulnerability Scanner

**Files:** `outcats/scan/fingerprint.py`, `outcats/scan/cve.py`, `outcats/scan/scanner.py`

**Purpose:** Connect-only TCP scan of authorized hosts with passive banner
grabbing and offline CVE correlation. No exploitation.

**CLI:**
```bash
outcats scan --target HOST --ports common|all|22,80,8000-8100 [--timeout 1.0] [--format ...] [--out ...]
```

**How it works:**

1. `enforce_target(host, scope)` — validates authorization
2. `scan_host()` — ThreadPoolExecutor connect-scan (32 workers default)
3. For each open port: passive `_grab_banner()` (TCP recv, or minimal HTTP HEAD)
4. `_service_from_banner()` — regex extraction of service name + version
5. `cve.correlate(service, version)` — matches against bundled CVE dataset

**Product-specific version extraction (`fingerprint.py`):**
```python
_PRODUCT_VERSION_RES = {
    "openssh": re.compile(r"openssh[_/](\d+\.\d+(?:p\d+)?)", re.IGNORECASE),
    "nginx":   re.compile(r"nginx/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "apache":  re.compile(r"apache/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    ...
}
```
This prevents grabbing "2.0" from "SSH-2.0-OpenSSH_9.6p1" — correctly extracts "9.6p1".

**CVE correlation (`cve.py`):**
```python
def correlate(service, version) -> list[CVEMatch]:
    # Load bundled JSON dataset
    # For each CVE entry: check if version falls in affected range
    # If version is None: flag all CVEs as "verify manually"
```

**Version parsing handles non-standard formats:**
```python
_parse_version("9.3p2")  → (9, 3, 0, 2)
_parse_version("2.4.49") → (2, 4, 49)
```

**Common ports scanned by default (`COMMON_PORTS`):**
21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
3306, 3389, 5432, 5900, 6379, 8080, 8443

---

### 5. Network Mapper

**File:** `outcats/netmap/mapper.py`

**Purpose:** Scan multiple authorized hosts simultaneously and produce a
host×port service matrix. Shows what's running where at a glance.

**CLI:**
```bash
outcats netmap --targets 10.0.0.1,10.0.0.2,10.0.0.3 [--ports common] [--timeout 1.0] [--format ...]
```

**Key classes:**

| Name | Description |
|------|-------------|
| `HostEntry` | Stores host, open_ports, services dict, banners dict |
| `NetworkMap` | Collection of HostEntry objects + set of all discovered ports |
| `NetworkMap.to_table()` | Renders ASCII host×port matrix with color |

**How it works:**
1. Validates ALL hosts against scope BEFORE scanning begins
2. Creates (host, port) task pairs
3. ThreadPoolExecutor (64 workers) connect-scans all combinations
4. Assembles results into NetworkMap
5. Renders as colored ASCII table or converts to Report for JSON/HTML export

**Example output:**
```
-----------------------------------------------
              22     80     443    3306
-----------------------------------------------
10.0.0.1      ssh    http   https  ·
10.0.0.2      ssh    ·      ·      mysql
10.0.0.3      ·      http   ·      ·
-----------------------------------------------
Hosts: 3 | Open ports discovered: 4
Top services: ssh(2), http(2), https(1), mysql(1)
```

---


### 6. SSL/TLS Checker

**File:** `outcats/tlscheck/checker.py`

**Purpose:** Connects to HTTPS endpoints you own and validates certificate
validity, expiry, protocol version, and cipher strength. Reports weak configs.

**CLI:**
```bash
outcats tls --targets mysite.com,api.mysite.com [--port 443] [--timeout 5.0] [--format ...]
```

**What it checks:**

| Finding ID Pattern | What | Severity when failing |
|-------------------|------|----------------------|
| OC-TLS-PROTO-* | Protocol version (SSLv3/TLS1.0/1.1 = weak) | HIGH |
| OC-TLS-CIPHER-* | Cipher strength (RC4/DES/NULL/EXPORT = weak) | HIGH |
| OC-TLS-EXPIRY-* | Certificate expiry (expired / <30d / <90d) | CRITICAL/HIGH/MEDIUM |
| OC-TLS-SELFSIGNED-* | Self-signed certificate detection | MEDIUM |
| OC-TLS-ERR-* | Connection/TLS errors | HIGH |

**How it works:**
1. Attempts TLS connection with verification ON
2. If cert verification fails → retries with verification OFF (to still report)
3. Extracts: protocol version, cipher name + bits, certificate details
4. Parses notBefore/notAfter for expiry calculation
5. Checks cipher name against `_WEAK_CIPHERS` set
6. Checks protocol against `_WEAK_PROTOCOLS` set

**Weak cipher detection:**
```python
_WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
```

**Certificate info extracted (`CertInfo` dataclass):**
- subject, issuer, notBefore, notAfter, serial, SAN list, version, SHA-256 fingerprint

---

### 7. OSINT Passive Recon

**File:** `outcats/osint/recon.py`

**Purpose:** Passive, read-only reconnaissance for domains YOU OWN. DNS records,
HTTP security headers, WHOIS expiry, and subdomain discovery.

**CLI:**
```bash
outcats osint --domain mydomain.com [--format ...]
```

**What it does (all read-only, no brute-force):**

| Step | Method | What |
|------|--------|------|
| DNS records | socket.getaddrinfo + `dig` | A, AAAA, MX, NS, TXT, CNAME |
| HTTP headers | urllib HEAD request | Checks 7 security headers |
| WHOIS expiry | `whois` command | Domain expiration date |
| Subdomain discovery | DNS A-record lookup | 13 common prefixes (www, mail, api, etc.) |
| SPF includes | TXT record parsing | Domains referenced in SPF |

**Security headers checked:**
1. Strict-Transport-Security (HSTS)
2. Content-Security-Policy (CSP)
3. X-Content-Type-Options
4. X-Frame-Options
5. X-XSS-Protection
6. Referrer-Policy
7. Permissions-Policy

Missing headers are flagged as MEDIUM severity findings with OWASP references.

**What it does NOT do:**
- No brute-force enumeration
- No active vulnerability testing
- No scanning of third-party infrastructure
- No certificate transparency log queries (could be added)

---

### 8. Blue-Team Detection

**Files:** `outcats/detect/engine.py`, `outcats/detect/runner.py`

**Purpose:** Ingest log files and evaluate them against regex-based detection
rules. Supports simple matches and thresholded rules (e.g., fire after N
failures from the same IP within a time window).

**CLI:**
```bash
outcats detect run --log /var/log/auth.log [--rules custom.json] [--format ...]
outcats detect rules [--rules custom.json]
```

**Detection engine architecture:**

```
Log lines → Timestamp parser → Rule regex matching → Actor grouping
         → Rolling-window threshold → Alert generation → Report
```

**Key classes:**

| Name | Description |
|------|-------------|
| `Rule` | id, name, severity, pattern (regex), group_by, threshold, window_seconds, mitre, guidance |
| `Alert` | rule_id, name, severity, actor, count, first_line, mitre, guidance |
| `DetectionEngine` | Holds rules; `run(lines)` → list of Alerts |

**Thresholded detection (e.g., brute-force):**
```python
# Uses a deque per (rule_id, actor) key
# Timestamps outside window_seconds are evicted
# Alert fires when len(deque) >= threshold
```

**Timestamp parsing supports:**
- Syslog format: `Jul 25 22:48:01`
- Access log format: `[25/Jul/2026:22:48:01 +0000]`
- Falls back to line number when no timestamp found

**All 10 bundled detection rules:**

| Rule ID | Name | Severity | Threshold | MITRE |
|---------|------|----------|-----------|-------|
| OC-DET-SSH-BRUTE | SSH brute-force | high | 5 in 60s | T1110 |
| OC-DET-SSH-ACCEPT-AFTER-FAIL | Successful SSH login | info | 1 | T1078 |
| OC-DET-SUDO-FAIL | Repeated sudo failures | medium | 3 in 120s | T1548.003 |
| OC-DET-WEB-PATH-TRAVERSAL | Path traversal | high | 1 | T1083 |
| OC-DET-WEB-SQLI-PROBE | SQL injection probe | high | 1 | T1190 |
| OC-DET-WEB-CMDI | OS command injection | critical | 1 | T1059 |
| OC-DET-WEB-LFI | Local file inclusion | high | 1 | T1083 |
| OC-DET-WEB-LOG4SHELL | JNDI injection (Log4Shell) | critical | 1 | T1190 |
| OC-DET-SCANNER-UA | Known scanner user-agent | medium | 1 | T1595 |
| OC-DET-WIN-LOGON-FAIL | Windows Event 4625 | high | 5 in 300s | T1110 |

---


### 9. CTF/Lab Companion

**File:** `outcats/lab/companion.py`

**Purpose:** Structured methodology checklists, engagement notebooks, and
progress tracking for practicing on intentionally-vulnerable labs.

**CLI:**
```bash
outcats lab templates                           # list available templates
outcats lab start "HTB-Blue" --template smb     # start an engagement
outcats lab show "HTB-Blue"                     # view checklist + notes
outcats lab note "HTB-Blue" --phase Enumeration "Found SMBv2 on port 445"
outcats lab done "HTB-Blue" "Identify OS build and SMB dialect/version."
outcats lab list                                # list all engagements
```

**Templates available:**

| Template | Title | Phases |
|----------|-------|--------|
| generic | Generic box methodology | Enumeration → Research → Foothold → Post & Reporting |
| web | Web application box | Mapping → Analysis → Defensive lesson |
| smb | SMB / Windows services | Enumeration → Research → Defensive lesson |
| redteam | Red-team ATT&CK study plan | Recon → Initial Access → Execution & Persistence → Priv Esc → Lateral Movement → Report |

**Engagement persistence:**
- Stored as JSON in `~/.outcats/labs/<name>.json`
- Tracks: name, template, platform, created_at, completed_steps[], notes[]

**Key class (`Engagement`):**
```python
@dataclass
class Engagement:
    name: str
    template: str
    platform: str = "practice-lab"
    completed_steps: list[str]
    notes: list[dict]  # {at, phase, text}

    def checklist() -> list[tuple[str, str, bool]]  # (phase, step, done)
    def progress() -> tuple[int, int]               # (done, total)
    def add_note(phase, text)
    def complete_step(step)
    def save() / load(name)
```

---

### 10. Web GUI Dashboard

**File:** `outcats/gui/server.py`

**Purpose:** Zero-dependency web dashboard served from Python's stdlib
`http.server`. Works in ANY browser — desktop (Windows/Linux/macOS) or
phone/tablet. Exposes hardening, scan, and detection modules.

**CLI:**
```bash
outcats gui [--host 127.0.0.1] [--port 8787] [--token SECRET]
```

**Architecture:**
- `ThreadingHTTPServer` with custom `Handler(BaseHTTPRequestHandler)`
- Single-page app: HTML + CSS + vanilla JS (no framework)
- Dark theme, responsive, mobile-friendly

**Endpoints:**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/` | Yes | Dashboard HTML (tabs: harden, scan, detect) |
| GET | `/healthz` | **No** | Health check for platform probes |
| GET | `/api/status` | Yes | System info + scope status as JSON |
| POST | `/api/harden` | Yes | Run hardening audit, return HTML fragment |
| POST | `/api/scan` | Yes | Run authorized scan, return HTML fragment |
| POST | `/api/detect` | Yes | Run detection on pasted logs, return HTML fragment |

**Token authentication:**
- When `OUTCATS_TOKEN` env var or `--token` is set: every request must carry it
- Via URL: `/?token=SECRET`
- Via header: `X-Outcats-Token: SECRET`
- Uses `hmac.compare_digest()` for constant-time comparison (timing-attack safe)
- `/healthz` is always unauthenticated (returns no sensitive data)

**Dashboard JavaScript (vanilla, no dependencies):**
```javascript
const TOKEN = "{{TOKEN}}";  // injected server-side
async function post(url, data, target) {
    const headers = {'Content-Type': 'application/x-www-form-urlencoded'};
    if (TOKEN) { headers['X-Outcats-Token'] = TOKEN; }
    const res = await fetch(url, {method: 'POST', headers, body: new URLSearchParams(data)});
    document.getElementById(target).innerHTML = await res.text();
}
```

---

### 11. Interactive TUI

**File:** `outcats/interactive.py`

**Purpose:** Menu-driven interactive shell. All 12 modules accessible via
numbered choices — no CLI flags to remember.

**CLI:**
```bash
outcats interactive
```

**Menu options:**
1. Authorize (set scope)
2. Hardening audit (local)
3. Vulnerability scan (authorized target)
4. Network mapper (multi-host)
5. SSL/TLS certificate check
6. Password policy audit
7. OSINT passive recon (own domain)
8. Blue-team detection (paste/file)
9. CTF/Lab methodology
10. Launch web GUI
0. Exit

**After every report:** offers to save as JSON, CSV, or HTML (PDF).

---

### 12. Guided Intake

**File:** `outcats/guide.py`

**Purpose:** Tell it what you're trying to do (or nothing at all) and it
suggests the exact commands to run next. Never executes anything itself.

**CLI:**
```bash
outcats guide
```

**Flow:**
1. Asks: "What are you trying to do?" (harden/scan/learn/detect/not sure)
2. Auto-detects local system info
3. Based on goal, suggests specific `outcats` commands with correct flags
4. If goal is "learn": asks platform + name + template → suggests lab start
5. Prints plan but executes nothing

---


## Report Engine & Export Formats

**Files:** `outcats/common/report.py`, `outcats/common/export.py`

### Data Model

```python
class Severity(str, Enum):
    INFO = "info"       # rank 0
    LOW = "low"         # rank 1
    MEDIUM = "medium"   # rank 2
    HIGH = "high"       # rank 3
    CRITICAL = "critical"  # rank 4

class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"

@dataclass
class Finding:
    id: str              # e.g. "OC-FS-001", "CVE-2024-6387"
    title: str           # human-readable title
    severity: Severity
    status: Status
    detail: str = ""     # additional context
    remediation: str = ""  # fix guidance (shown only on FAIL/WARN)
    references: list[str] = []  # CIS IDs, URLs

@dataclass
class Report:
    module: str          # e.g. "harden", "scan", "detect"
    target: str          # what was assessed
    findings: list[Finding]
    generated_at: float  # unix timestamp
```

### Renderers

| Format | Method | Description |
|--------|--------|-------------|
| Text | `report.to_text(color=True)` | Terminal-friendly with ANSI colors, sorted by severity |
| JSON | `report.to_json()` | Machine-readable, includes summary counts |
| HTML | `report.to_html()` | Self-contained dark-theme report (responsive) |
| HTML fragment | `report.to_html_fragment()` | Embeddable (used by GUI) |
| CSV | `export.to_csv(report)` | RFC-4180, all fields, importable into SIEM/Excel |
| PDF | `export.to_pdf_html(report)` | Print-optimized HTML with @media print CSS |

### PDF Generation (zero dependencies)

Instead of requiring wkhtmltopdf/weasyprint, we generate print-optimized HTML:
- Adds `@media print` CSS that converts dark theme → print-friendly
- `@page { margin: 1.5cm; size: A4 landscape; }`
- User opens in browser → File → Print → Save as PDF

---

## Deployment Guide

### Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENV HOST=0.0.0.0 PORT=8787
EXPOSE 8787
CMD ["outcats", "gui"]
```

### Render.com (free)
- `render.yaml` included — auto-configures everything
- Uses Blueprint mode: connects repo, detects config, deploys
- Auto-generates `OUTCATS_TOKEN` as a secret

### Railway / Koyeb / Cloud Run
- All detect Dockerfile automatically
- Set `OUTCATS_TOKEN` env var manually

### Procfile (Heroku-compatible)
```
web: outcats gui
```

### Local testing
```bash
outcats gui                                    # localhost only
outcats gui --host 0.0.0.0 --token mytoken    # LAN access
```

---


## File-by-File Code Reference

### `outcats/__init__.py`
- Defines `__version__ = "0.1.0"`
- Module docstring listing all available modules

### `outcats/cli.py`
- `build_parser()` — constructs argparse with 12 subcommands
- `_emit(report, fmt, out)` — routes report to correct renderer + handles file output
- `_parse_ports(spec)` — parses "common", "all", "22,80,8000-8100" into port lists
- `cmd_authorize()` — calls `interactive_authorize()`
- `cmd_guide()` — calls `run_guide()`
- `cmd_gui()` — calls `serve(host, port, token)`
- `cmd_harden()` — calls `run_audit(level, plat)`
- `cmd_scan()` — calls `run_scan(target, scope, ports, timeout)`
- `cmd_lab()` — dispatches to templates/start/show/note/done/list
- `cmd_detect()` — dispatches to run/rules
- `cmd_netmap()` — calls `map_network(hosts, scope, ports, timeout)`
- `cmd_tls()` — calls `check_tls(host, port, timeout)` for each target
- `cmd_passwords()` — calls `audit_password_policy()`
- `cmd_osint()` — calls `recon_domain(domain, scope)`
- `cmd_interactive()` — calls `run_interactive()`
- `main(argv)` — entry point, dispatches to handler, catches errors

### `outcats/authorization.py`
- `CONFIG_DIR` = `~/.outcats/`
- `SCOPE_FILE` = `~/.outcats/scope.json`
- `LOOPBACK` = {"127.0.0.1", "::1", "localhost"}
- `Scope` dataclass with load/save/to_json
- `_normalize(host)` — strip + lowercase
- `is_in_scope(host, scope)` — loopback check → exact match → CIDR match
- `enforce_target(host, scope)` — raises AuthorizationError if not in scope
- `require_scope()` — load or raise
- `interactive_authorize()` — stdin-driven attestation flow

### `outcats/common/system.py`
- `SystemInfo` dataclass: hostname, os_system, os_release, os_version, architecture, python_version, kernel, distro
- `_read_os_release()` — parses /etc/os-release
- `detect_distro()` — returns PRETTY_NAME or platform.platform()
- `collect()` → SystemInfo (reads uname + os-release)
- `which(binary)` — shutil.which wrapper

### `outcats/common/report.py`
- `Severity` enum (info/low/medium/high/critical) with `.rank` property
- `Status` enum (pass/fail/warn/info)
- `Finding` dataclass with `as_dict()`
- `Report` dataclass with:
  - `add(finding)`, `counts_by_severity()`, `counts_by_status()`
  - `to_text(color)`, `to_json()`, `to_html()`, `to_html_fragment()`
  - `_rows_html()` — internal table row generator

### `outcats/common/export.py`
- `to_csv(report)` → RFC-4180 CSV string
- `to_pdf_html(report)` → print-optimized HTML with @media print CSS
- `save_csv(report, path)` → writes file
- `save_pdf_html(report, path)` → writes file

### `outcats/harden/checks.py`
- `LINUX, MACOS, WINDOWS` — platform constants
- `ALL_PLATFORMS` — frozenset of all three
- `current_platform()` — detects via platform.system()
- `CheckMeta` dataclass: id, title, level, severity, func, platforms
- `_REGISTRY` — global list of registered checks
- `@check(cid, title, *, level, severity, platforms)` — decorator
- `_finding(...)` — helper to construct Finding
- `_read(path)` — safe file read
- `_sshd_option(name)` — parse sshd_config for a directive
- `_sysctl(key)` — read /proc/sys/... value
- `_run(cmd, timeout)` — subprocess.run wrapper for macOS/Windows checks
- `_powershell(script)` — Windows PowerShell runner
- 18 check functions (see table in Module Reference)
- `all_checks(level, plat)` — filter registry by level + platform

### `outcats/harden/audit.py`
- `run_audit(level, plat)` → Report

### `outcats/harden/passwords.py`
- `audit_password_policy()` → Report
- `_linux_checks(report)` — /etc/login.defs + /etc/shadow + /etc/passwd
- `_macos_checks(report)` — pwpolicy command
- `_windows_checks(report)` — Get-ADDefaultDomainPasswordPolicy

### `outcats/scan/fingerprint.py`
- `COMMON_PORTS` — list of 23 common TCP ports
- `_VERSION_RE` — generic version regex
- `_PRODUCT_VERSION_RES` — dict of service-specific version regexes
- `PortResult` dataclass: port, open, service, banner, version, cves
- `_grab_banner(host, port, timeout)` — passive banner read
- `_service_from_banner(banner)` → (service_name, version)
- `_probe_port(host, port, timeout)` → PortResult
- `scan_host(host, scope, ports, timeout, workers)` → list[PortResult]

### `outcats/scan/cve.py`
- `DATA_FILE` — path to bundled cve_sample.json
- `CVEMatch` dataclass: cve, severity, summary, fixed_in, refs
- `_dataset()` — cached JSON load
- `port_hint(port)` — lookup common port→service mapping
- `_parse_version(v)` → comparable tuple
- `_in_range(version, lo, hi)` — inclusive-lower, exclusive-upper
- `correlate(service, version)` → list[CVEMatch]
- `known_services()` → sorted list of services in dataset

### `outcats/scan/scanner.py`
- `run_scan(host, scope, ports, timeout)` → Report

### `outcats/netmap/mapper.py`
- `HostEntry` dataclass: host, open_ports, services, banners
- `NetworkMap` dataclass: hosts, all_ports
- `NetworkMap.to_table(color)` → ASCII matrix string
- `_probe(host, port, timeout)` → (host, port, is_open, service)
- `map_network(hosts, scope, ports, timeout, workers)` → NetworkMap
- `netmap_to_report(nmap)` → Report

### `outcats/tlscheck/checker.py`
- `CertInfo` dataclass: subject, issuer, not_before, not_after, serial, san, version, fingerprint_sha256
- `TLSResult` dataclass: host, port, cert, protocol, cipher, cipher_bits, errors
- `_WEAK_CIPHERS`, `_WEAK_PROTOCOLS` — sets of known-bad values
- `_parse_cert(der, info)` → CertInfo
- `check_tls(host, port, timeout)` → TLSResult
- `tls_to_report(results)` → Report

### `outcats/osint/recon.py`
- `DomainInfo` dataclass: domain, dns_records, http_headers, security_headers, whois_expiry, subdomains
- `_SECURITY_HEADERS` — list of 7 headers to check
- `_dns_lookup(domain, rtype)` — socket + dig fallback
- `_check_http_headers(domain)` — urllib HEAD request
- `_whois_expiry(domain)` — whois command parsing
- `recon_domain(domain, scope)` → DomainInfo
- `recon_to_report(info)` → Report

### `outcats/detect/engine.py`
- `Rule` dataclass with compiled regex
- `Alert` dataclass
- `load_rules(path)` — cached JSON→Rule list
- `_parse_ts(line, fallback)` — syslog + access log timestamp extraction
- `DetectionEngine.run(lines)` → list[Alert] (rolling window + threshold)

### `outcats/detect/runner.py`
- `_iter_lines(log_path)` — generator over file lines
- `run_detection(log_path, rules_path)` → Report

### `outcats/lab/companion.py`
- `list_templates()` → dict[name, title]
- `get_template(name)` → template dict
- `Note` dataclass
- `Engagement` dataclass with save/load/checklist/progress/add_note/complete_step
- `list_engagements()` → list of saved engagement names

### `outcats/gui/server.py`
- `_TOKEN` — module-level token (set by serve())
- `_page()` — renders dashboard HTML with system info injected
- `_fragment(report)` — HTML fragment bytes
- `_error_fragment(msg)` — error display bytes
- `Handler` class — GET/POST routing + token enforcement
- `_authorized()` — constant-time token check via X-Outcats-Token or ?token=
- `_path_only()` — strips query string from path
- `serve(host, port, token)` — starts ThreadingHTTPServer

### `outcats/guide.py`
- `_ask(prompt, default)` — input helper
- `run_guide()` — interactive advisor flow

### `outcats/interactive.py`
- `_header()` — ASCII art banner + system info
- `_menu()` — numbered menu display
- `_input(prompt, default)` — input helper
- `_emit_report(report)` — display + offer save
- `run_interactive()` — main loop (10 menu items)

---


## Data Files Reference

### `outcats/data/cve_sample.json`

Offline CVE correlation dataset. Structure:
```json
{
  "services": {
    "openssh": [
      {
        "cve": "CVE-2024-6387",
        "severity": "high",
        "affected": {"min": "8.5p1", "max": "9.8"},
        "summary": "regreSSHion: signal-handler race condition...",
        "fixed_in": "9.8p1",
        "refs": ["https://..."]
      }
    ]
  },
  "port_service_hints": {
    "22": "ssh", "80": "http", ...
  }
}
```

**Covered services:** openssh, openssl, nginx, apache, vsftpd

### `outcats/data/detection_rules.json`

Blue-team detection rules. Structure:
```json
{
  "rules": [
    {
      "id": "OC-DET-SSH-BRUTE",
      "name": "SSH brute-force attempt",
      "severity": "high",
      "pattern": "regex with named groups (?P<ip>...)",
      "group_by": "ip",
      "threshold": 5,
      "window_seconds": 60,
      "mitre": "T1110",
      "guidance": "Remediation advice..."
    }
  ]
}
```

### `outcats/data/methodologies.json`

CTF/lab study plan templates. Structure:
```json
{
  "templates": {
    "generic": {
      "title": "Generic box methodology",
      "phases": [
        {
          "name": "Enumeration",
          "steps": ["step 1", "step 2", ...]
        }
      ]
    }
  }
}
```

---

## Security Model

### What outcats DOES:
- Read-only system inspection (file permissions, sysctl, configs)
- TCP connect-scan (full handshake only, no SYN/stealth)
- Passive banner reading (no crafted payloads)
- Offline CVE correlation (local dataset lookup)
- Log file analysis (regex matching)
- DNS/HTTP lookups on owned domains
- TLS connection + certificate inspection

### What outcats does NOT do:
- Exploitation of any vulnerability
- Credential attacks (brute-force, spraying, stuffing)
- Social engineering
- Denial-of-service
- Active payload injection
- Any modification of target state
- Unauthorized access attempts
- Sending crafted/malformed packets

### Authorization enforcement:
1. `outcats authorize` must be run first (creates scope.json)
2. Every network-touching command calls `enforce_target(host, scope)`
3. Out-of-scope targets are REFUSED with a clear error message
4. Loopback (127.0.0.1/localhost/::1) is always in scope
5. CIDR ranges are supported for subnet-level authorization
6. Lab mode flag for intentionally-vulnerable targets

### Token protection (deployed GUI):
- `OUTCATS_TOKEN` env var or `--token` flag
- Constant-time comparison via `hmac.compare_digest()`
- Applied to ALL endpoints except `/healthz`
- Token can be passed via header or URL parameter

---

## Test Suite

**File:** `tests/test_core.py` — 21 tests covering:

| Test | What it validates |
|------|------------------|
| `test_loopback_always_in_scope` | 127.0.0.1 and localhost pass scope check |
| `test_cidr_membership` | 10.0.0.55 in 10.0.0.0/24 passes; 10.0.1.55 fails |
| `test_exact_host_match` | Hostname in allowed_hosts passes |
| `test_out_of_scope_public_ip` | 8.8.8.8 is refused |
| `test_version_parse_handles_patch_letters` | "9.3p2" → (9,3,0,2) |
| `test_openssh_vulnerable_and_fixed` | 9.6p1 → CVE match; 9.9p1 → no match |
| `test_unknown_version_flags_for_verification` | None version → "[verify]" prefix |
| `test_ssh_bruteforce_threshold` | 5+ failures from same IP → alert |
| `test_below_threshold_does_not_fire` | 2 failures → no alert |
| `test_sqli_probe_detected` | union select in URL → alert |
| `test_log4shell_probe_detected` | ${jndi:ldap://...} → critical alert |
| `test_scanner_user_agent_detected` | sqlmap UA → alert |
| `test_platform_routing_filters_checks` | Linux ≠ Windows checks; no cross-contamination |
| `test_report_counts_and_json` | Counts correct; JSON output valid |
| `test_password_policy_audit` | Returns findings on Linux |
| `test_csv_export` | CSV contains correct fields |
| `test_pdf_export_has_print_css` | PDF HTML has @media print |
| `test_netmap_import_and_table` | NetworkMap renders ASCII table |
| `test_tls_checker_connection_refused` | Connection error → errors list |
| `test_osint_recon_import` | DomainInfo → Report conversion works |
| `test_interactive_import` | Module imports without error |

Run tests:
```bash
python -m pytest -q
# 21 passed in 0.05s
```

---

*Documentation generated for outcats v0.1.0 — RishiPlaysCodes*
