# outcats - Setup & All Commands Guide

## Where does the project exist on your computer?

After you clone, it will be at:
```
C:\Users\<your-username>\outcats\
```
Or wherever you run the `git clone` command from.

---

## TERMINAL 1: Setup (one-time, your computer)

Open **Command Prompt** or **PowerShell** or **Git Bash**:

```bash
# Step 1: Clone the repo from GitHub
git clone https://github.com/RishiPlaysCodes/outcats.git

# Step 2: Go into the project folder
cd outcats

# Step 3: Install the tool (makes 'outcats' command available globally)
pip install -e .

# Step 4: Verify it works
outcats --version
# Should show: outcats 0.1.0
```

If `pip` doesn't work, try `pip3` or `python -m pip install -e .`

---

## TERMINAL 2: First-time authorization (required before scanning)

```bash
# Set up your authorized scope (interactive prompts)
outcats authorize
```

It will ask:
1. Your name → type your name
2. Authorization reference → type "I own these hosts"
3. Type "I AGREE"
4. Lab mode? → y or n
5. In-scope hosts → e.g. `127.0.0.1, 192.168.1.0/24, mydomain.com`

---

## ALL COMMANDS (copy-paste ready)

### Hardening Audit (check your own machine's security)

```bash
# Basic audit (text output in terminal)
outcats harden

# Level 1 only (baseline checks)
outcats harden --level 1

# Save as HTML report
outcats harden --format html --out hardening-report.html

# Save as JSON (for automation/SIEM)
outcats harden --format json --out hardening-report.json

# Save as CSV (for Excel/spreadsheet)
outcats harden --format csv --out hardening-report.csv

# Save as printable PDF (open in browser → Print → Save as PDF)
outcats harden --format pdf --out hardening-report.pdf.html

# Preview macOS checks (even from Windows/Linux)
outcats harden --platform macos

# Preview Windows checks
outcats harden --platform windows

# Show ALL checks for all platforms
outcats harden --platform all
```

### Password Policy Audit

```bash
# Check credential hygiene (empty passwords, expiry, duplicates)
outcats passwords

# Save report
outcats passwords --format html --out passwords-report.html
```

### Vulnerability Scanner (authorized targets only)

```bash
# Scan localhost (always allowed)
outcats scan --target 127.0.0.1

# Scan with specific ports
outcats scan --target 127.0.0.1 --ports 22,80,443,8080

# Scan port range
outcats scan --target 192.168.1.10 --ports 1-1024

# Scan all common ports
outcats scan --target 192.168.1.10 --ports common

# Custom timeout (seconds)
outcats scan --target 10.0.0.5 --timeout 2.0

# Save results
outcats scan --target 127.0.0.1 --format html --out scan-report.html
```

### Network Mapper (multiple hosts at once)

```bash
# Map services on multiple hosts
outcats netmap --targets 192.168.1.1,192.168.1.2,192.168.1.3

# Specific ports
outcats netmap --targets 10.0.0.1,10.0.0.2 --ports 22,80,443,3306,5432

# Save the network map
outcats netmap --targets 192.168.1.1,192.168.1.2 --format html --out network-map.html
```

### SSL/TLS Certificate Checker

```bash
# Check a single HTTPS endpoint
outcats tls --targets mydomain.com

# Check multiple endpoints
outcats tls --targets mydomain.com,api.mydomain.com,mail.mydomain.com

# Custom port (not 443)
outcats tls --targets myserver.com --port 8443

# Save report
outcats tls --targets mydomain.com --format html --out tls-report.html
```

### OSINT Passive Recon (your own domains)

```bash
# DNS records + security headers + subdomains for a domain you own
outcats osint --domain mydomain.com

# Save results
outcats osint --domain mydomain.com --format html --out osint-report.html
```

### Blue-Team Detection (analyze logs)

```bash
# Analyze an auth log file
outcats detect run --log /var/log/auth.log

# On Windows (example path)
outcats detect run --log C:\logs\security.log

# Use the sample logs included in the project
outcats detect run --log examples/sample_auth.log
outcats detect run --log examples/sample_access.log

# Save alert report
outcats detect run --log /var/log/auth.log --format html --out alerts.html

# List all detection rules
outcats detect rules
```

### CTF / Lab Training Companion

```bash
# List methodology templates
outcats lab templates

# Start a new engagement
outcats lab start "My-First-Box" --template generic
outcats lab start "HTB-Blue" --template smb
outcats lab start "Web-Challenge" --template web
outcats lab start "ATT&CK-Study" --template redteam

# View checklist and progress
outcats lab show "HTB-Blue"

# Add a note
outcats lab note "HTB-Blue" --phase Enumeration "Port 445 open, SMBv2 detected"

# Mark a step as done
outcats lab done "HTB-Blue" "Identify OS build and SMB dialect/version."

# List all engagements
outcats lab list
```

### Web GUI Dashboard (opens in browser)

```bash
# Start dashboard on localhost (open http://127.0.0.1:8787 in browser)
outcats gui

# With access token (recommended for non-localhost)
outcats gui --token mysecretpassword
# Then open: http://127.0.0.1:8787/?token=mysecretpassword

# Make accessible from phone/other devices on same WiFi
outcats gui --host 0.0.0.0 --port 8080 --token mytoken
# Then open from phone: http://<your-pc-ip>:8080/?token=mytoken

# Custom port
outcats gui --port 9000
```

### Interactive Mode (menu-driven, no flags needed)

```bash
# Launch interactive shell (easiest way to use everything)
outcats interactive
```

### Guided Intake (don't know where to start?)

```bash
# It asks what you know and suggests what to do
outcats guide
```

---

## RUNNING THE WEB DASHBOARD (Frontend + Backend)

outcats has a built-in web server — NO separate frontend/backend setup needed.

```bash
# TERMINAL: Start the server
cd outcats
outcats gui --port 8787

# OUTPUT:
# outcats GUI running at http://127.0.0.1:8787/  (Ctrl+C to stop)
# Open it in any browser - desktop or phone.
```

Then open your browser and go to: `http://127.0.0.1:8787/`

**That's it.** The "frontend" (HTML/CSS/JS) and "backend" (Python) are in ONE
command. No npm, no React, no separate terminal needed.

To stop: press `Ctrl+C` in the terminal.

---

## PROJECT FOLDER STRUCTURE (on your computer)

After `git clone`, this is what exists on your machine:

```
C:\Users\<you>\outcats\           ← or wherever you cloned it
│
├── outcats/                      ← main source code
│   ├── __init__.py               ← version info
│   ├── cli.py                    ← all CLI commands
│   ├── authorization.py          ← scope/auth system
│   ├── guide.py                  ← guided intake
│   ├── interactive.py            ← TUI menu shell
│   ├── common/
│   │   ├── system.py             ← OS fingerprint
│   │   ├── report.py             ← report engine (text/json/html)
│   │   └── export.py             ← CSV + PDF export
│   ├── harden/
│   │   ├── checks.py             ← 18 CIS/STIG checks
│   │   ├── audit.py              ← audit runner
│   │   └── passwords.py          ← credential hygiene
│   ├── scan/
│   │   ├── fingerprint.py        ← TCP scanner + banner grab
│   │   ├── cve.py                ← CVE correlation
│   │   └── scanner.py            ← orchestrator
│   ├── netmap/
│   │   └── mapper.py             ← multi-host network mapper
│   ├── tlscheck/
│   │   └── checker.py            ← SSL/TLS auditor
│   ├── osint/
│   │   └── recon.py              ← passive recon
│   ├── detect/
│   │   ├── engine.py             ← detection rule engine
│   │   └── runner.py             ← log file processor
│   ├── lab/
│   │   └── companion.py          ← CTF methodology tracker
│   ├── gui/
│   │   └── server.py             ← web dashboard
│   └── data/
│       ├── cve_sample.json       ← offline CVE database
│       ├── detection_rules.json  ← 10 MITRE-mapped rules
│       └── methodologies.json    ← study templates
│
├── tests/
│   └── test_core.py              ← 21 unit tests
├── examples/
│   ├── sample_auth.log           ← test log (SSH brute force)
│   └── sample_access.log         ← test log (web attacks)
├── DOCUMENTATION.md              ← full technical docs
├── README.md                     ← project overview
├── Dockerfile                    ← for cloud deployment
├── Procfile                      ← Heroku/Railway
├── render.yaml                   ← Render.com config
├── pyproject.toml                ← Python package config
└── .gitignore
```

---

## QUICK TEST (verify everything works)

```bash
cd outcats

# Run all tests
python -m pytest -q
# Expected: 21 passed

# Quick hardening check
outcats harden

# Quick detection on sample log
outcats detect run --log examples/sample_auth.log

# Start GUI and open browser
outcats gui
```

---

## REQUIREMENTS

- Python 3.10+ (check with: python --version)
- No other packages needed (zero dependencies!)
- Git (to clone)
- Admin/root recommended for full hardening checks

---

## LIVE DEPLOYED VERSION

Your app is live at:
```
https://outcats-dashboard.onrender.com/?token=UEgRB82bITF6kmMGvUuOKuXE9220Anm0Tv9gGRxRvbE=
```

(Change Render to deploy from `main` branch in Settings for latest version)
