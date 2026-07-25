"""Password policy and credential hygiene auditor (read-only).

Checks local password policies, finds accounts with no expiry, empty password
hashes (login without password), duplicate UIDs, and accounts that should be
locked but aren't. Purely read-only inspection of /etc/shadow, /etc/passwd,
/etc/login.defs, and (on macOS) dscl output.

All findings are advisory - the tool never changes passwords or locks accounts.
"""

from __future__ import annotations

import platform
from pathlib import Path

from ..common.report import Finding, Report, Severity, Status


def _read(path: str) -> str | None:
    p = Path(path)
    try:
        return p.read_text() if p.exists() else None
    except OSError:
        return None


def audit_password_policy() -> Report:
    """Run password/credential hygiene checks on the local system."""
    report = Report(module="passwords", target="local credential policy")

    sysname = platform.system().lower()
    if sysname.startswith("win"):
        _windows_checks(report)
    elif sysname.startswith("darwin"):
        _macos_checks(report)
    else:
        _linux_checks(report)

    return report


def _linux_checks(report: Report) -> None:
    # --- /etc/login.defs policy ---
    logindefs = _read("/etc/login.defs")
    if logindefs:
        defs: dict[str, str] = {}
        for line in logindefs.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                defs[parts[0]] = parts[1]

        max_days = int(defs.get("PASS_MAX_DAYS", "99999"))
        min_days = int(defs.get("PASS_MIN_DAYS", "0"))
        min_len = int(defs.get("PASS_MIN_LEN", "0"))
        warn_age = int(defs.get("PASS_WARN_AGE", "7"))

        report.add(Finding(
            id="OC-PW-MAXAGE",
            title="Password max age policy",
            severity=Severity.MEDIUM if max_days > 365 else Severity.LOW,
            status=Status.FAIL if max_days > 365 else Status.PASS,
            detail=f"PASS_MAX_DAYS={max_days}",
            remediation="Set PASS_MAX_DAYS to 365 or less in /etc/login.defs",
        ))
        report.add(Finding(
            id="OC-PW-MINAGE",
            title="Password min age prevents rapid changes",
            severity=Severity.LOW,
            status=Status.PASS if min_days >= 1 else Status.WARN,
            detail=f"PASS_MIN_DAYS={min_days}",
            remediation="Set PASS_MIN_DAYS >= 1 to prevent immediate reuse",
        ))
        report.add(Finding(
            id="OC-PW-MINLEN",
            title="Minimum password length is configured",
            severity=Severity.MEDIUM if min_len < 8 else Severity.LOW,
            status=Status.FAIL if min_len < 8 else Status.PASS,
            detail=f"PASS_MIN_LEN={min_len}",
            remediation="Set PASS_MIN_LEN >= 12 (or use pam_pwquality)",
        ))
    else:
        report.add(Finding(
            id="OC-PW-DEFS",
            title="/etc/login.defs not found",
            severity=Severity.INFO,
            status=Status.INFO,
            detail="Cannot assess password policy",
        ))

    # --- /etc/shadow: empty passwords, no-expiry accounts, locked status ---
    shadow = _read("/etc/shadow")
    if shadow:
        empty_pw: list[str] = []
        no_expiry: list[str] = []
        system_accts_unlocked: list[str] = []

        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) < 8:
                continue
            user, pw_hash = fields[0], fields[1]
            max_age = fields[4] if len(fields) > 4 else ""

            # Empty or no-password hash (! and * are locked)
            if pw_hash == "" or pw_hash == "::":
                empty_pw.append(user)
            # No max age (empty or 99999 means effectively no expiry)
            if max_age in ("", "99999") and pw_hash not in ("!", "*", "!!", "!!*"):
                no_expiry.append(user)
            # System accounts (UID typically < 1000) that aren't locked
            # We can't easily get UID from shadow alone, so flag known system names
            system_names = {"daemon", "bin", "sys", "sync", "games", "man",
                           "lp", "mail", "news", "uucp", "proxy", "www-data",
                           "backup", "list", "irc", "gnats", "nobody"}
            if user in system_names and pw_hash not in ("!", "*", "!!", "!!*"):
                system_accts_unlocked.append(user)

        if empty_pw:
            report.add(Finding(
                id="OC-PW-EMPTY",
                title="Accounts with EMPTY password hash",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                detail=f"Users: {', '.join(empty_pw[:10])}",
                remediation="Set a password or lock these accounts: passwd -l <user>",
            ))
        else:
            report.add(Finding(
                id="OC-PW-EMPTY",
                title="No accounts with empty password",
                severity=Severity.INFO,
                status=Status.PASS,
            ))

        if no_expiry:
            report.add(Finding(
                id="OC-PW-NOEXPIRY",
                title=f"{len(no_expiry)} account(s) with no password expiry",
                severity=Severity.LOW,
                status=Status.WARN,
                detail=f"Users: {', '.join(no_expiry[:10])}",
                remediation="Set password aging: chage -M 365 <user>",
            ))

        if system_accts_unlocked:
            report.add(Finding(
                id="OC-PW-SYSUNLOCKED",
                title="System accounts that are not locked",
                severity=Severity.MEDIUM,
                status=Status.WARN,
                detail=f"Users: {', '.join(system_accts_unlocked[:10])}",
                remediation="Lock system accounts: passwd -l <user>",
            ))
    else:
        report.add(Finding(
            id="OC-PW-SHADOW",
            title="/etc/shadow not readable (not root?)",
            severity=Severity.INFO,
            status=Status.INFO,
            detail="Run as root to check for empty passwords and expiry.",
        ))

    # --- /etc/passwd: duplicate UIDs ---
    passwd = _read("/etc/passwd")
    if passwd:
        uids: dict[str, list[str]] = {}
        for line in passwd.splitlines():
            fields = line.split(":")
            if len(fields) >= 3:
                uid = fields[2]
                uids.setdefault(uid, []).append(fields[0])
        dupes = {uid: users for uid, users in uids.items() if len(users) > 1}
        if dupes:
            detail = "; ".join(f"UID {uid}: {', '.join(users)}" for uid, users in dupes.items())
            report.add(Finding(
                id="OC-PW-DUPUID",
                title="Duplicate UIDs found",
                severity=Severity.HIGH,
                status=Status.FAIL,
                detail=detail[:200],
                remediation="Each account should have a unique UID.",
                references=["CIS 6.2.16"],
            ))
        else:
            report.add(Finding(
                id="OC-PW-DUPUID",
                title="No duplicate UIDs",
                severity=Severity.INFO,
                status=Status.PASS,
            ))


def _macos_checks(report: Report) -> None:
    import subprocess
    try:
        out = subprocess.run(
            ["pwpolicy", "getaccountpolicies"],
            capture_output=True, text=True, timeout=5
        )
        has_policy = "policyParameters" in (out.stdout or "")
        report.add(Finding(
            id="OC-PW-MACPOLICY",
            title="macOS password policy is configured",
            severity=Severity.MEDIUM if not has_policy else Severity.INFO,
            status=Status.PASS if has_policy else Status.WARN,
            detail="pwpolicy " + ("has" if has_policy else "does not have") + " account policies",
            remediation="Configure password policy via profiles or pwpolicy command",
        ))
    except (OSError, subprocess.SubprocessError):
        report.add(Finding(
            id="OC-PW-MACPOLICY",
            title="Cannot check macOS password policy",
            severity=Severity.INFO, status=Status.INFO,
        ))


def _windows_checks(report: Report) -> None:
    import subprocess
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-ADDefaultDomainPasswordPolicy | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode == 0 and out.stdout.strip():
            import json
            policy = json.loads(out.stdout)
            report.add(Finding(
                id="OC-PW-WINPOLICY",
                title="Windows domain password policy",
                severity=Severity.INFO, status=Status.PASS,
                detail=f"MinLength={policy.get('MinPasswordLength')}, "
                       f"MaxAge={policy.get('MaxPasswordAge')}, "
                       f"History={policy.get('PasswordHistoryCount')}",
            ))
        else:
            report.add(Finding(
                id="OC-PW-WINPOLICY",
                title="Cannot retrieve Windows domain password policy",
                severity=Severity.INFO, status=Status.INFO,
                detail="Not a domain member or RSAT not installed.",
            ))
    except (OSError, subprocess.SubprocessError):
        report.add(Finding(
            id="OC-PW-WINPOLICY",
            title="Cannot check Windows password policy",
            severity=Severity.INFO, status=Status.INFO,
        ))
