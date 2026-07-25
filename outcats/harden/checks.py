"""CIS/STIG-style hardening checks for Linux systems (read-only).

Each check is a small, self-contained function that inspects the local system
and returns a Finding. Checks never modify state; remediation is emitted as
guidance for the operator to review and apply.

Checks are registered via the @check decorator and discovered automatically, so
adding coverage is a matter of writing one function.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..common.report import Finding, Severity, Status


@dataclass
class CheckMeta:
    id: str
    title: str
    level: int  # CIS profile level (1 = baseline, 2 = defense-in-depth)
    severity: Severity
    func: Callable[[], Finding]


_REGISTRY: list[CheckMeta] = []


def check(
    cid: str, title: str, *, level: int = 1, severity: Severity = Severity.MEDIUM
):
    def deco(func: Callable[[], Finding]) -> Callable[[], Finding]:
        _REGISTRY.append(CheckMeta(cid, title, level, severity, func))
        return func

    return deco


def _finding(
    cid: str,
    title: str,
    severity: Severity,
    ok: bool,
    detail: str,
    remediation: str,
    refs: list[str] | None = None,
) -> Finding:
    return Finding(
        id=cid,
        title=title,
        severity=severity,
        status=Status.PASS if ok else Status.FAIL,
        detail=detail,
        remediation="" if ok else remediation,
        references=refs or [],
    )


def _read(path: str) -> str | None:
    p = Path(path)
    try:
        return p.read_text() if p.exists() else None
    except OSError:
        return None


# --------------------------------------------------------------------------
# Filesystem & permissions
# --------------------------------------------------------------------------
@check("OC-FS-001", "World-writable /etc/passwd is not permitted", severity=Severity.HIGH)
def _passwd_perms() -> Finding:
    path = "/etc/passwd"
    p = Path(path)
    if not p.exists():
        return _finding("OC-FS-001", "/etc/passwd permissions", Severity.HIGH,
                        True, f"{path} not present (non-Linux?)", "")
    mode = p.stat().st_mode
    world_writable = bool(mode & stat.S_IWOTH)
    return _finding(
        "OC-FS-001", "World-writable /etc/passwd is not permitted", Severity.HIGH,
        ok=not world_writable,
        detail=f"{path} mode = {oct(stat.S_IMODE(mode))}",
        remediation="chmod 644 /etc/passwd && chown root:root /etc/passwd",
        refs=["CIS 6.1.2"],
    )


@check("OC-FS-002", "/etc/shadow is restricted to root", severity=Severity.CRITICAL)
def _shadow_perms() -> Finding:
    path = "/etc/shadow"
    p = Path(path)
    if not p.exists():
        return _finding("OC-FS-002", "/etc/shadow permissions", Severity.CRITICAL,
                        True, f"{path} not present", "")
    mode = stat.S_IMODE(p.stat().st_mode)
    # Acceptable: 0o600, 0o640, or 0o000 depending on distro.
    ok = (mode & stat.S_IRWXO) == 0 and (mode & stat.S_IWGRP) == 0
    return _finding(
        "OC-FS-002", "/etc/shadow is restricted to root", Severity.CRITICAL,
        ok=ok,
        detail=f"{path} mode = {oct(mode)}",
        remediation="chown root:shadow /etc/shadow && chmod 0640 /etc/shadow",
        refs=["CIS 6.1.3"],
    )


@check("OC-FS-003", "No world-writable files in system PATH dirs", level=2,
       severity=Severity.MEDIUM)
def _path_world_writable() -> Finding:
    path_dirs = [d for d in os.environ.get("PATH", "").split(":") if d]
    offenders: list[str] = []
    for d in path_dirs[:12]:  # bound the walk for speed
        dp = Path(d)
        if not dp.is_dir():
            continue
        try:
            for entry in list(dp.iterdir())[:500]:
                if entry.is_file() and (entry.stat().st_mode & stat.S_IWOTH):
                    offenders.append(str(entry))
        except OSError:
            continue
    return _finding(
        "OC-FS-003", "No world-writable files in system PATH dirs", Severity.MEDIUM,
        ok=not offenders,
        detail=(f"{len(offenders)} world-writable file(s): "
                f"{', '.join(offenders[:5])}") if offenders else "none found",
        remediation="Remove the world-writable bit: chmod o-w <file>",
        refs=["CIS 6.1.10"],
    )


# --------------------------------------------------------------------------
# SSH server configuration
# --------------------------------------------------------------------------
def _sshd_option(name: str) -> str | None:
    text = _read("/etc/ssh/sshd_config")
    if text is None:
        return None
    value = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == name.lower():
            value = parts[1].strip()
    return value


@check("OC-SSH-001", "SSH root login is disabled", severity=Severity.HIGH)
def _ssh_root_login() -> Finding:
    if _read("/etc/ssh/sshd_config") is None:
        return _finding("OC-SSH-001", "SSH PermitRootLogin", Severity.HIGH,
                        True, "sshd_config not present (SSH server not installed)", "")
    val = (_sshd_option("PermitRootLogin") or "prohibit-password").lower()
    ok = val in {"no", "prohibit-password", "without-password"}
    return _finding(
        "OC-SSH-001", "SSH root login is disabled", Severity.HIGH,
        ok=ok, detail=f"PermitRootLogin = {val}",
        remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd",
        refs=["CIS 5.2.10"],
    )


@check("OC-SSH-002", "SSH password authentication is disabled", level=2,
       severity=Severity.MEDIUM)
def _ssh_password_auth() -> Finding:
    if _read("/etc/ssh/sshd_config") is None:
        return _finding("OC-SSH-002", "SSH PasswordAuthentication", Severity.MEDIUM,
                        True, "sshd_config not present", "")
    val = (_sshd_option("PasswordAuthentication") or "yes").lower()
    ok = val == "no"
    return _finding(
        "OC-SSH-002", "SSH password authentication is disabled", Severity.MEDIUM,
        ok=ok, detail=f"PasswordAuthentication = {val}",
        remediation="Prefer key-based auth: set 'PasswordAuthentication no'",
        refs=["CIS 5.2.11"],
    )


@check("OC-SSH-003", "SSH protocol uses modern MACs/ciphers", level=2,
       severity=Severity.LOW)
def _ssh_x11() -> Finding:
    if _read("/etc/ssh/sshd_config") is None:
        return _finding("OC-SSH-003", "SSH X11Forwarding", Severity.LOW,
                        True, "sshd_config not present", "")
    val = (_sshd_option("X11Forwarding") or "no").lower()
    ok = val == "no"
    return _finding(
        "OC-SSH-003", "SSH X11 forwarding is disabled", Severity.LOW,
        ok=ok, detail=f"X11Forwarding = {val}",
        remediation="Set 'X11Forwarding no' unless explicitly required",
        refs=["CIS 5.2.6"],
    )


# --------------------------------------------------------------------------
# Kernel / sysctl network hardening
# --------------------------------------------------------------------------
def _sysctl(key: str) -> str | None:
    procpath = "/proc/sys/" + key.replace(".", "/")
    return (_read(procpath) or "").strip() or None


@check("OC-NET-001", "IP forwarding is disabled on hosts", severity=Severity.MEDIUM)
def _ip_forward() -> Finding:
    val = _sysctl("net.ipv4.ip_forward")
    if val is None:
        return _finding("OC-NET-001", "net.ipv4.ip_forward", Severity.MEDIUM,
                        True, "sysctl not readable (non-Linux?)", "")
    ok = val == "0"
    return _finding(
        "OC-NET-001", "IP forwarding is disabled on hosts", Severity.MEDIUM,
        ok=ok, detail=f"net.ipv4.ip_forward = {val}",
        remediation="Set net.ipv4.ip_forward=0 in /etc/sysctl.d/ (unless a router)",
        refs=["CIS 3.2.1"],
    )


@check("OC-NET-002", "ICMP redirects are not accepted", severity=Severity.MEDIUM)
def _accept_redirects() -> Finding:
    val = _sysctl("net.ipv4.conf.all.accept_redirects")
    if val is None:
        return _finding("OC-NET-002", "accept_redirects", Severity.MEDIUM,
                        True, "sysctl not readable", "")
    ok = val == "0"
    return _finding(
        "OC-NET-002", "ICMP redirects are not accepted", Severity.MEDIUM,
        ok=ok, detail=f"net.ipv4.conf.all.accept_redirects = {val}",
        remediation="Set net.ipv4.conf.all.accept_redirects=0",
        refs=["CIS 3.3.2"],
    )


@check("OC-NET-003", "Reverse-path filtering is enabled", level=2,
       severity=Severity.LOW)
def _rp_filter() -> Finding:
    val = _sysctl("net.ipv4.conf.all.rp_filter")
    if val is None:
        return _finding("OC-NET-003", "rp_filter", Severity.LOW,
                        True, "sysctl not readable", "")
    ok = val in {"1", "2"}
    return _finding(
        "OC-NET-003", "Reverse-path filtering is enabled", Severity.LOW,
        ok=ok, detail=f"net.ipv4.conf.all.rp_filter = {val}",
        remediation="Set net.ipv4.conf.all.rp_filter=1",
        refs=["CIS 3.3.7"],
    )


# --------------------------------------------------------------------------
# Accounts & auth policy
# --------------------------------------------------------------------------
@check("OC-ACC-001", "No non-root accounts have UID 0", severity=Severity.CRITICAL)
def _uid0() -> Finding:
    text = _read("/etc/passwd")
    if text is None:
        return _finding("OC-ACC-001", "UID 0 accounts", Severity.CRITICAL,
                        True, "/etc/passwd not present", "")
    uid0 = [line.split(":")[0] for line in text.splitlines()
            if len(line.split(":")) > 2 and line.split(":")[2] == "0"]
    extra = [u for u in uid0 if u != "root"]
    return _finding(
        "OC-ACC-001", "No non-root accounts have UID 0", Severity.CRITICAL,
        ok=not extra,
        detail=f"UID-0 accounts: {', '.join(uid0) or 'none'}",
        remediation="Remove or re-assign UID for accounts other than root",
        refs=["CIS 6.2.9"],
    )


@check("OC-ACC-002", "Password max-age policy is configured", level=1,
       severity=Severity.LOW)
def _pass_max_days() -> Finding:
    text = _read("/etc/login.defs")
    if text is None:
        return _finding("OC-ACC-002", "PASS_MAX_DAYS", Severity.LOW,
                        True, "/etc/login.defs not present", "")
    value = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("PASS_MAX_DAYS"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                value = int(parts[1])
    ok = value is not None and value <= 365
    return _finding(
        "OC-ACC-002", "Password max-age policy is configured", Severity.LOW,
        ok=ok, detail=f"PASS_MAX_DAYS = {value}",
        remediation="Set PASS_MAX_DAYS to 365 or fewer in /etc/login.defs",
        refs=["CIS 5.4.1.1"],
    )


def all_checks(level: int = 2) -> list[CheckMeta]:
    """Return registered checks up to and including the given CIS level."""
    return [c for c in _REGISTRY if c.level <= level]
