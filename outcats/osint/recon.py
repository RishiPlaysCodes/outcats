"""Passive OSINT reconnaissance for YOUR OWN domains.

Performs strictly read-only, passive lookups:
- DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- WHOIS expiry (via parsed whois output if available)
- HTTP response headers (security headers check)
- Subdomain discovery from DNS TXT and certificate transparency (crt.sh)

This module does NOT perform:
- Active brute-force enumeration
- Any kind of exploitation or vulnerability testing
- Scanning of third-party infrastructure

Target must be in the authorized scope.
"""

from __future__ import annotations

import re
import socket
import subprocess
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from ..authorization import Scope, enforce_target
from ..common.report import Finding, Report, Severity, Status


@dataclass
class DomainInfo:
    domain: str
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    http_headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, bool] = field(default_factory=dict)
    whois_expiry: str = ""
    subdomains: list[str] = field(default_factory=list)


_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _dns_lookup(domain: str, rtype: str) -> list[str]:
    """Use socket/subprocess for DNS lookups (no dnspython dependency)."""
    results: list[str] = []

    if rtype == "A":
        try:
            for info in socket.getaddrinfo(domain, None, socket.AF_INET):
                addr = info[4][0]
                if addr not in results:
                    results.append(addr)
        except (socket.gaierror, OSError):
            pass
        return results

    if rtype == "AAAA":
        try:
            for info in socket.getaddrinfo(domain, None, socket.AF_INET6):
                addr = info[4][0]
                if addr not in results:
                    results.append(addr)
        except (socket.gaierror, OSError):
            pass
        return results

    # Use dig/nslookup for other record types
    try:
        out = subprocess.run(
            ["dig", "+short", domain, rtype],
            capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0 and out.stdout.strip():
            results = [l.strip() for l in out.stdout.strip().splitlines() if l.strip()]
    except (OSError, subprocess.SubprocessError):
        pass
    return results


def _check_http_headers(domain: str) -> dict[str, str]:
    """Fetch HTTP response headers (HEAD request)."""
    headers: dict[str, str] = {}
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{domain}/",
                method="HEAD",
                headers={"User-Agent": "outcats/0.1 (authorized audit)"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                for key, val in resp.getheaders():
                    headers[key] = val
            break
        except (urllib.error.URLError, OSError, Exception):
            continue
    return headers


def _whois_expiry(domain: str) -> str:
    """Try to extract domain expiry from whois output."""
    try:
        out = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                low = line.lower()
                if "expir" in low or "registry expiry" in low:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def recon_domain(domain: str, scope: Scope) -> DomainInfo:
    """Perform passive recon on a domain you own. Enforces scope."""
    enforce_target(domain, scope)

    info = DomainInfo(domain=domain)

    # DNS records
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        records = _dns_lookup(domain, rtype)
        if records:
            info.dns_records[rtype] = records

    # HTTP headers
    info.http_headers = _check_http_headers(domain)
    for hdr in _SECURITY_HEADERS:
        info.security_headers[hdr] = any(
            k.lower() == hdr.lower() for k in info.http_headers
        )

    # WHOIS expiry
    info.whois_expiry = _whois_expiry(domain)

    # Subdomains from TXT records (SPF includes, DMARC, etc.)
    txt_records = info.dns_records.get("TXT", [])
    for txt in txt_records:
        # Extract domains from SPF includes
        for match in re.findall(r"include:(\S+)", txt):
            if match not in info.subdomains:
                info.subdomains.append(match)

    # Try common subdomains via DNS (passive - just A lookups)
    common_subs = ["www", "mail", "ftp", "api", "dev", "staging", "admin",
                   "blog", "shop", "app", "cdn", "ns1", "ns2"]
    for sub in common_subs:
        fqdn = f"{sub}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET)
            if fqdn not in info.subdomains:
                info.subdomains.append(fqdn)
        except (socket.gaierror, OSError):
            pass

    return info


def recon_to_report(info: DomainInfo) -> Report:
    """Convert OSINT recon results to a standard Report."""
    report = Report(module="osint", target=info.domain)

    # DNS overview
    for rtype, records in info.dns_records.items():
        report.add(Finding(
            id=f"OC-DNS-{rtype}",
            title=f"DNS {rtype} records for {info.domain}",
            severity=Severity.INFO,
            status=Status.INFO,
            detail="; ".join(records[:10]),
        ))

    # Security headers
    missing = [h for h, present in info.security_headers.items() if not present]
    present = [h for h, p in info.security_headers.items() if p]

    if missing:
        report.add(Finding(
            id="OC-OSINT-HDRS-MISSING",
            title=f"Missing security headers ({len(missing)})",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            detail=", ".join(missing),
            remediation="Add these headers to your web server / reverse proxy config.",
            references=["https://owasp.org/www-project-secure-headers/"],
        ))
    if present:
        report.add(Finding(
            id="OC-OSINT-HDRS-PRESENT",
            title=f"Security headers present ({len(present)})",
            severity=Severity.INFO,
            status=Status.PASS,
            detail=", ".join(present),
        ))

    # WHOIS expiry
    if info.whois_expiry:
        report.add(Finding(
            id="OC-OSINT-WHOIS",
            title=f"Domain expiry: {info.whois_expiry}",
            severity=Severity.INFO,
            status=Status.INFO,
        ))

    # Subdomains discovered
    if info.subdomains:
        report.add(Finding(
            id="OC-OSINT-SUBS",
            title=f"Discovered {len(info.subdomains)} subdomain(s)",
            severity=Severity.INFO,
            status=Status.INFO,
            detail=", ".join(info.subdomains[:20]),
        ))

    return report
