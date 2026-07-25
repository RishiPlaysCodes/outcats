"""Read-only TCP service fingerprinting for AUTHORIZED hosts.

This performs a lightweight, connect-only port check (a full TCP handshake, then
immediate close) and an optional passive banner read. It does NOT send crafted
payloads, does not attempt authentication, and does not exploit anything. Every
target is validated against the authorization scope before any socket is opened.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ..authorization import Scope, enforce_target
from . import cve

# Curated common-port set (fast, sane default).
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]

# Generic version token, and product-specific patterns that tie a version to
# the product name so we don't accidentally grab a protocol version (e.g. the
# "2.0" in "SSH-2.0-OpenSSH_9.6p1").
_VERSION_RE = re.compile(r"(\d+\.\d+(?:[.\-p]\d+)*)")
_PRODUCT_VERSION_RES = {
    "openssh": re.compile(r"openssh[_/](\d+\.\d+(?:p\d+)?)", re.IGNORECASE),
    "nginx": re.compile(r"nginx/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "apache": re.compile(r"apache/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "vsftpd": re.compile(r"vsftpd\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "openssl": re.compile(r"openssl/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
}


@dataclass
class PortResult:
    port: int
    open: bool
    service: str | None = None
    banner: str = ""
    version: str | None = None
    cves: list[cve.CVEMatch] = field(default_factory=list)


def _grab_banner(host: str, port: int, timeout: float) -> str:
    """Passively read a service banner if one is offered on connect."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # For HTTP-ish ports, a minimal, benign HEAD nudges a Server: line.
            if port in (80, 8080):
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except OSError:
                    pass
            try:
                data = sock.recv(256)
            except (socket.timeout, OSError):
                return ""
            return data.decode(errors="replace").strip()
    except OSError:
        return ""


def _service_from_banner(banner: str) -> tuple[str | None, str | None]:
    b = banner.lower()
    service = None
    if "ssh" in b or "openssh" in b:
        service = "openssh"
    elif "nginx" in b:
        service = "nginx"
    elif "apache" in b:
        service = "apache"
    elif "vsftpd" in b:
        service = "vsftpd"
    elif "openssl" in b:
        service = "openssl"
    version = None
    # Prefer a version tied to the detected product name.
    if service and service in _PRODUCT_VERSION_RES:
        pm = _PRODUCT_VERSION_RES[service].search(banner)
        if pm:
            version = pm.group(1)
    # Fall back to the first generic version token only if nothing better found.
    if version is None:
        m = _VERSION_RE.search(banner)
        if m:
            version = m.group(1)
    return service, version


def _probe_port(host: str, port: int, timeout: float) -> PortResult:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            is_open = True
    except OSError:
        return PortResult(port=port, open=False)

    banner = _grab_banner(host, port, timeout)
    svc, ver = _service_from_banner(banner)
    if svc is None:
        svc = cve.port_hint(port)
    result = PortResult(port=port, open=True, service=svc, banner=banner, version=ver)
    if svc:
        result.cves = cve.correlate(svc, ver)
    return result


def scan_host(
    host: str,
    scope: Scope,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    workers: int = 32,
) -> list[PortResult]:
    """Connect-scan `host` for open ports. Refuses out-of-scope targets."""
    enforce_target(host, scope)  # hard gate: authorization enforced here
    ports = ports or COMMON_PORTS
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res.open:
                results.append(res)
    return sorted(results, key=lambda r: r.port)
