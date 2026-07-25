"""Network mapper: scan multiple authorized hosts and build a service overview.

Produces a host×port matrix showing which services are open where, plus
summary stats. All hosts are validated against the authorization scope before
any packet leaves. Read-only connect-scan only — no exploitation.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ..authorization import Scope, enforce_target
from ..common.report import Finding, Report, Severity, Status
from ..scan.fingerprint import COMMON_PORTS, _grab_banner, _service_from_banner
from ..scan.cve import port_hint


@dataclass
class HostEntry:
    host: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)  # port -> service name
    banners: dict[int, str] = field(default_factory=dict)   # port -> banner


@dataclass
class NetworkMap:
    hosts: list[HostEntry] = field(default_factory=list)
    all_ports: set[int] = field(default_factory=set)

    def to_table(self, color: bool = True) -> str:
        """Render a host×port ASCII matrix."""
        if not self.hosts:
            return "(no hosts scanned)"

        ports = sorted(self.all_ports)
        if not ports:
            return "(no open ports found across all hosts)"

        # Column widths
        host_w = max(len(h.host) for h in self.hosts) + 2
        col_w = 7

        # Header
        hdr = " " * host_w + "".join(f"{p:<{col_w}}" for p in ports)
        sep = "-" * len(hdr)
        lines = [sep, hdr, sep]

        g = "\033[32m" if color else ""
        r = "\033[0m" if color else ""

        for h in self.hosts:
            row = f"{h.host:<{host_w}}"
            for p in ports:
                if p in h.open_ports:
                    svc = h.services.get(p, "open")[:5]
                    row += f"{g}{svc:<{col_w}}{r}"
                else:
                    row += f"{'·':<{col_w}}"
            lines.append(row)
        lines.append(sep)

        # Summary
        lines.append(f"\nHosts: {len(self.hosts)} | Open ports discovered: {len(ports)}")
        svc_counts: dict[str, int] = {}
        for h in self.hosts:
            for svc in h.services.values():
                svc_counts[svc] = svc_counts.get(svc, 0) + 1
        if svc_counts:
            top = sorted(svc_counts.items(), key=lambda x: -x[1])[:10]
            lines.append("Top services: " + ", ".join(f"{s}({n})" for s, n in top))
        return "\n".join(lines)


def _probe(host: str, port: int, timeout: float) -> tuple[str, int, bool, str | None]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        banner = _grab_banner(host, port, timeout)
        svc, _ = _service_from_banner(banner)
        if svc is None:
            svc = port_hint(port)
        return host, port, True, svc
    except OSError:
        return host, port, False, None


def map_network(
    hosts: list[str],
    scope: Scope,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    workers: int = 64,
) -> NetworkMap:
    """Connect-scan multiple hosts and build a NetworkMap.

    Every host is enforced against the authorization scope.
    """
    ports = ports or COMMON_PORTS
    netmap = NetworkMap()

    # Validate all hosts FIRST before any scanning begins.
    for h in hosts:
        enforce_target(h, scope)

    entries: dict[str, HostEntry] = {}
    for h in hosts:
        entries[h] = HostEntry(host=h)

    tasks = [(h, p) for h in hosts for p in ports]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe, h, p, timeout): (h, p) for h, p in tasks}
        for fut in as_completed(futures):
            host, port, is_open, svc = fut.result()
            if is_open:
                entry = entries[host]
                entry.open_ports.append(port)
                if svc:
                    entry.services[port] = svc
                netmap.all_ports.add(port)

    netmap.hosts = [entries[h] for h in hosts]
    # Sort open ports
    for h in netmap.hosts:
        h.open_ports.sort()
    return netmap


def netmap_to_report(nmap: NetworkMap) -> Report:
    """Convert a NetworkMap to a standard Report for rendering."""
    report = Report(module="netmap", target=f"{len(nmap.hosts)} host(s)")

    report.add(Finding(
        id="OC-NETMAP-SUMMARY",
        title=f"Network overview: {len(nmap.hosts)} hosts, {len(nmap.all_ports)} unique open ports",
        severity=Severity.INFO,
        status=Status.INFO,
        detail=nmap.to_table(color=False)[:500],
    ))

    for h in nmap.hosts:
        if not h.open_ports:
            report.add(Finding(
                id=f"OC-NETMAP-{h.host}",
                title=f"{h.host}: no open ports",
                severity=Severity.INFO,
                status=Status.PASS,
            ))
        else:
            svcs = ", ".join(f"{p}/{h.services.get(p, '?')}" for p in h.open_ports)
            report.add(Finding(
                id=f"OC-NETMAP-{h.host}",
                title=f"{h.host}: {len(h.open_ports)} open port(s)",
                severity=Severity.LOW,
                status=Status.INFO,
                detail=svcs,
            ))
    return report
