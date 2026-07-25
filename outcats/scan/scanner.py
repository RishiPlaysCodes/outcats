"""Assemble fingerprint + CVE results into a unified Report."""

from __future__ import annotations

from ..authorization import Scope
from ..common.report import Finding, Report, Severity, Status
from . import fingerprint

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def run_scan(
    host: str,
    scope: Scope,
    ports: list[int] | None = None,
    timeout: float = 1.0,
) -> Report:
    report = Report(module="scan", target=host)
    results = fingerprint.scan_host(host, scope, ports=ports, timeout=timeout)

    if not results:
        report.add(
            Finding(
                id="OC-SCAN-000",
                title="No open ports detected",
                severity=Severity.INFO,
                status=Status.INFO,
                detail="No listening TCP services found in the scanned port set.",
            )
        )
        return report

    for r in results:
        svc = r.service or "unknown"
        ver = r.version or "unknown"
        # Open-port informational finding.
        report.add(
            Finding(
                id=f"OC-PORT-{r.port}",
                title=f"Open port {r.port}/tcp ({svc})",
                severity=Severity.INFO,
                status=Status.INFO,
                detail=f"service={svc} version={ver} "
                + (f"banner={r.banner[:80]!r}" if r.banner else "banner=<none>"),
            )
        )
        # One finding per correlated CVE.
        for m in r.cves:
            report.add(
                Finding(
                    id=m.cve,
                    title=f"{svc} {ver}: {m.cve}",
                    severity=_SEV.get(m.severity, Severity.MEDIUM),
                    status=Status.FAIL,
                    detail=m.summary,
                    remediation=f"Upgrade {svc} to {m.fixed_in} or later.",
                    references=m.refs,
                )
            )
    return report
