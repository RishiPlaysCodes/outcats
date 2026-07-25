"""Run hardening checks and assemble a Report."""

from __future__ import annotations

from ..common import system
from ..common.report import Finding, Report, Severity, Status
from . import checks


def run_audit(level: int = 2) -> Report:
    """Execute all registered checks up to `level` and build a Report."""
    info = system.collect()
    report = Report(module="harden", target=f"{info.hostname} ({info.distro})")

    # Informational header finding: what we audited.
    report.add(
        Finding(
            id="OC-INFO",
            title="System under audit",
            severity=Severity.INFO,
            status=Status.INFO,
            detail=(
                f"os={info.os_system} release={info.os_release} "
                f"arch={info.architecture} python={info.python_version}"
            ),
        )
    )

    for meta in checks.all_checks(level=level):
        try:
            finding = meta.func()
        except Exception as exc:  # a broken check must not abort the whole audit
            finding = Finding(
                id=meta.id,
                title=meta.title,
                severity=meta.severity,
                status=Status.WARN,
                detail=f"check error: {exc}",
                remediation="Review check execution environment",
            )
        report.add(finding)

    return report
