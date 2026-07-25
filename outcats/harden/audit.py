"""Run hardening checks and assemble a Report."""

from __future__ import annotations

from ..common import system
from ..common.report import Finding, Report, Severity, Status
from . import checks


def run_audit(level: int = 2, plat: str | None = None) -> Report:
    """Execute the checks relevant to this platform up to `level`.

    `plat` overrides platform auto-detection (one of linux/macos/windows/all).
    """
    info = system.collect()
    active_plat = plat or checks.current_platform()
    report = Report(module="harden", target=f"{info.hostname} ({info.distro})")

    selected = checks.all_checks(level=level, plat=active_plat)

    # Informational header finding: what we audited.
    report.add(
        Finding(
            id="OC-INFO",
            title="System under audit",
            severity=Severity.INFO,
            status=Status.INFO,
            detail=(
                f"platform={active_plat} os={info.os_system} "
                f"release={info.os_release} arch={info.architecture} "
                f"python={info.python_version} checks={len(selected)}"
            ),
        )
    )

    for meta in selected:
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
