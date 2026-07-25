"""Run the detection engine over a log source and build a Report."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..common.report import Finding, Report, Severity, Status
from .engine import Alert, DetectionEngine, load_rules

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _iter_lines(log_path: str) -> Iterable[str]:
    p = Path(log_path)
    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")
    with p.open("r", errors="replace") as fh:
        yield from fh


def run_detection(log_path: str, rules_path: str | None = None) -> Report:
    rules = load_rules(rules_path)
    engine = DetectionEngine(rules)
    alerts: list[Alert] = engine.run(_iter_lines(log_path))

    report = Report(module="detect", target=log_path)
    report.add(
        Finding(
            id="OC-DET-INFO",
            title="Detection run summary",
            severity=Severity.INFO,
            status=Status.INFO,
            detail=f"{len(rules)} rule(s) evaluated; {len(alerts)} alert(s) raised.",
        )
    )
    for a in alerts:
        report.add(
            Finding(
                id=a.rule_id,
                title=f"{a.name} (actor={a.actor}, hits={a.count})",
                severity=_SEV.get(a.severity, Severity.MEDIUM),
                status=Status.FAIL if a.severity != "info" else Status.INFO,
                detail=f"MITRE {a.mitre} | first: {a.first_line}",
                remediation=a.guidance,
                references=[f"https://attack.mitre.org/techniques/{a.mitre}/"]
                if a.mitre else [],
            )
        )
    return report
