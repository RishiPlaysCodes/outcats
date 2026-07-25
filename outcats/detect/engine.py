"""Blue-team detection engine.

Ingests log lines, evaluates them against regex-based detection rules, and
raises alerts. Rules can be simple (fire on any match) or thresholded (fire when
N matches from the same actor occur within a rolling time window - e.g.
brute-force). Timestamps are parsed from common syslog / access-log formats;
when absent, a monotonic line counter approximates ordering.

This module is purely analytic: it reads logs and reports. It takes no action
against any host.
"""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Iterable

_DEFAULT_RULES = Path(__file__).resolve().parent.parent / "data" / "detection_rules.json"

# syslog: "Jul 25 22:48:01" ; assumes current year.
_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
                        r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})")
# common/combined access log: "[25/Jul/2026:22:48:01 +0000]"
_ACCESS_TS = re.compile(r"\[(?P<d>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<y>\d{4}):"
                        r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    pattern: str
    group_by: str = "ip"
    threshold: int = 1
    window_seconds: int = 0
    mitre: str = ""
    guidance: str = ""
    regex: re.Pattern = field(init=False)

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, re.IGNORECASE)


@dataclass
class Alert:
    rule_id: str
    name: str
    severity: str
    actor: str
    count: int
    first_line: str
    mitre: str
    guidance: str


@lru_cache(maxsize=8)
def load_rules(path: str | None = None) -> tuple[Rule, ...]:
    p = Path(path) if path else _DEFAULT_RULES
    data = json.loads(p.read_text())
    rules = []
    for r in data.get("rules", []):
        rules.append(
            Rule(
                id=r["id"], name=r["name"], severity=r.get("severity", "medium"),
                pattern=r["pattern"], group_by=r.get("group_by", "ip"),
                threshold=int(r.get("threshold", 1)),
                window_seconds=int(r.get("window_seconds", 0)),
                mitre=r.get("mitre", ""), guidance=r.get("guidance", ""),
            )
        )
    return tuple(rules)


def _parse_ts(line: str, fallback: float) -> float:
    m = _ACCESS_TS.search(line)
    if m:
        try:
            return datetime(
                int(m.group("y")), _MONTHS[m.group("mon")], int(m.group("d")),
                int(m.group("h")), int(m.group("m")), int(m.group("s")),
            ).timestamp()
        except (ValueError, KeyError):
            pass
    m = _SYSLOG_TS.match(line)
    if m:
        try:
            year = datetime.now().year
            return datetime(
                year, _MONTHS[m.group("mon")], int(m.group("day")),
                int(m.group("h")), int(m.group("m")), int(m.group("s")),
            ).timestamp()
        except (ValueError, KeyError):
            pass
    return fallback


class DetectionEngine:
    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    def run(self, lines: Iterable[str]) -> list[Alert]:
        # For thresholded rules, track (rule.id, actor) -> deque of timestamps.
        hits: dict[tuple[str, str], deque] = defaultdict(deque)
        first_seen: dict[tuple[str, str], str] = {}
        fired: set[tuple[str, str]] = set()
        alerts: list[Alert] = []

        for idx, raw in enumerate(lines):
            line = raw.rstrip("\n")
            if not line:
                continue
            ts = _parse_ts(line, fallback=float(idx))
            for rule in self.rules:
                m = rule.regex.search(line)
                if not m:
                    continue
                groups = m.groupdict()
                actor = groups.get(rule.group_by) or groups.get("ip") \
                    or groups.get("user") or "unknown"
                key = (rule.id, actor)
                dq = hits[key]
                dq.append(ts)
                first_seen.setdefault(key, line)

                # Evict timestamps outside the window (window 0 = no windowing).
                if rule.window_seconds > 0:
                    while dq and ts - dq[0] > rule.window_seconds:
                        dq.popleft()

                if len(dq) >= rule.threshold and key not in fired:
                    fired.add(key)
                    alerts.append(
                        Alert(
                            rule_id=rule.id, name=rule.name, severity=rule.severity,
                            actor=actor, count=len(dq),
                            first_line=first_seen[key][:160],
                            mitre=rule.mitre, guidance=rule.guidance,
                        )
                    )
        return alerts
