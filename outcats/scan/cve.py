"""Offline CVE correlation.

Loads a bundled CVE dataset and correlates it against detected
service/version pairs. Version comparison uses a tolerant tuple parser so it
handles values like '9.3p2', '2.4.49', '3.0.7'. This is read-only lookup only;
it never validates or attempts a vulnerability.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "cve_sample.json"


@dataclass
class CVEMatch:
    cve: str
    severity: str
    summary: str
    fixed_in: str
    refs: list[str]


@lru_cache(maxsize=1)
def _dataset() -> dict:
    return json.loads(DATA_FILE.read_text())


def port_hint(port: int) -> str | None:
    return _dataset().get("port_service_hints", {}).get(str(port))


def _parse_version(v: str) -> tuple:
    """Turn a version string into a comparable tuple.

    '9.3p2' -> (9, 3, 0, 2) ; '2.4.49' -> (2, 4, 49) ; letters become numbers.
    """
    parts = re.split(r"[.\-]", v.strip())
    out: list[int] = []
    for part in parts:
        m = re.match(r"(\d+)([a-zA-Z]*)(\d*)", part)
        if not m:
            continue
        out.append(int(m.group(1)))
        if m.group(2):  # e.g. the 'p' in 9.3p2 -> patch marker
            out.append(0)
        if m.group(3):
            out.append(int(m.group(3)))
    return tuple(out) if out else (0,)


def _in_range(version: str, lo: str, hi: str) -> bool:
    vt, lot, hit = _parse_version(version), _parse_version(lo), _parse_version(hi)
    return lot <= vt < hit


def correlate(service: str, version: str | None) -> list[CVEMatch]:
    """Return CVEs affecting `service` at `version`.

    If version is unknown, returns all known CVEs for the service flagged as
    'version unknown' so the operator can verify manually.
    """
    service = service.lower()
    entries = _dataset().get("services", {}).get(service, [])
    matches: list[CVEMatch] = []
    for e in entries:
        affected = e.get("affected", {})
        lo, hi = affected.get("min", "0"), affected.get("max", "999999")
        include = version is None or _in_range(version, lo, hi)
        if include:
            summary = e["summary"]
            if version is None:
                summary = "[version unknown - verify] " + summary
            matches.append(
                CVEMatch(
                    cve=e["cve"],
                    severity=e.get("severity", "medium"),
                    summary=summary,
                    fixed_in=e.get("fixed_in", "unknown"),
                    refs=e.get("refs", []),
                )
            )
    return matches


def known_services() -> list[str]:
    return sorted(_dataset().get("services", {}).keys())
