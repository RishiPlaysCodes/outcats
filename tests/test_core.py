"""Unit tests for outcats core logic (no network required)."""

from __future__ import annotations

import time

import pytest

from outcats.authorization import Scope, is_in_scope
from outcats.common.report import Finding, Report, Severity, Status
from outcats.detect.engine import DetectionEngine, load_rules
from outcats.scan import cve


# --------------------------------------------------------------------------
# Authorization scope
# --------------------------------------------------------------------------
def _scope() -> Scope:
    return Scope(
        operator="t",
        authorization_ref="own",
        attested_at=time.time(),
        allowed_hosts=["10.0.0.0/24", "myhost.local"],
    )


def test_loopback_always_in_scope():
    assert is_in_scope("127.0.0.1", _scope())
    assert is_in_scope("localhost", _scope())


def test_cidr_membership():
    s = _scope()
    assert is_in_scope("10.0.0.55", s)
    assert not is_in_scope("10.0.1.55", s)


def test_exact_host_match():
    assert is_in_scope("myhost.local", _scope())


def test_out_of_scope_public_ip():
    assert not is_in_scope("8.8.8.8", _scope())


# --------------------------------------------------------------------------
# CVE correlation
# --------------------------------------------------------------------------
def test_version_parse_handles_patch_letters():
    assert cve._parse_version("9.3p2") == (9, 3, 0, 2)
    assert cve._parse_version("2.4.49") == (2, 4, 49)


def test_openssh_vulnerable_and_fixed():
    assert any(m.cve == "CVE-2024-6387" for m in cve.correlate("openssh", "9.6p1"))
    assert cve.correlate("openssh", "9.9p1") == []


def test_unknown_version_flags_for_verification():
    matches = cve.correlate("nginx", None)
    assert matches and matches[0].summary.startswith("[version unknown")


# --------------------------------------------------------------------------
# Detection engine
# --------------------------------------------------------------------------
def test_ssh_bruteforce_threshold():
    rules = load_rules()
    engine = DetectionEngine(rules)
    lines = [
        f"Jul 25 22:10:0{i} host sshd: Failed password for invalid user u{i} "
        f"from 203.0.113.7 port 5100{i} ssh2"
        for i in range(6)
    ]
    alerts = engine.run(lines)
    brute = [a for a in alerts if a.rule_id == "OC-DET-SSH-BRUTE"]
    assert brute and brute[0].actor == "203.0.113.7"


def test_below_threshold_does_not_fire():
    rules = load_rules()
    engine = DetectionEngine(rules)
    lines = [
        "Jul 25 22:10:01 host sshd: Failed password for invalid user a "
        "from 203.0.113.9 port 51001 ssh2",
        "Jul 25 22:10:02 host sshd: Failed password for invalid user b "
        "from 203.0.113.9 port 51002 ssh2",
    ]
    alerts = [a for a in engine.run(lines) if a.rule_id == "OC-DET-SSH-BRUTE"]
    assert alerts == []


def test_sqli_probe_detected():
    engine = DetectionEngine(load_rules())
    line = ('192.0.2.66 - - [25/Jul/2026:22:15:10 +0000] '
            '"GET /x?id=1 union select a,b from users HTTP/1.1" 200 1 "-" "x"')
    alerts = [a for a in engine.run([line]) if a.rule_id == "OC-DET-WEB-SQLI-PROBE"]
    assert alerts


# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------
def test_report_counts_and_json():
    r = Report(module="harden", target="host")
    r.add(Finding("A", "ok", Severity.LOW, Status.PASS))
    r.add(Finding("B", "bad", Severity.HIGH, Status.FAIL, remediation="fix it"))
    assert r.counts_by_status()["pass"] == 1
    assert r.counts_by_status()["fail"] == 1
    assert r.counts_by_severity()["high"] == 1
    assert '"module": "harden"' in r.to_json()
    assert "outcats report" in r.to_html()
