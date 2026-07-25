"""outcats unified command-line interface.

Subcommands:
    authorize   Attest authorization and declare an in-scope host list.
    guide       Guided intake: tell it what you know (or nothing); get a plan.
    gui         Launch the cross-platform web dashboard.
    interactive Menu-driven interactive shell (TUI).
    harden      Run a CIS/STIG-style hardening audit of the local system.
    passwords   Password policy & credential hygiene audit.
    scan        Read-only service fingerprint + CVE correlation (authorized hosts).
    netmap      Network mapper: scan multiple hosts, visualize services.
    tls         SSL/TLS certificate and protocol checker.
    osint       Passive OSINT recon for domains you own.
    lab         CTF / practice-lab methodology companion.
    detect      Blue-team log ingestion + detection-rule engine.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .authorization import (
    AuthorizationError,
    interactive_authorize,
    require_scope,
)
from .common.report import Report
from .scan.fingerprint import COMMON_PORTS


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def _emit(report: Report, fmt: str, out: str | None) -> None:
    if fmt == "json":
        text = report.to_json()
    elif fmt == "html":
        text = report.to_html()
    elif fmt == "csv":
        from .common.export import to_csv
        text = to_csv(report)
    elif fmt == "pdf":
        from .common.export import to_pdf_html
        text = to_pdf_html(report)
    else:
        text = report.to_text(color=out is None and sys.stdout.isatty())

    if out:
        Path(out).write_text(text)
        suffix = " (open in browser -> Print -> Save as PDF)" if fmt == "pdf" else ""
        print(f"Report written to {out}  ({len(report.findings)} findings){suffix}")
    else:
        print(text)


def _parse_ports(spec: str) -> list[int]:
    if spec in ("common", "", None):
        return COMMON_PORTS
    if spec == "all":
        return list(range(1, 1025))
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            ports.append(int(part))
    return ports or COMMON_PORTS


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------
def cmd_authorize(args: argparse.Namespace) -> int:
    interactive_authorize()
    return 0


def cmd_guide(args: argparse.Namespace) -> int:
    from .guide import run_guide

    run_guide()
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from .gui.server import serve

    serve(host=args.host, port=args.port, token=args.token)
    return 0


def cmd_harden(args: argparse.Namespace) -> int:
    from .harden.audit import run_audit

    report = run_audit(level=args.level, plat=args.platform)
    _emit(report, args.format, args.out)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from .scan.scanner import run_scan

    try:
        scope = require_scope()
        report = run_scan(
            args.target, scope, ports=_parse_ports(args.ports), timeout=args.timeout
        )
    except AuthorizationError as exc:
        print(f"[authorization] {exc}", file=sys.stderr)
        return 2
    _emit(report, args.format, args.out)
    return 0


def cmd_lab(args: argparse.Namespace) -> int:
    from .lab import companion

    if args.lab_cmd == "templates":
        for key, title in companion.list_templates().items():
            print(f"  {key:10} {title}")
        return 0

    if args.lab_cmd == "start":
        eng = companion.Engagement(
            name=args.name, template=args.template, platform=args.platform
        )
        eng.save()
        print(f"Started engagement '{eng.name}' using template '{eng.template}'.")
        _print_checklist(eng)
        return 0

    if args.lab_cmd == "show":
        eng = companion.Engagement.load(args.name)
        _print_checklist(eng)
        if eng.notes:
            print("\nNotes:")
            for n in eng.notes:
                print(f"  [{n['phase']}] {n['text']}")
        return 0

    if args.lab_cmd == "note":
        eng = companion.Engagement.load(args.name)
        eng.add_note(args.phase, args.text)
        eng.save()
        print("Note added.")
        return 0

    if args.lab_cmd == "done":
        eng = companion.Engagement.load(args.name)
        eng.complete_step(args.step)
        eng.save()
        d, t = eng.progress()
        print(f"Marked done. Progress: {d}/{t} steps.")
        return 0

    if args.lab_cmd == "list":
        names = companion.list_engagements()
        print("\n".join(f"  {n}" for n in names) if names else "  (no engagements)")
        return 0

    return 1


def _print_checklist(eng) -> None:
    d, t = eng.progress()
    print(f"\nMethodology: {eng.template}  |  progress {d}/{t}")
    current = None
    for phase, step, done in eng.checklist():
        if phase != current:
            print(f"\n  == {phase} ==")
            current = phase
        mark = "x" if done else " "
        print(f"    [{mark}] {step}")


def cmd_detect(args: argparse.Namespace) -> int:
    from .detect.runner import run_detection

    if args.detect_cmd == "run":
        try:
            report = run_detection(args.log, rules_path=args.rules)
        except FileNotFoundError as exc:
            print(f"[detect] {exc}", file=sys.stderr)
            return 2
        _emit(report, args.format, args.out)
        return 0

    if args.detect_cmd == "rules":
        from .detect.engine import load_rules

        for r in load_rules(args.rules):
            print(f"  {r.id:28} [{r.severity:8}] {r.name}  (MITRE {r.mitre})")
        return 0

    return 1


def cmd_netmap(args: argparse.Namespace) -> int:
    from .netmap.mapper import map_network, netmap_to_report

    try:
        scope = require_scope()
        hosts = [h.strip() for h in args.targets.split(",") if h.strip()]
        nmap = map_network(hosts, scope, ports=_parse_ports(args.ports),
                           timeout=args.timeout)
    except AuthorizationError as exc:
        print(f"[authorization] {exc}", file=sys.stderr)
        return 2
    if args.format == "text" and not args.out:
        print(nmap.to_table(color=sys.stdout.isatty()))
    else:
        _emit(netmap_to_report(nmap), args.format, args.out)
    return 0


def cmd_tls(args: argparse.Namespace) -> int:
    from .authorization import enforce_target
    from .tlscheck.checker import check_tls, tls_to_report

    try:
        scope = require_scope()
        hosts = [h.strip() for h in args.targets.split(",") if h.strip()]
        results = []
        for h in hosts:
            enforce_target(h, scope)
            results.append(check_tls(h, port=args.port, timeout=args.timeout))
    except AuthorizationError as exc:
        print(f"[authorization] {exc}", file=sys.stderr)
        return 2
    _emit(tls_to_report(results), args.format, args.out)
    return 0


def cmd_passwords(args: argparse.Namespace) -> int:
    from .harden.passwords import audit_password_policy

    _emit(audit_password_policy(), args.format, args.out)
    return 0


def cmd_osint(args: argparse.Namespace) -> int:
    from .osint.recon import recon_domain, recon_to_report

    try:
        scope = require_scope()
        info = recon_domain(args.domain, scope)
    except AuthorizationError as exc:
        print(f"[authorization] {exc}", file=sys.stderr)
        return 2
    _emit(recon_to_report(info), args.format, args.out)
    return 0


def cmd_interactive(args: argparse.Namespace) -> int:
    from .interactive import run_interactive

    run_interactive()
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="outcats",
        description="Enterprise-grade DEFENSIVE security platform (authorized use only).",
    )
    p.add_argument("--version", action="version", version=f"outcats {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # authorize
    sub.add_parser("authorize", help="Attest authorization and set host scope")

    # guide
    sub.add_parser("guide", help="Guided intake; tell it what you know")

    # gui
    gp = sub.add_parser("gui", help="Launch the cross-platform web dashboard")
    gp.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default localhost-only; use 0.0.0.0 to deploy)")
    gp.add_argument("--port", type=int, default=8787, help="Port (default 8787)")
    gp.add_argument("--token", default=None,
                    help="Require this access token on every request "
                         "(strongly recommended for public/deployed instances)")

    def add_output(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--format", choices=["text", "json", "html", "csv", "pdf"],
                        default="text",
                        help="Output format (pdf = print-ready HTML for Save as PDF)")
        sp.add_argument("--out", help="Write report to a file instead of stdout")

    # harden
    hp = sub.add_parser("harden", help="CIS/STIG-style hardening audit (local)")
    hp.add_argument("--level", type=int, choices=[1, 2], default=2,
                    help="CIS profile level (1=baseline, 2=defense-in-depth)")
    hp.add_argument("--platform", choices=["linux", "macos", "windows", "all"],
                    default=None,
                    help="Override platform detection (default: auto-detect)")
    add_output(hp)

    # scan
    scp = sub.add_parser("scan", help="Read-only fingerprint + CVE (authorized hosts)")
    scp.add_argument("--target", required=True, help="Host/IP in your authorized scope")
    scp.add_argument("--ports", default="common",
                     help="'common', 'all', or list/range e.g. 22,80,8000-8100")
    scp.add_argument("--timeout", type=float, default=1.0, help="Per-port timeout (s)")
    add_output(scp)

    # lab
    lp = sub.add_parser("lab", help="CTF / practice-lab methodology companion")
    lsub = lp.add_subparsers(dest="lab_cmd", required=True)
    lsub.add_parser("templates", help="List methodology templates")
    lstart = lsub.add_parser("start", help="Start a new engagement")
    lstart.add_argument("name")
    lstart.add_argument("--template", default="generic")
    lstart.add_argument("--platform", default="practice-lab")
    lshow = lsub.add_parser("show", help="Show an engagement checklist + notes")
    lshow.add_argument("name")
    lnote = lsub.add_parser("note", help="Add a note to an engagement")
    lnote.add_argument("name")
    lnote.add_argument("--phase", default="general")
    lnote.add_argument("text")
    ldone = lsub.add_parser("done", help="Mark a checklist step complete")
    ldone.add_argument("name")
    ldone.add_argument("step")
    lsub.add_parser("list", help="List engagements")

    # detect
    dp = sub.add_parser("detect", help="Blue-team log detection engine")
    dsub = dp.add_subparsers(dest="detect_cmd", required=True)
    drun = dsub.add_parser("run", help="Run detection rules over a log file")
    drun.add_argument("--log", required=True, help="Path to a log file")
    drun.add_argument("--rules", help="Custom rules JSON (defaults to bundled set)")
    add_output(drun)
    drules = dsub.add_parser("rules", help="List loaded detection rules")
    drules.add_argument("--rules", help="Custom rules JSON")

    # netmap
    nmp = sub.add_parser("netmap", help="Network mapper (multi-host service scan)")
    nmp.add_argument("--targets", required=True,
                     help="Comma-separated hosts/IPs (must be in scope)")
    nmp.add_argument("--ports", default="common",
                     help="'common', 'all', or list/range")
    nmp.add_argument("--timeout", type=float, default=1.0)
    add_output(nmp)

    # tls
    tp = sub.add_parser("tls", help="SSL/TLS certificate & protocol checker")
    tp.add_argument("--targets", required=True,
                    help="Comma-separated HTTPS hosts (must be in scope)")
    tp.add_argument("--port", type=int, default=443)
    tp.add_argument("--timeout", type=float, default=5.0)
    add_output(tp)

    # passwords
    pwp = sub.add_parser("passwords", help="Password policy & credential hygiene audit")
    add_output(pwp)

    # osint
    osp = sub.add_parser("osint", help="Passive OSINT recon for domains you own")
    osp.add_argument("--domain", required=True,
                     help="Domain you own (must be in scope)")
    add_output(osp)

    # interactive
    sub.add_parser("interactive", help="Menu-driven interactive shell (TUI)")

    return p


_HANDLERS = {
    "authorize": cmd_authorize,
    "guide": cmd_guide,
    "gui": cmd_gui,
    "interactive": cmd_interactive,
    "harden": cmd_harden,
    "passwords": cmd_passwords,
    "scan": cmd_scan,
    "netmap": cmd_netmap,
    "tls": cmd_tls,
    "osint": cmd_osint,
    "lab": cmd_lab,
    "detect": cmd_detect,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = _HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except (AuthorizationError, FileNotFoundError, KeyError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
