"""Interactive terminal mode (TUI) for outcats.

A menu-driven shell that walks through all modules without needing to remember
CLI flags. Designed for quick use and exploration — every action available in
the CLI is accessible here via numbered menus.
"""

from __future__ import annotations

import sys

from .authorization import AuthorizationError, Scope, interactive_authorize, require_scope
from .common import system


def _header():
    print("\033[1;36m")
    print("  ██████  ██    ██ ████████  ██████  █████  ████████ ███████")
    print("  ██    ██ ██    ██    ██    ██      ██   ██    ██    ██     ")
    print("  ██    ██ ██    ██    ██    ██      ███████    ██    ███████")
    print("  ██    ██ ██    ██    ██    ██      ██   ██    ██         ██")
    print("  ██████   ██████     ██     ██████ ██   ██    ██    ███████")
    print("\033[0m")
    print("  Enterprise Defensive Security Platform")
    print("  ────────────────────────────────────────────────────────────")
    info = system.collect()
    print(f"  Host: {info.hostname} | OS: {info.distro} | Python: {info.python_version}")
    scope = Scope.load()
    if scope:
        print(f"  Scope: {', '.join(scope.allowed_hosts) or 'localhost'} "
              f"(by {scope.operator})")
    else:
        print("  Scope: NOT SET (run option 1 first)")
    print()


def _menu():
    print("  ┌─────────────────────────────────────────────┐")
    print("  │  1. Authorize (set scope)                    │")
    print("  │  2. Hardening audit (local)                  │")
    print("  │  3. Vulnerability scan (authorized target)   │")
    print("  │  4. Network mapper (multi-host)              │")
    print("  │  5. SSL/TLS certificate check                │")
    print("  │  6. Password policy audit                    │")
    print("  │  7. OSINT passive recon (own domain)         │")
    print("  │  8. Blue-team detection (paste/file)         │")
    print("  │  9. CTF/Lab methodology                      │")
    print("  │  10. Launch web GUI                          │")
    print("  │  0. Exit                                     │")
    print("  └─────────────────────────────────────────────┘")


def _input(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"  {prompt}{suffix}: ").strip()
    return val or default


def _emit_report(report):
    print()
    print(report.to_text(color=sys.stdout.isatty()))
    print()
    save = _input("Save report? (json/csv/html/no)", "no").lower()
    if save == "json":
        fname = _input("Filename", "report.json")
        from pathlib import Path
        Path(fname).write_text(report.to_json())
        print(f"  Saved to {fname}")
    elif save == "csv":
        fname = _input("Filename", "report.csv")
        from .common.export import save_csv
        save_csv(report, fname)
        print(f"  Saved to {fname}")
    elif save == "html":
        fname = _input("Filename", "report.html")
        from .common.export import save_pdf_html
        save_pdf_html(report, fname)
        print(f"  Saved to {fname} (open in browser -> Print -> Save as PDF)")


def run_interactive():
    """Main interactive loop."""
    _header()

    while True:
        _menu()
        choice = _input("Choose", "0")

        try:
            if choice == "0":
                print("  Goodbye.")
                break

            elif choice == "1":
                interactive_authorize()

            elif choice == "2":
                from .harden.audit import run_audit
                level = int(_input("CIS level (1 or 2)", "2"))
                _emit_report(run_audit(level=level))

            elif choice == "3":
                scope = require_scope()
                target = _input("Target host/IP (must be in scope)")
                ports = _input("Ports (common / all / list)", "common")
                from .scan.scanner import run_scan
                from .scan.fingerprint import COMMON_PORTS
                plist = COMMON_PORTS if ports == "common" else (
                    list(range(1, 1025)) if ports == "all" else
                    [int(p) for p in ports.replace("-", ",").split(",") if p.strip().isdigit()]
                )
                _emit_report(run_scan(target, scope, ports=plist))

            elif choice == "4":
                scope = require_scope()
                raw = _input("Hosts (comma-separated, must be in scope)")
                hosts = [h.strip() for h in raw.split(",") if h.strip()]
                from .netmap.mapper import map_network, netmap_to_report
                nmap = map_network(hosts, scope)
                print()
                print(nmap.to_table(color=sys.stdout.isatty()))
                print()
                save = _input("Generate full report? (y/n)", "n")
                if save.lower() == "y":
                    _emit_report(netmap_to_report(nmap))

            elif choice == "5":
                scope = require_scope()
                from .authorization import enforce_target
                host = _input("HTTPS host to check (must be in scope)")
                enforce_target(host, scope)
                port = int(_input("Port", "443"))
                from .tlscheck.checker import check_tls, tls_to_report
                result = check_tls(host, port)
                _emit_report(tls_to_report([result]))

            elif choice == "6":
                from .harden.passwords import audit_password_policy
                _emit_report(audit_password_policy())

            elif choice == "7":
                scope = require_scope()
                domain = _input("Domain you own (must be in scope)")
                from .osint.recon import recon_domain, recon_to_report
                info = recon_domain(domain, scope)
                _emit_report(recon_to_report(info))

            elif choice == "8":
                from .detect.runner import run_detection
                source = _input("Log file path (or 'paste' to enter text)", "paste")
                if source == "paste":
                    print("  Paste log lines (empty line to finish):")
                    lines = []
                    while True:
                        line = input()
                        if not line:
                            break
                        lines.append(line)
                    import tempfile, os
                    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                                     delete=False)
                    tmp.write("\n".join(lines))
                    tmp.close()
                    _emit_report(run_detection(tmp.name))
                    os.unlink(tmp.name)
                else:
                    _emit_report(run_detection(source))

            elif choice == "9":
                from .lab.companion import (
                    list_templates, list_engagements, Engagement, get_template
                )
                print("\n  Templates:", ", ".join(list_templates().keys()))
                print("  Engagements:", ", ".join(list_engagements()) or "(none)")
                action = _input("start/show/note/done", "start")
                if action == "start":
                    name = _input("Engagement name")
                    tmpl = _input("Template", "generic")
                    eng = Engagement(name=name, template=tmpl)
                    eng.save()
                    print(f"  Started '{name}' with template '{tmpl}'.")
                elif action == "show":
                    name = _input("Engagement name")
                    eng = Engagement.load(name)
                    d, t = eng.progress()
                    print(f"\n  Progress: {d}/{t}")
                    current = None
                    for phase, step, done in eng.checklist():
                        if phase != current:
                            print(f"\n    == {phase} ==")
                            current = phase
                        mark = "x" if done else " "
                        print(f"      [{mark}] {step}")
                elif action == "note":
                    name = _input("Engagement name")
                    eng = Engagement.load(name)
                    phase = _input("Phase", "general")
                    text = _input("Note text")
                    eng.add_note(phase, text)
                    eng.save()
                    print("  Note added.")
                elif action == "done":
                    name = _input("Engagement name")
                    eng = Engagement.load(name)
                    step = _input("Step text to mark done")
                    eng.complete_step(step)
                    eng.save()
                    d, t = eng.progress()
                    print(f"  Marked done. Progress: {d}/{t}")

            elif choice == "10":
                from .gui.server import serve
                port = int(_input("Port", "8787"))
                token = _input("Access token (blank for none)", "")
                serve(port=port, token=token or None)

            else:
                print("  Invalid choice. Try again.")

        except AuthorizationError as exc:
            print(f"\n  [AUTH ERROR] {exc}\n")
        except KeyboardInterrupt:
            print("\n  Interrupted. Back to menu.\n")
        except Exception as exc:
            print(f"\n  [ERROR] {type(exc).__name__}: {exc}\n")
