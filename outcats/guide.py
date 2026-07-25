"""Guided intake.

Tell outcats what you already know - OS, versions, hosts, or nothing at all -
and it suggests the right next commands. This is a planner/advisor: it never
runs anything against a target on its own, it just points you at the correct
authorized workflow.
"""

from __future__ import annotations

from .authorization import Scope
from .common import system


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val or default


def run_guide() -> None:
    line = "=" * 70
    print(line)
    print(" outcats - guided intake")
    print(line)
    print(
        "Answer what you know. Leave blank if you don't - I'll still guide you.\n"
        "Reminder: outcats only audits/reports and only on authorized targets.\n"
    )

    goal = _ask(
        "What are you trying to do? (harden / scan / learn / detect / not sure)",
        "not sure",
    ).lower()

    info = system.collect()
    print(f"\nDetected local system: {info.distro} ({info.os_system} {info.os_release})")

    plan: list[str] = []

    if goal.startswith("hard") or goal == "not sure":
        plan.append(
            "Harden THIS machine (read-only audit, no changes):\n"
            "    outcats harden --level 2 --format html --out hardening.html"
        )

    if goal.startswith("scan"):
        scope = Scope.load()
        if scope is None:
            plan.append(
                "First authorize + declare scope (one time):\n"
                "    outcats authorize"
            )
        target = _ask("Which host do you want to check? (must be yours/authorized)")
        if target:
            plan.append(
                f"Read-only fingerprint + CVE correlation for {target}:\n"
                f"    outcats scan --target {target} --ports common"
            )
        else:
            plan.append(
                "Read-only self-scan of localhost:\n"
                "    outcats scan --target 127.0.0.1"
            )

    if goal.startswith("learn"):
        plat = _ask("Which practice platform? (HackTheBox / TryHackMe / own VM)",
                    "practice-lab")
        name = _ask("Give this engagement a name", "my-first-box")
        tmpl = _ask("Box type? (generic / web / smb)", "generic")
        plan.append(
            f"Start a guided learning engagement:\n"
            f"    outcats lab start \"{name}\" --template {tmpl} --platform \"{plat}\""
        )
        plan.append("Track progress:  outcats lab show \"%s\"" % name)

    if goal.startswith("detect"):
        logpath = _ask("Path to a log file to analyze", "/var/log/auth.log")
        plan.append(
            f"Run detection rules over your logs:\n"
            f"    outcats detect run --log {logpath} --format html --out alerts.html"
        )

    if not plan:
        plan.append(
            "Not sure where to start? Try a local hardening audit first:\n"
            "    outcats harden"
        )

    print("\nSuggested next steps:")
    print("-" * 70)
    for i, step in enumerate(plan, 1):
        print(f"{i}. {step}\n")
    print("-" * 70)
    print("Nothing was executed. Run the command that fits your authorized goal.")
