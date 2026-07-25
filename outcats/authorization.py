"""Authorization gate and scope management.

Before any scanning command runs, the operator must attest that the targets are
owned or that written authorization exists, and must declare an explicit host
scope. Targets outside the declared scope are refused. This keeps the platform
firmly on the defensive/authorized side of the line.
"""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

CONFIG_DIR = Path.home() / ".outcats"
SCOPE_FILE = CONFIG_DIR / "scope.json"

# The local machine is always allowed.
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class AuthorizationError(PermissionError):
    """Raised when an action is attempted outside the authorized scope."""


@dataclass
class Scope:
    operator: str
    authorization_ref: str
    attested_at: float
    allowed_hosts: list[str] = field(default_factory=list)
    lab_mode: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def load(cls) -> "Scope | None":
        if not SCOPE_FILE.exists():
            return None
        try:
            data = json.loads(SCOPE_FILE.read_text())
            return cls(**data)
        except (json.JSONDecodeError, TypeError):
            return None

    def save(self) -> Path:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SCOPE_FILE.write_text(self.to_json())
        return SCOPE_FILE


def _normalize(host: str) -> str:
    return host.strip().lower()


def is_in_scope(host: str, scope: Scope) -> bool:
    """Return True if `host` falls within the authorized scope."""
    host = _normalize(host)
    if host in LOOPBACK:
        return True
    for raw in scope.allowed_hosts:
        entry = _normalize(raw)
        if host == entry:
            return True
        try:
            if "/" in entry and ipaddress.ip_address(host) in ipaddress.ip_network(
                entry, strict=False
            ):
                return True
        except ValueError:
            continue
    return False


def require_scope() -> Scope:
    scope = Scope.load()
    if scope is None:
        raise AuthorizationError(
            "No authorization scope found. Run `outcats authorize` first to attest "
            "ownership/authorization and declare which hosts you may assess."
        )
    return scope


def enforce_target(host: str, scope: Scope) -> None:
    """Raise if `host` is not authorized. Call before touching any remote target."""
    if not is_in_scope(host, scope):
        raise AuthorizationError(
            f"Target '{host}' is NOT in your authorized scope.\n"
            f"Authorized: {', '.join(scope.allowed_hosts) or '(localhost only)'}\n"
            "Refusing to proceed. Re-run `outcats authorize` to update your scope "
            "only for hosts you own or are permitted to assess."
        )


def interactive_authorize() -> Scope:
    """Walk the operator through attesting authorization and setting scope."""
    line = "=" * 70
    print(line)
    print(" outcats - authorization")
    print(line)
    print(
        "This platform AUDITS and REPORTS. It performs NO exploitation, no\n"
        "credential attacks, no denial-of-service, and no social engineering.\n\n"
        "Run it ONLY against systems you OWN or are EXPLICITLY AUTHORIZED (in\n"
        "writing) to assess, or against intentionally-vulnerable practice labs\n"
        "(HackTheBox, TryHackMe, your own VMs).\n"
    )
    operator = input("Your name / handle: ").strip() or "operator"

    print(
        "\nAuthorization basis. Examples:\n"
        "  - 'I own these hosts'\n"
        "  - 'Engagement TICKET-1234, signed SOW on file'\n"
        "  - 'Personal HackTheBox / TryHackMe lab'\n"
    )
    auth_ref = input("Authorization reference: ").strip()
    if not auth_ref:
        raise AuthorizationError("Authorization reference is required. Aborting.")

    confirm = (
        input("\nType 'I AGREE' to confirm you are authorized: ").strip().upper()
    )
    if confirm != "I AGREE":
        raise AuthorizationError("Authorization not confirmed. Aborting.")

    lab = (
        input("\nIs this an intentionally-vulnerable practice lab? [y/N]: ")
        .strip()
        .lower()
        == "y"
    )

    print(
        "\nDeclare in-scope hosts (comma-separated). Accepts hostnames, IPs, and\n"
        "CIDR ranges you own, e.g.  10.0.0.0/24, 192.168.1.10, myserver.local\n"
        "(localhost is always allowed)."
    )
    raw = input("In-scope hosts: ").strip()
    hosts = [h.strip() for h in raw.split(",") if h.strip()]

    scope = Scope(
        operator=operator,
        authorization_ref=auth_ref,
        attested_at=time.time(),
        allowed_hosts=hosts,
        lab_mode=lab,
    )
    path = scope.save()
    print(f"\nScope saved to {path}")
    print("Allowed hosts:", ", ".join(hosts) if hosts else "(localhost only)")
    return scope
