"""Local system fingerprinting helpers (read-only)."""

from __future__ import annotations

import platform
import shutil
import socket
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class SystemInfo:
    hostname: str
    os_system: str
    os_release: str
    os_version: str
    architecture: str
    python_version: str
    kernel: str
    distro: str

    def as_dict(self) -> dict:
        return asdict(self)


def _read_os_release() -> dict[str, str]:
    """Parse /etc/os-release on Linux (best-effort)."""
    data: dict[str, str] = {}
    path = Path("/etc/os-release")
    if path.exists():
        for raw in path.read_text().splitlines():
            if "=" in raw:
                key, _, value = raw.partition("=")
                data[key.strip()] = value.strip().strip('"')
    return data


def detect_distro() -> str:
    rel = _read_os_release()
    pretty = rel.get("PRETTY_NAME")
    if pretty:
        return pretty
    name = rel.get("NAME", "")
    version = rel.get("VERSION", "")
    combined = f"{name} {version}".strip()
    return combined or platform.platform()


def collect() -> SystemInfo:
    """Collect a read-only fingerprint of the local system."""
    uname = platform.uname()
    return SystemInfo(
        hostname=socket.gethostname(),
        os_system=uname.system,
        os_release=uname.release,
        os_version=uname.version,
        architecture=uname.machine,
        python_version=platform.python_version(),
        kernel=uname.release,
        distro=detect_distro(),
    )


def which(binary: str) -> str | None:
    """Return the resolved path of an executable, or None."""
    return shutil.which(binary)
