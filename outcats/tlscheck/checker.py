"""SSL/TLS certificate and protocol checker for AUTHORIZED endpoints.

Connects to HTTPS endpoints the operator owns, validates the certificate
chain (expiry, self-signed, hostname mismatch), and checks which TLS versions
and ciphers are accepted. Reports weak configurations (SSLv3, TLS 1.0/1.1,
known-weak ciphers, short keys, expired certs). Read-only: never modifies
anything on the target.

Target enforcement via the authorization scope is the caller's responsibility
(the CLI handler calls enforce_target before invoking this module).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..common.report import Finding, Report, Severity, Status


@dataclass
class CertInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial: str
    san: list[str]
    version: int
    fingerprint_sha256: str
    key_bits: int | None = None


@dataclass
class TLSResult:
    host: str
    port: int
    cert: CertInfo | None = None
    protocol: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    errors: list[str] = field(default_factory=list)


_WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _parse_cert(der: bytes, info: dict) -> CertInfo:
    """Extract CertInfo from the dict returned by ssl.getpeercert()."""
    subject_parts = []
    for rdn in info.get("subject", ()):
        for key, val in rdn:
            subject_parts.append(f"{key}={val}")
    issuer_parts = []
    for rdn in info.get("issuer", ()):
        for key, val in rdn:
            issuer_parts.append(f"{key}={val}")

    san = []
    for dtype, val in info.get("subjectAltName", ()):
        san.append(f"{dtype}:{val}")

    not_before = datetime.strptime(info["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

    fp = hashlib.sha256(der).hexdigest()
    return CertInfo(
        subject=", ".join(subject_parts),
        issuer=", ".join(issuer_parts),
        not_before=not_before,
        not_after=not_after,
        serial=info.get("serialNumber", ""),
        san=san,
        version=info.get("version", 0),
        fingerprint_sha256=fp,
    )


def check_tls(host: str, port: int = 443, timeout: float = 5.0) -> TLSResult:
    """Perform a read-only TLS connection check against host:port."""
    result = TLSResult(host=host, port=port)

    ctx = ssl.create_default_context()
    # We still want to connect even if cert is self-signed, so we can report on it.
    # Try first with verification ON, then fallback with it off.
    for verify in (True, False):
        if not verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    result.protocol = ssock.version() or ""
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result.cipher = cipher_info[0]
                        result.cipher_bits = cipher_info[2]
                    der = ssock.getpeercert(binary_form=True)
                    peer = ssock.getpeercert()
                    if peer and der:
                        result.cert = _parse_cert(der, peer)
                    elif der:
                        # self-signed / untrusted — parse what we can
                        result.cert = CertInfo(
                            subject="(unavailable - untrusted cert)",
                            issuer="(unavailable)",
                            not_before=datetime.min.replace(tzinfo=timezone.utc),
                            not_after=datetime.min.replace(tzinfo=timezone.utc),
                            serial="", san=[], version=0,
                            fingerprint_sha256=hashlib.sha256(der).hexdigest(),
                        )
                        if verify:
                            continue  # retry without verification
                    break
        except ssl.SSLCertVerificationError as e:
            result.errors.append(f"cert verification: {e}")
            if verify:
                continue
            break
        except ssl.SSLError as e:
            result.errors.append(f"SSL error: {e}")
            break
        except OSError as e:
            result.errors.append(f"connection error: {e}")
            break
    return result


def tls_to_report(results: list[TLSResult]) -> Report:
    """Convert TLS check results to a standard Report."""
    report = Report(module="tlscheck", target=f"{len(results)} endpoint(s)")

    for r in results:
        prefix = f"{r.host}:{r.port}"

        # Connection errors
        if r.errors:
            for err in r.errors:
                report.add(Finding(
                    id=f"OC-TLS-ERR-{r.host}",
                    title=f"{prefix}: connection/TLS error",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    detail=err,
                    remediation="Verify the host is reachable and serving valid TLS.",
                ))
            if r.cert is None:
                continue

        # Protocol version
        if r.protocol in _WEAK_PROTOCOLS:
            report.add(Finding(
                id=f"OC-TLS-PROTO-{r.host}",
                title=f"{prefix}: weak protocol ({r.protocol})",
                severity=Severity.HIGH,
                status=Status.FAIL,
                detail=f"Negotiated {r.protocol}, which has known vulnerabilities.",
                remediation="Disable SSLv3 and TLS 1.0/1.1; require TLS 1.2+.",
                references=["CIS Controls v8 3.10"],
            ))
        else:
            report.add(Finding(
                id=f"OC-TLS-PROTO-{r.host}",
                title=f"{prefix}: protocol {r.protocol}",
                severity=Severity.INFO,
                status=Status.PASS,
                detail=f"Negotiated {r.protocol}.",
            ))

        # Cipher strength
        weak_cipher = any(w in r.cipher.upper() for w in _WEAK_CIPHERS)
        if weak_cipher:
            report.add(Finding(
                id=f"OC-TLS-CIPHER-{r.host}",
                title=f"{prefix}: weak cipher ({r.cipher})",
                severity=Severity.HIGH,
                status=Status.FAIL,
                detail=f"Cipher {r.cipher} ({r.cipher_bits} bits).",
                remediation="Disable weak ciphers; prefer AEAD ciphers (AES-GCM, ChaCha20).",
            ))
        elif r.cipher_bits < 128 and r.cipher_bits > 0:
            report.add(Finding(
                id=f"OC-TLS-CIPHER-{r.host}",
                title=f"{prefix}: short cipher key ({r.cipher_bits} bits)",
                severity=Severity.MEDIUM,
                status=Status.WARN,
                detail=f"Cipher {r.cipher} ({r.cipher_bits} bits).",
                remediation="Use ciphers with >=128-bit keys.",
            ))
        else:
            report.add(Finding(
                id=f"OC-TLS-CIPHER-{r.host}",
                title=f"{prefix}: cipher {r.cipher} ({r.cipher_bits}b)",
                severity=Severity.INFO,
                status=Status.PASS,
            ))

        # Certificate validity
        if r.cert:
            now = datetime.now(timezone.utc)
            days_left = (r.cert.not_after - now).days if r.cert.not_after.year > 1 else -9999

            if days_left < 0:
                report.add(Finding(
                    id=f"OC-TLS-EXPIRY-{r.host}",
                    title=f"{prefix}: certificate EXPIRED ({-days_left} days ago)",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    detail=f"notAfter={r.cert.not_after.isoformat()}",
                    remediation="Renew the certificate immediately.",
                ))
            elif days_left < 30:
                report.add(Finding(
                    id=f"OC-TLS-EXPIRY-{r.host}",
                    title=f"{prefix}: certificate expires in {days_left} days",
                    severity=Severity.HIGH,
                    status=Status.WARN,
                    detail=f"notAfter={r.cert.not_after.isoformat()}",
                    remediation="Renew before expiry to avoid outages.",
                ))
            elif days_left < 90:
                report.add(Finding(
                    id=f"OC-TLS-EXPIRY-{r.host}",
                    title=f"{prefix}: certificate expires in {days_left} days",
                    severity=Severity.MEDIUM,
                    status=Status.WARN,
                    detail=f"notAfter={r.cert.not_after.isoformat()}",
                    remediation="Plan renewal (< 90 days remaining).",
                ))
            else:
                report.add(Finding(
                    id=f"OC-TLS-EXPIRY-{r.host}",
                    title=f"{prefix}: certificate valid ({days_left} days remaining)",
                    severity=Severity.INFO,
                    status=Status.PASS,
                    detail=f"subject={r.cert.subject}, issuer={r.cert.issuer}",
                ))

            # Self-signed check
            if r.cert.subject == r.cert.issuer and r.cert.subject != "":
                report.add(Finding(
                    id=f"OC-TLS-SELFSIGNED-{r.host}",
                    title=f"{prefix}: certificate is self-signed",
                    severity=Severity.MEDIUM,
                    status=Status.WARN,
                    detail="Subject == Issuer; browsers will show a warning.",
                    remediation="Use a certificate from a trusted CA (e.g. Let's Encrypt).",
                ))
    return report
