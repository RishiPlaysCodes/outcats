"""outcats - an enterprise-grade DEFENSIVE security platform (authorized use only).

Modules:
    authorize  Attest authorization and declare an in-scope host list.
    guide      Guided intake: tell it what you know (or nothing); it plans next steps.
    harden     CIS/STIG-style hardening audit of a system.
    scan       Read-only service fingerprint + CVE correlation for authorized hosts.
    lab        CTF / practice-lab methodology companion.
    detect     Blue-team log ingestion + detection-rule engine.

outcats performs auditing, reporting, read-only fingerprinting, and detection.
It does NOT perform exploitation, credential attacks, denial-of-service, or
social engineering. Use only on systems you own or are explicitly authorized to
assess, or on intentionally-vulnerable practice labs.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
