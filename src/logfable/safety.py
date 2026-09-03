from __future__ import annotations

import ipaddress
import re
from pathlib import Path

DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
RESERVED_DOC_V4 = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
PRIVATE_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
ALLOWED_REFERENCE_DOMAINS = (
    "mitre.org",
    "github.com",
    "ocsf.io",
    "elastic.co",
    "opentelemetry.io",
    "sigmahq.io",
    "taheramine.org",
)


class SafetyError(ValueError):
    pass


def is_safe_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version == 6:
        return ip in ipaddress.ip_network("2001:db8::/32") or ip.is_private or ip.is_loopback
    return any(ip in network for network in RESERVED_DOC_V4 + PRIVATE_V4) or ip.is_loopback


def unsafe_indicators(text: str) -> list[str]:
    findings: list[str] = []
    for match in IP_RE.findall(text):
        if not is_safe_ip(match):
            findings.append(f"unsafe-ip:{match}")
    for domain in DOMAIN_RE.findall(text):
        normalized = domain.lower().rstrip(".")
        if normalized.endswith(".example") or normalized in {
            "example.com",
            "example.net",
            "example.org",
        }:
            continue
        if not any(
            normalized == suffix or normalized.endswith(f".{suffix}")
            for suffix in ALLOWED_REFERENCE_DOMAINS
        ):
            findings.append(f"live-domain:{domain}")
    return sorted(set(findings))


def safe_child(root: Path, requested: Path) -> Path:
    resolved_root = root.resolve()
    target = requested.resolve()
    if resolved_root != target and resolved_root not in target.parents:
        raise SafetyError("path escapes permitted root")
    return target


def reject_symlink_tree(path: Path) -> None:
    for candidate in path.rglob("*"):
        if candidate.is_symlink():
            raise SafetyError(f"symlink not allowed: {candidate}")


def sanitize_terminal(text: str) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x1b]", "?", text)
