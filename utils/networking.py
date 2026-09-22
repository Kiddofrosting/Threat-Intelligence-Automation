"""Small helpers for classifying and cleaning up network addresses."""

import ipaddress
from typing import Optional


def is_useful_ip(ip: str) -> bool:
    """Return False for addresses that make poor IOCs (private, loopback,
    link-local, multicast, reserved, broadcast, unspecified)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    if ip == "255.255.255.255":
        return False
    return True


def ip_version(ip: str) -> Optional[int]:
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


# User-Agent substrings commonly associated with scripted / command-line
# tooling. A match is a signal to look closer, not proof of malice.
SUSPICIOUS_USER_AGENT_MARKERS = [
    "curl", "wget", "python-requests", "powershell", "certutil",
    "bitsadmin", "python-urllib", "go-http-client", "libwww-perl",
    "nikto", "masscan", "nmap",
]

# Extensions of files that are worth flagging when seen in an HTTP path.
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".jar",
    ".hta", ".cpl", ".msi",
]

SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".click", ".gq", ".tk", ".ml", ".cf", ".ga", ".icu",
]


def has_suspicious_user_agent(user_agent: str) -> bool:
    if not user_agent:
        return False
    ua = user_agent.lower()
    return any(marker in ua for marker in SUSPICIOUS_USER_AGENT_MARKERS)


def has_suspicious_extension(path: str) -> bool:
    if not path:
        return False
    lowered = path.lower().split("?")[0]
    return any(lowered.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)


def has_suspicious_tld(domain: str) -> bool:
    if not domain:
        return False
    lowered = domain.lower()
    return any(lowered.endswith(tld) for tld in SUSPICIOUS_TLDS)


def looks_dga_like(domain: str) -> bool:
    """Very rough heuristic: long, high-entropy-looking subdomain labels
    with few vowels are the kind of thing a domain-generation algorithm
    produces. This is a hint for an analyst, not a verdict."""
    if not domain:
        return False
    label = domain.split(".")[0]
    if len(label) < 12:
        return False
    vowels = sum(1 for c in label.lower() if c in "aeiou")
    return vowels / max(len(label), 1) < 0.25
