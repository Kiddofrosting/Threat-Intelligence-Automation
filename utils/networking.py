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
