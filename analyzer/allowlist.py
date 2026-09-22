"""Configurable allowlist / suppression framework.

Matching an allowlist entry never destroys evidence: a suppressed
detection signal is kept (with `suppressed=True` and a
`suppression_reason` recording which rule and which allowlist entry
matched) so it remains visible in the technical appendix and the rule
tuning report, but it is excluded from correlated findings and risk
scoring.
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import yaml

DEFAULT_ALLOWLIST: Dict[str, List[str]] = {
    "domains": [
        "microsoft.com", "windowsupdate.com", "msftconnecttest.com",
        "akamai.net", "akamaiedge.net", "akadns.net",
        "googleapis.com", "google.com", "gstatic.com",
        "cloudflare.com", "cloudfront.net",
        "amazonaws.com", "azureedge.net", "azure.com",
        "apple.com", "icloud.com",
    ],
    "ips": [],
    "user_agents": [],
    "internal_hosts": [],
}


@dataclass
class SuppressionMatch:
    matched: bool
    reason: Optional[str] = None
    matched_entry: Optional[str] = None


def load_allowlist(path: str = "config/allowlist.yaml") -> Dict[str, List[str]]:
    if not os.path.exists(path):
        return {k: list(v) for k, v in DEFAULT_ALLOWLIST.items()}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return {k: list(v) for k, v in DEFAULT_ALLOWLIST.items()}
    merged = {k: list(v) for k, v in DEFAULT_ALLOWLIST.items()}
    for key in merged:
        extra = data.get(key) or []
        for entry in extra:
            if entry not in merged[key]:
                merged[key].append(entry)
    return merged


def check_domain(domain: Optional[str], allowlist: Dict[str, List[str]]) -> SuppressionMatch:
    if not domain:
        return SuppressionMatch(False)
    lowered = domain.lower().rstrip(".")
    for entry in allowlist.get("domains", []):
        entry_l = entry.lower()
        if lowered == entry_l or lowered.endswith("." + entry_l):
            return SuppressionMatch(True, "known_legitimate_infrastructure", entry)
    return SuppressionMatch(False)


def check_ip(ip: Optional[str], allowlist: Dict[str, List[str]]) -> SuppressionMatch:
    if not ip:
        return SuppressionMatch(False)
    for entry in allowlist.get("ips", []):
        if ip == entry:
            return SuppressionMatch(True, "known_legitimate_infrastructure", entry)
    return SuppressionMatch(False)


def check_user_agent(user_agent: Optional[str], allowlist: Dict[str, List[str]]) -> SuppressionMatch:
    if not user_agent:
        return SuppressionMatch(False)
    lowered = user_agent.lower()
    for entry in allowlist.get("user_agents", []):
        if entry.lower() in lowered:
            return SuppressionMatch(True, "approved_user_agent", entry)
    return SuppressionMatch(False)


def is_trusted_internal_host(ip: Optional[str], allowlist: Dict[str, List[str]]) -> bool:
    if not ip:
        return False
    return ip in set(allowlist.get("internal_hosts", []))
