"""Central configuration for detection thresholds, risk weights and
severity bands.

Values are loaded from config/detection_config.yaml when the file is
present and parses cleanly; DEFAULT_CONFIG is used otherwise, so a
missing or malformed config file never crashes a run -- it just falls
back to the shipped defaults. This is the single place thresholds
live; the detection engine, correlator and reporter all read from the
dict this module returns rather than hardcoding numbers.
"""

import os
from typing import Any, Dict

import yaml

DEFAULT_CONFIG: Dict[str, Any] = {
    "dns": {
        "dga_min_label_length": 8,
        "dga_flag_threshold": 30,
        "excessive_query_threshold": 8,
        "nxdomain_ratio_threshold": 0.5,
        "nxdomain_min_occurrences": 4,
        "excessive_subdomain_threshold": 6,
    },
    "http": {
        "suspicious_extensions": [
            ".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".jar",
            ".hta", ".cpl", ".msi",
        ],
        "script_extensions": [".ps1", ".vbs", ".js", ".bat", ".hta"],
        "suspicious_user_agents": [
            "curl", "wget", "python-requests", "powershell", "certutil",
            "bitsadmin", "python-urllib", "go-http-client", "libwww-perl",
            "nikto", "masscan", "nmap",
        ],
        "rare_host_occurrence_threshold": 2,
        "repeated_payload_threshold": 3,
    },
    "ti": {
        "abuseipdb": {"malicious_score": 75, "suspicious_score": 25, "stale_after_days": 365},
        "virustotal": {"malicious_vendor_count": 5, "weak_single_hit_min_total": 30},
        "urlhaus": {"stale_after_days": 730},
    },
    "risk": {
        "weights": {
            "reputation": 30, "behavior": 30, "payload": 20,
            "network_context": 10, "asset_context": 10,
        },
        "severity_bands": {"Critical": 85, "High": 65, "Medium": 40, "Low": 20},
        "caps": {"behavior_only_max_severity": "Medium"},
    },
    "correlation": {
        "time_window_seconds": 900,
        "dedup_time_bucket_seconds": 3600,
    },
}

_SEVERITY_RANK = ["Informational", "Low", "Medium", "High", "Critical"]


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str = "config/detection_config.yaml") -> Dict[str, Any]:
    if not os.path.exists(path):
        return DEFAULT_CONFIG
    try:
        with open(path, "r", encoding="utf-8") as fh:
            override = yaml.safe_load(fh) or {}
    except Exception:
        return DEFAULT_CONFIG
    return _deep_merge(DEFAULT_CONFIG, override)


def severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_RANK.index(severity)
    except ValueError:
        return 0


def min_severity(a: str, b: str) -> str:
    """Return whichever of a/b ranks lower -- used to apply a severity cap."""
    return a if severity_rank(a) <= severity_rank(b) else b


def band_from_score(score: int, bands: Dict[str, int]) -> str:
    if score >= bands.get("Critical", 85):
        return "Critical"
    if score >= bands.get("High", 65):
        return "High"
    if score >= bands.get("Medium", 40):
        return "Medium"
    if score >= bands.get("Low", 20):
        return "Low"
    return "Informational"
