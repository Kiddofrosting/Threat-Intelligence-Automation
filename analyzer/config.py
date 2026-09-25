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
        "rare_domain_occurrence_threshold": 2,
        "tunneling_min_subdomains": 8,
        "tunneling_avg_label_length_threshold": 30,
        "tunneling_txt_null_ratio_threshold": 0.3,
        "fastflux_min_distinct_ips": 4,
        "fastflux_window_seconds": 600,
        "newly_observed_enabled": True,
        "custom_public_suffixes": [],
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
        "executable_mime_types": [
            "application/x-msdownload", "application/octet-stream",
            "application/x-executable", "application/vnd.microsoft.portable-executable",
            "application/x-dosexec",
        ],
        "benign_mime_prefixes": ["text/", "image/", "application/json", "application/xml"],
        "web_attack_min_repetitions": 3,
    },
    "ti": {
        "abuseipdb": {"malicious_score": 75, "suspicious_score": 25, "stale_after_days": 365},
        "virustotal": {"malicious_vendor_count": 5, "weak_single_hit_min_total": 30},
        "urlhaus": {"stale_after_days": 730},
    },
    "network": {
        "port_scan_min_distinct_ports": 15,
        "port_scan_max_success_ratio": 0.2,
        "host_scan_min_distinct_ips": 10,
        "host_scan_max_success_ratio": 0.2,
        "auth_port_min_attempts": 5,
        "auth_port_max_success_ratio": 0.3,
        "exfil_min_outbound_bytes": 200000,
        "exfil_min_outbound_ratio": 5.0,
    },
    "beaconing": {
        "min_occurrences": 5,
        "max_coefficient_of_variation": 0.35,
    },
    "risk": {
        "weights": {
            "reputation": 30, "behavior": 30, "payload": 20,
            "network_context": 10, "asset_context": 10,
        },
        "severity_bands": {"Critical": 85, "High": 65, "Medium": 40, "Low": 20},
        "caps": {"behavior_only_max_severity": "Medium"},
        "asset_criticality_weights": {
            "Unknown": 0, "Low": 2, "Medium": 4, "High": 7, "Critical": 10,
        },
        # Evidence-family caps within the Behavior dimension: multiple
        # signals of the SAME category (e.g. three DNS rules all firing
        # for the same beaconing domain) are capped per-category before
        # being summed, so restating one underlying behavior three ways
        # doesn't triple its weight. The category sum is still subject
        # to the overall "behavior" weight cap above.
        "category_caps": {
            "DNS": 14, "HTTP": 14, "File": 16, "Network": 14, "Behavioral": 10,
        },
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
