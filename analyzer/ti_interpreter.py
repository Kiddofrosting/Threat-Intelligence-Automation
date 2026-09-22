"""Feed-specific interpretation of raw threat-intelligence results.

A raw FeedResult tells you what a provider returned. It does not by
itself tell you whether that is a meaningful finding: an AbuseIPDB
score of 0, a single VirusTotal vendor hit out of 90, and "no URLhaus
record found" are all, on their own, non-events. This module maps
each feed's own scoring model onto one shared vocabulary --
CLEAN / UNKNOWN / WEAK_REPUTATION / SUSPICIOUS / MALICIOUS -- so the
rest of the pipeline can reason about TI evidence consistently
without re-deriving feed-specific thresholds everywhere.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from feeds.base import FeedResult

CLEAN = "CLEAN"
UNKNOWN = "UNKNOWN"
WEAK_REPUTATION = "WEAK_REPUTATION"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS = "MALICIOUS"

STATE_ORDER = [UNKNOWN, CLEAN, WEAK_REPUTATION, SUSPICIOUS, MALICIOUS]

# Contribution to the Reputation risk dimension (capped at 30 overall
# in correlator.py) for a single feed's assessment at this state.
STATE_WEIGHT = {
    UNKNOWN: 0,
    CLEAN: 0,
    WEAK_REPUTATION: 6,
    SUSPICIOUS: 16,
    MALICIOUS: 28,
}


@dataclass
class TIAssessment:
    feed: str
    indicator: str
    state: str
    confidence: str  # confidence in *this assessment*, independent of the indicator's severity
    summary: str
    weight: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_meaningful(self) -> bool:
        return self.state in (SUSPICIOUS, MALICIOUS)


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    normalized = ts.replace("Z", "+0000")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(normalized, fmt)
        except Exception:
            continue
    return None


def _age_days(ts: Optional[str]) -> Optional[int]:
    dt = _parse_iso(ts)
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def _interpret_abuseipdb(result: FeedResult, config: dict) -> TIAssessment:
    raw = result.raw or {}
    score = raw.get("abuseConfidenceScore", 0) or 0
    reports = raw.get("totalReports", 0) or 0
    age_days = _age_days(raw.get("lastReportedAt"))
    cfg = config.get("abuseipdb", {})
    malicious_threshold = cfg.get("malicious_score", 75)
    suspicious_threshold = cfg.get("suspicious_score", 25)
    stale_days = cfg.get("stale_after_days", 365)

    if score == 0 and reports == 0:
        state, conf = CLEAN, "High"
    elif score < suspicious_threshold:
        state, conf = WEAK_REPUTATION, "Low"
    elif score < malicious_threshold:
        state, conf = (SUSPICIOUS, "Medium") if reports >= 3 else (WEAK_REPUTATION, "Low")
    else:
        state, conf = MALICIOUS, "High"

    if state == MALICIOUS and age_days is not None and age_days > stale_days:
        state, conf = SUSPICIOUS, "Medium"

    recency = f", last reported {age_days}d ago" if age_days is not None else ", no reported date on file"
    summary = (f"AbuseIPDB abuse confidence {score}/100 from {reports} report(s){recency}. "
               f"Interpreted as {state.replace('_', ' ').title()}.")
    return TIAssessment("AbuseIPDB", result.indicator, state, conf, summary,
                         weight=STATE_WEIGHT[state], raw=raw)


def _interpret_virustotal(result: FeedResult, config: dict) -> TIAssessment:
    raw = result.raw or {}
    stats = raw.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0) or 0
    suspicious = stats.get("suspicious", 0) or 0
    total = sum(stats.values()) if stats else 0
    cfg = config.get("virustotal", {})
    malicious_vendors = cfg.get("malicious_vendor_count", 5)
    weak_single_hit_total = cfg.get("weak_single_hit_min_total", 30)

    if total == 0:
        state, conf = UNKNOWN, "Low"
    elif malicious == 0 and suspicious == 0:
        state, conf = CLEAN, "High"
    elif malicious == 0 and suspicious > 0:
        state, conf = (SUSPICIOUS, "Medium") if suspicious >= 3 else (WEAK_REPUTATION, "Low")
    elif malicious == 1 and total >= weak_single_hit_total:
        # A single AV hit out of many is exactly the false-positive-prone
        # case the brief calls out (1/89 != 40/89) -- weak, not a verdict.
        state, conf = WEAK_REPUTATION, "Low"
    elif malicious < malicious_vendors:
        state, conf = SUSPICIOUS, "Medium"
    else:
        state, conf = MALICIOUS, "High"

    ratio = f"{malicious}/{total}" if total else "0/0"
    summary = (f"VirusTotal: {ratio} vendor(s) flagged malicious, {suspicious} suspicious. "
               f"Interpreted as {state.replace('_', ' ').title()}.")
    return TIAssessment("VirusTotal", result.indicator, state, conf, summary,
                         weight=STATE_WEIGHT[state], raw=raw)


def _interpret_urlhaus(result: FeedResult, config: dict) -> TIAssessment:
    raw = result.raw or {}
    if not result.matched:
        return TIAssessment("URLhaus", result.indicator, UNKNOWN, "Low",
                             "No URLhaus record found for this indicator.", weight=0, raw=raw)

    cfg = config.get("urlhaus", {})
    stale_days = cfg.get("stale_after_days", 730)
    age_days = _age_days(raw.get("date_added"))
    status = (raw.get("url_status") or "").lower()

    if status == "online":
        state, conf = MALICIOUS, "High"
    elif age_days is not None and age_days > stale_days:
        state, conf = SUSPICIOUS, "Medium"
    else:
        # Confirmed record, offline or status unknown, and not stale --
        # URLhaus only lists confirmed malware-distribution infrastructure,
        # so this still counts as malicious, at slightly lower confidence
        # than a currently-online listing.
        state, conf = MALICIOUS, "Medium"

    threat_types = ", ".join(raw.get("threat_types") or []) or "unspecified"
    summary = (f"URLhaus record found (status: {status or 'unknown'}, threat: {threat_types}). "
               f"Interpreted as {state.replace('_', ' ').title()}.")
    return TIAssessment("URLhaus", result.indicator, state, conf, summary,
                         weight=STATE_WEIGHT[state], raw=raw)


_INTERPRETERS = {
    "AbuseIPDB": _interpret_abuseipdb,
    "VirusTotal": _interpret_virustotal,
    "URLhaus": _interpret_urlhaus,
}


def interpret(result: FeedResult, config: Optional[dict] = None) -> TIAssessment:
    """Translate one raw FeedResult into a feed-aware TIAssessment."""
    cfg = (config or {}).get("ti", {}) if config else {}
    if not result.available:
        return TIAssessment(result.feed, result.indicator, UNKNOWN, "Low",
                             f"{result.feed} lookup was unavailable at scan time "
                             f"(not a clean verdict).", weight=0, raw={})
    fn = _INTERPRETERS.get(result.feed)
    if not fn:
        state = SUSPICIOUS if result.matched else UNKNOWN
        return TIAssessment(result.feed, result.indicator, state, "Low",
                             result.summary, weight=STATE_WEIGHT[state], raw=result.raw or {})
    return fn(result, cfg)
