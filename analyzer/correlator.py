"""Correlation engine.

This is the heart of the tool: it does not just dump API results next
to packet data, it links PCAP evidence + local detections + threat-intel
results for the same IOC into a single structured Finding, and builds
the chronological investigation timeline used in the report.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from analyzer.detector import Detection, CONFIRMED_MALICIOUS, HIGH_CONFIDENCE_SUSPICIOUS
from analyzer.ioc_extractor import IOC
from analyzer.pcap_parser import ParsedCapture
from feeds.base import FeedResult

# --- Risk scoring -----------------------------------------------------
# A simple, transparent, PROJECT-DEFINED score. It is a prioritization
# aid, not proof of compromise and not an industry-standard methodology.
SCORE_WEIGHTS = {
    "ti_match": 25,            # any single feed reports the indicator
    "ti_match_multi": 20,      # extra weight if 2+ feeds independently match
    "high_confidence_ti": 15,  # a feed reports High confidence
    "suspicious_ua": 10,
    "suspicious_download": 20,
    "suspicious_dns": 10,
    "file_signature": 15,
}


def risk_band(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Informational"


@dataclass
class TimelineEvent:
    timestamp: datetime
    description: str


@dataclass
class Finding:
    finding_id: str
    ioc: str
    ioc_type: str
    severity: str
    confidence: str
    category: str
    risk_score: int
    pcap_evidence: List[str] = field(default_factory=list)
    ti_evidence: List[str] = field(default_factory=list)
    correlation_summary: str = ""
    recommended_action: str = ""


def build_timeline(capture: ParsedCapture) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []
    for rec in capture.dns_records:
        if rec.query and not rec.is_response:
            events.append(TimelineEvent(rec.timestamp, f"DNS query for {rec.query}"))
        if rec.is_response and rec.resolved_ips:
            events.append(TimelineEvent(
                rec.timestamp,
                f"{rec.query or 'Query'} resolved to {', '.join(rec.resolved_ips)}"))
    for rec in capture.http_records:
        if rec.method and rec.path:
            events.append(TimelineEvent(
                rec.timestamp, f"{rec.method} {rec.path} to host {rec.host or rec.dst_ip}"))
        if rec.status_code:
            events.append(TimelineEvent(rec.timestamp, f"HTTP response {rec.status_code}"))
    events.sort(key=lambda e: e.timestamp)
    return events


def correlate(
    capture: ParsedCapture,
    iocs: List[IOC],
    detections: List[Detection],
    ti_results: Dict[str, List[FeedResult]],
) -> List[Finding]:
    """Build one Finding per IOC that has either a local detection or a
    threat-intelligence match attached to it. IOCs with neither are left
    out of the findings list (they still appear in the IOC inventory)."""

    findings: List[Finding] = []
    counter = 0

    detections_by_ioc: Dict[str, List[Detection]] = {}
    for det in detections:
        if det.ioc:
            detections_by_ioc.setdefault(det.ioc, []).append(det)

    for ioc in iocs:
        local_dets = detections_by_ioc.get(ioc.indicator, [])
        feed_results = [r for r in ti_results.get(ioc.indicator, []) if r.available]
        matches = [r for r in feed_results if r.matched]

        if not local_dets and not matches:
            continue  # nothing to correlate — not a finding on its own

        counter += 1
        score = 0
        pcap_evidence = [f"{det.category}: {det.evidence}" for det in local_dets]
        ti_evidence = [f"{r.feed} — {r.summary}" for r in matches]

        if matches:
            score += SCORE_WEIGHTS["ti_match"]
            if len(matches) >= 2:
                score += SCORE_WEIGHTS["ti_match_multi"]
            if any(r.confidence == "High" for r in matches):
                score += SCORE_WEIGHTS["high_confidence_ti"]

        for det in local_dets:
            if det.category == "Suspicious User-Agent":
                score += SCORE_WEIGHTS["suspicious_ua"]
            elif det.category == "Suspicious HTTP Download":
                score += SCORE_WEIGHTS["suspicious_download"]
            elif "DNS" in det.category:
                score += SCORE_WEIGHTS["suspicious_dns"]
            elif det.category == "File Transfer Observed":
                score += SCORE_WEIGHTS["file_signature"]

        score = min(score, 100)
        severity = risk_band(score)

        classification = CONFIRMED_MALICIOUS if matches and any(
            d.classification == HIGH_CONFIDENCE_SUSPICIOUS for d in local_dets
        ) else None
        category = classification or (local_dets[0].category if local_dets else "Threat Intelligence Match")

        if matches and local_dets:
            summary = ("Multiple independent sources — local packet-level detection "
                       "and one or more threat-intelligence feeds — support further "
                       "investigation of this indicator.")
        elif matches:
            summary = ("Threat-intelligence feed(s) flagged this indicator; no local "
                       "detection rule fired for it, so this stands on TI reputation alone.")
        else:
            summary = ("Local detection logic flagged this indicator; no threat-"
                       "intelligence feed had a record for it at the time of the scan.")

        findings.append(Finding(
            finding_id=f"THREAT-{counter:03d}",
            ioc=ioc.indicator,
            ioc_type=ioc.type,
            severity=severity,
            confidence="High" if matches and local_dets else "Medium" if (matches or local_dets) else "Low",
            category=category,
            risk_score=score,
            pcap_evidence=pcap_evidence or ["Indicator observed in capture; see IOC inventory."],
            ti_evidence=ti_evidence or ["No threat-intelligence match available."],
            correlation_summary=summary,
            recommended_action=(
                "Investigate the originating endpoint and search historical network/"
                "security logs for this indicator. Consider blocking confirmed "
                "malicious infrastructure per local policy."
            ),
        ))

    findings.sort(key=lambda f: f.risk_score, reverse=True)
    return findings
