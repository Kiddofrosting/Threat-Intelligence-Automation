"""Rule-based detection engine.

Turns HTTP / DNS / file observations into structured Detection objects
with an explicit reason and a classification. Nothing here is labelled
"malicious" purely on the strength of a local heuristic — that word is
reserved for cases backed by threat-intelligence evidence, added later
by the correlator.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from analyzer.pcap_parser import ParsedCapture
from utils.hashing import hashes_for, identify_signature
from utils.networking import (
    has_suspicious_extension,
    has_suspicious_tld,
    has_suspicious_user_agent,
    looks_dga_like,
)

# Classification ladder, from least to most concerning.
INFORMATIONAL = "Informational"
SUSPICIOUS = "Suspicious"
HIGH_CONFIDENCE_SUSPICIOUS = "High-confidence suspicious"
CONFIRMED_MALICIOUS = "Confirmed malicious"  # reserved for TI-backed findings


@dataclass
class Detection:
    detection_id: str
    timestamp: datetime
    category: str
    classification: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    ioc: Optional[str]
    protocol: str
    evidence: str
    reason: str


def _next_id(counter: List[int]) -> str:
    counter[0] += 1
    return f"DET-{counter[0]:03d}"


def run_detections(capture: ParsedCapture) -> List[Detection]:
    detections: List[Detection] = []
    counter = [0]

    # --- HTTP-based detections ---
    for rec in capture.http_records:
        if rec.user_agent and has_suspicious_user_agent(rec.user_agent):
            detections.append(Detection(
                detection_id=_next_id(counter),
                timestamp=rec.timestamp,
                category="Suspicious User-Agent",
                classification=SUSPICIOUS,
                src_ip=rec.src_ip,
                dst_ip=rec.dst_ip,
                ioc=rec.dst_ip,
                protocol="HTTP",
                evidence=f"User-Agent observed: {rec.user_agent}",
                reason="User-Agent string matches a known command-line / "
                       "scripted HTTP client pattern, which is atypical for "
                       "normal browser traffic.",
            ))

        if rec.path and has_suspicious_extension(rec.path):
            classification = SUSPICIOUS
            reason = "Requested path ends in a file extension commonly " \
                     "associated with executables or scripts."
            if rec.user_agent and has_suspicious_user_agent(rec.user_agent):
                classification = HIGH_CONFIDENCE_SUSPICIOUS
                reason += " This is compounded by a suspicious User-Agent " \
                          "on the same request."
            detections.append(Detection(
                detection_id=_next_id(counter),
                timestamp=rec.timestamp,
                category="Suspicious HTTP Download",
                classification=classification,
                src_ip=rec.src_ip,
                dst_ip=rec.dst_ip,
                ioc=rec.dst_ip,
                protocol="HTTP",
                evidence=f"{rec.method or 'HTTP'} request for {rec.path} "
                         f"(host: {rec.host or 'unknown'})",
                reason=reason,
            ))

    # --- DNS-based detections ---
    for rec in capture.dns_records:
        if not rec.query:
            continue
        if has_suspicious_tld(rec.query):
            detections.append(Detection(
                detection_id=_next_id(counter),
                timestamp=rec.timestamp,
                category="Suspicious DNS Query",
                classification=SUSPICIOUS,
                src_ip=rec.src_ip,
                dst_ip=None,
                ioc=rec.query,
                protocol="DNS",
                evidence=f"DNS query for {rec.query}",
                reason="Queried domain uses a top-level domain that is "
                       "disproportionately associated with abuse in "
                       "public threat reporting. Potentially suspicious "
                       "domain structure.",
            ))
        if looks_dga_like(rec.query):
            detections.append(Detection(
                detection_id=_next_id(counter),
                timestamp=rec.timestamp,
                category="Possible DGA-like Domain",
                classification=SUSPICIOUS,
                src_ip=rec.src_ip,
                dst_ip=None,
                ioc=rec.query,
                protocol="DNS",
                evidence=f"DNS query for {rec.query}",
                reason="The queried label is long and low in vowel "
                       "density, a shape loosely consistent with "
                       "domain-generation-algorithm output. This is a "
                       "heuristic only and can be triggered by legitimate "
                       "randomly-named subdomains.",
            ))

    # --- File-based detections ---
    for f in capture.files:
        digests = hashes_for(f.data)
        signature = identify_signature(f.data)
        detections.append(Detection(
            detection_id=_next_id(counter),
            timestamp=datetime.now().astimezone(),
            category="File Transfer Observed",
            classification=SUSPICIOUS if signature else INFORMATIONAL,
            src_ip=f.src_ip,
            dst_ip=f.dst_ip,
            ioc=digests["sha256"],
            protocol="TCP",
            evidence=f"{f.size}-byte payload transferred, signature: "
                     f"{signature or 'unrecognized'} "
                     f"(SHA256 {digests['sha256'][:16]}...)",
            reason="A file-like payload was reassembled from the raw TCP "
                   "stream. Executable or script signatures on a "
                   "network-transferred file warrant follow-up.",
        ))

    return detections
