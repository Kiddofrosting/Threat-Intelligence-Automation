"""Rule-based detection engine.

Every rule here evaluates an aggregated BehavioralEvent (see
analyzer/aggregator.py), never a raw packet or a single DNS query --
that is what stops one repeated query from producing one detection
per occurrence. Each rule produces at most one DetectionSignal per
behavioral event, carrying the occurrence count and first/last-seen
timestamps of everything it summarizes.

Nothing here is labelled "malicious": that word is reserved for
findings backed by threat-intelligence evidence, assigned later by
the correlator. A rule that matches a known-legitimate allowlist
entry still produces its signal (so it stays visible for tuning) but
is marked `suppressed=True` and excluded from correlation/risk
scoring.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from analyzer.aggregator import AggregationResult, DNSBehavior, FileBehavior, HTTPBehavior
from analyzer.allowlist import check_domain, check_ip, check_user_agent
from analyzer.config import DEFAULT_CONFIG
from analyzer.dga import score_domain

INFORMATIONAL = "Informational"
LOW = "Low"
MEDIUM = "Medium"
HIGH = "High"


@dataclass
class DetectionSignal:
    rule_id: str
    title: str
    category: str              # DNS / HTTP / File
    severity: str              # this signal's own inherent ceiling -- not the finding's severity
    confidence: str
    score: int                 # contribution to the Behavior risk dimension
    indicator: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    evidence: List[str]
    explanation: str
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    suppression_entry: Optional[str] = None


def _apex_domain(domain: str) -> str:
    """Best-effort registrable-domain approximation (last two labels).
    Good enough for grouping subdomains under the same apex without a
    public-suffix-list dependency; not authoritative for multi-part
    TLDs like .co.uk."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _detect_dns(dns_events: List[DNSBehavior], config: dict, allowlist: dict) -> List[DetectionSignal]:
    signals: List[DetectionSignal] = []
    cfg = config["dns"]

    by_apex: Dict[str, List[DNSBehavior]] = {}
    for ev in dns_events:
        by_apex.setdefault(_apex_domain(ev.domain), []).append(ev)

    for ev in dns_events:
        suppression = check_domain(ev.domain, allowlist)

        # DNS-001: Excessive DNS Frequency
        if ev.occurrence_count >= cfg["excessive_query_threshold"]:
            signals.append(DetectionSignal(
                rule_id="DNS-001", title="Excessive DNS Frequency", category="DNS",
                severity=LOW, confidence="Medium", score=6,
                indicator=ev.domain, source_ip=ev.source_ip, destination_ip=None,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=ev.occurrence_count,
                evidence=[f"{ev.source_ip} queried {ev.domain} ({ev.query_type}) "
                          f"{ev.occurrence_count} time(s) between {ev.first_seen.strftime('%H:%M:%S')} "
                          f"and {ev.last_seen.strftime('%H:%M:%S')}."],
                explanation=(f"{ev.source_ip} issued {ev.occurrence_count} DNS queries for "
                             f"{ev.domain} within a {ev.duration_seconds:.0f}-second window, "
                             f"exceeding the configured threshold of {cfg['excessive_query_threshold']}. "
                             f"High query volume alone can be legitimate (polling, retries, short TTLs) "
                             f"and is treated as a behavioral signal, not a verdict."),
                suppressed=suppression.matched, suppression_reason=suppression.reason,
                suppression_entry=suppression.matched_entry,
            ))

        # DNS-002: High NXDOMAIN Ratio
        if (ev.occurrence_count >= cfg["nxdomain_min_occurrences"]
                and ev.nxdomain_ratio >= cfg["nxdomain_ratio_threshold"]):
            signals.append(DetectionSignal(
                rule_id="DNS-002", title="High NXDOMAIN Ratio", category="DNS",
                severity=MEDIUM, confidence="Medium", score=10,
                indicator=ev.domain, source_ip=ev.source_ip, destination_ip=None,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=ev.occurrence_count,
                evidence=[f"{ev.nxdomain_count}/{ev.occurrence_count} queries for {ev.domain} "
                          f"from {ev.source_ip} resolved NXDOMAIN ({ev.nxdomain_ratio:.0%})."],
                explanation=(f"{ev.nxdomain_ratio:.0%} of {ev.occurrence_count} queries for "
                             f"{ev.domain} from {ev.source_ip} returned NXDOMAIN, above the "
                             f"{cfg['nxdomain_ratio_threshold']:.0%} threshold. This pattern is "
                             f"consistent with DGA beaconing or misconfigured/stale infrastructure; "
                             f"it is not on its own evidence of compromise."),
                suppressed=suppression.matched, suppression_reason=suppression.reason,
                suppression_entry=suppression.matched_entry,
            ))

        # DNS-003: Potential Algorithmically Generated Domain
        dga = score_domain(ev.domain, config={"dns": cfg},
                            nxdomain_ratio=ev.nxdomain_ratio, query_count=ev.occurrence_count)
        if dga.score >= cfg["dga_flag_threshold"]:
            severity = HIGH if dga.confidence == "High" else MEDIUM if dga.confidence == "Medium" else LOW
            signals.append(DetectionSignal(
                rule_id="DNS-003", title="Potential Algorithmically Generated Domain", category="DNS",
                severity=severity, confidence=dga.confidence, score=int(dga.score * 0.2),
                indicator=ev.domain, source_ip=ev.source_ip, destination_ip=None,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=ev.occurrence_count,
                evidence=[f"DGA heuristic score: {dga.score}/100 (confidence: {dga.confidence})",
                          f"Signal breakdown: {dga.signals}"],
                explanation=dga.explanation,
                suppressed=suppression.matched, suppression_reason=suppression.reason,
                suppression_entry=suppression.matched_entry,
            ))

    # DNS-007: Excessive Unique Subdomains (per apex domain, across all clients)
    for apex, events in by_apex.items():
        unique_subdomains = {ev.domain for ev in events if ev.domain != apex}
        if len(unique_subdomains) >= cfg["excessive_subdomain_threshold"]:
            suppression = check_domain(apex, allowlist)
            first_seen = min(ev.first_seen for ev in events)
            last_seen = max(ev.last_seen for ev in events)
            total_occurrences = sum(ev.occurrence_count for ev in events)
            sources = sorted({ev.source_ip for ev in events})
            signals.append(DetectionSignal(
                rule_id="DNS-007", title="Excessive Unique Subdomains", category="DNS",
                severity=MEDIUM, confidence="Medium", score=10,
                indicator=apex, source_ip=sources[0] if sources else None, destination_ip=None,
                first_seen=first_seen, last_seen=last_seen, occurrence_count=total_occurrences,
                evidence=[f"{len(unique_subdomains)} unique subdomains observed under {apex} "
                          f"across {len(sources)} source(s): "
                          f"{', '.join(sorted(unique_subdomains)[:10])}"
                          f"{'...' if len(unique_subdomains) > 10 else ''}"],
                explanation=(f"{len(unique_subdomains)} distinct subdomains were queried under the "
                             f"same apex domain {apex}, exceeding the configured threshold of "
                             f"{cfg['excessive_subdomain_threshold']}. This pattern can indicate "
                             f"fast-flux infrastructure, DNS tunneling, or content-delivery/load-"
                             f"balancing subdomains, and needs corroborating evidence to distinguish "
                             f"between them."),
                suppressed=suppression.matched, suppression_reason=suppression.reason,
                suppression_entry=suppression.matched_entry,
            ))

    return signals


def _extension_of(path: str) -> Optional[str]:
    if not path:
        return None
    lowered = path.lower().split("?")[0]
    if "." not in lowered:
        return None
    return "." + lowered.rsplit(".", 1)[-1]


def _has_suspicious_ua(ev: HTTPBehavior, http_cfg: dict) -> bool:
    if not ev.user_agent:
        return False
    lowered = ev.user_agent.lower()
    return any(marker in lowered for marker in http_cfg["suspicious_user_agents"])


def _detect_http(http_events: List[HTTPBehavior], config: dict, allowlist: dict) -> List[DetectionSignal]:
    signals: List[DetectionSignal] = []
    cfg = config["http"]
    suspicious_ext = set(cfg["suspicious_extensions"])
    script_ext = set(cfg["script_extensions"])

    host_totals: Dict[str, int] = {}
    for ev in http_events:
        host_totals[ev.host] = host_totals.get(ev.host, 0) + ev.occurrence_count

    for ev in http_events:
        domain_suppression = check_domain(ev.host, allowlist)
        ip_suppression = check_ip(ev.dest_ip, allowlist)
        ua_suppression = check_user_agent(ev.user_agent, allowlist)
        host_suppressed = domain_suppression.matched or ip_suppression.matched
        combined_suppression = domain_suppression if domain_suppression.matched else ip_suppression
        is_suspicious_ua = _has_suspicious_ua(ev, cfg)

        # HTTP-001 / HTTP-002: Suspicious Executable / Script Download
        flagged_paths = [p for p in ev.paths if _extension_of(p) in suspicious_ext]
        if flagged_paths:
            is_script = any(_extension_of(p) in script_ext for p in flagged_paths)
            rule_id = "HTTP-002" if is_script else "HTTP-001"
            title = "Suspicious Script Download" if is_script else "Suspicious Executable Download"
            repeated = any(ev.path_counts.get(p, 0) >= cfg["repeated_payload_threshold"] for p in flagged_paths)
            severity = HIGH if is_suspicious_ua else MEDIUM
            score = (18 if is_script else 20) + (4 if repeated else 0)
            signals.append(DetectionSignal(
                rule_id=rule_id, title=title, category="HTTP",
                severity=severity, confidence="Medium", score=score,
                indicator=ev.host, source_ip=ev.source_ip, destination_ip=ev.dest_ip,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=sum(ev.path_counts.get(p, 0) for p in flagged_paths),
                evidence=[f"{'/'.join(sorted(ev.methods)) or 'HTTP'} request(s) for "
                          f"{', '.join(flagged_paths)} from host {ev.host}"
                          + (f", User-Agent: {ev.user_agent}" if ev.user_agent else "")],
                explanation=(f"{ev.source_ip} requested {len(flagged_paths)} path(s) ending in an "
                             f"executable/script extension from {ev.host}"
                             + (f", retrieved {cfg['repeated_payload_threshold']}+ times" if repeated else "")
                             + ". A file extension alone is a weak signal; this is escalated when "
                               "corroborated by User-Agent, destination reputation, or the transferred "
                               "file's own signature (see correlated findings)."),
                suppressed=host_suppressed, suppression_reason=combined_suppression.reason,
                suppression_entry=combined_suppression.matched_entry,
            ))

        # HTTP-003: Suspicious User-Agent (aggregated, contextual only)
        if is_suspicious_ua:
            signals.append(DetectionSignal(
                rule_id="HTTP-003", title="Suspicious User-Agent", category="HTTP",
                severity=LOW, confidence="Low", score=4,
                indicator=ev.host, source_ip=ev.source_ip, destination_ip=ev.dest_ip,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=ev.occurrence_count,
                evidence=[f"User-Agent '{ev.user_agent}' used for {ev.occurrence_count} "
                          f"request(s) to {ev.host}"],
                explanation=(f"The User-Agent '{ev.user_agent}' matches a known scripted/"
                             "command-line HTTP client pattern. This is common for legitimate "
                             "automation and is only meaningful in combination with other "
                             "evidence (rare destination, suspicious download, TI match)."),
                suppressed=ua_suppression.matched, suppression_reason=ua_suppression.reason,
                suppression_entry=ua_suppression.matched_entry,
            ))

        # HTTP-004: Rare External Host
        if host_totals.get(ev.host, 0) <= cfg["rare_host_occurrence_threshold"] and not host_suppressed:
            signals.append(DetectionSignal(
                rule_id="HTTP-004", title="Rare External Host", category="HTTP",
                severity=INFORMATIONAL, confidence="Low", score=2,
                indicator=ev.host, source_ip=ev.source_ip, destination_ip=ev.dest_ip,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=ev.occurrence_count,
                evidence=[f"{ev.host} was contacted only {host_totals.get(ev.host, 0)} "
                          f"time(s) across the entire capture."],
                explanation=(f"{ev.host} accounts for a very small share of observed HTTP "
                             f"traffic. Rarity alone is not suspicious -- most legitimate "
                             f"destinations are rare in a short capture -- but it raises the "
                             f"value of any corroborating signal for the same host."),
                suppressed=False,
            ))

    return signals


def _detect_files(file_events: List[FileBehavior], config: dict, allowlist: dict) -> List[DetectionSignal]:
    signals: List[DetectionSignal] = []
    cfg = config["http"]

    for f in file_events:
        suppression = check_ip(f.src_ip, allowlist)
        if not suppression.matched:
            suppression = check_ip(f.dst_ip, allowlist)

        if not f.signature:
            continue  # no recognizable signature -- not enough to raise a signal

        repeated = f.transfer_count >= cfg["repeated_payload_threshold"]
        is_executable = any(kw in f.signature.lower() for kw in ("executable", "script", "elf"))
        score = (15 if is_executable else 8) + (5 if repeated else 0)

        signals.append(DetectionSignal(
            rule_id="FILE-001", title="Suspicious File Signature", category="File",
            severity=HIGH if is_executable else MEDIUM, confidence="Medium", score=score,
            indicator=f.sha256, source_ip=f.src_ip, destination_ip=f.dst_ip,
            first_seen=f.first_seen, last_seen=f.last_seen, occurrence_count=f.transfer_count,
            evidence=[f"{f.size}-byte payload transferred {f.transfer_count} time(s) "
                      f"({f.src_ip} -> {f.dst_ip}), signature: {f.signature}, "
                      f"SHA256 {f.sha256[:16]}..."],
            explanation=(f"A network-transferred payload was reassembled and identified as "
                         f"{f.signature} by magic bytes"
                         + (f", and retrieved {f.transfer_count} separate times" if repeated else "")
                         + ". A recognizable executable or script signature on network-transferred "
                           "data warrants follow-up regardless of threat-intelligence reputation, "
                           "since a novel payload will have no TI history yet."),
            suppressed=suppression.matched, suppression_reason=suppression.reason,
            suppression_entry=suppression.matched_entry,
        ))

    return signals


def run_detections(aggregation: AggregationResult, config: Optional[dict] = None,
                    allowlist: Optional[dict] = None) -> List[DetectionSignal]:
    """Evaluate every rule against the aggregated behavioral events and
    return the full signal list, including suppressed signals (callers
    that need only active signals should filter on `.suppressed`)."""
    config = config or DEFAULT_CONFIG
    allowlist = allowlist if allowlist is not None else {
        "domains": [], "ips": [], "user_agents": [], "internal_hosts": []}

    signals: List[DetectionSignal] = []
    signals.extend(_detect_dns(aggregation.dns_events, config, allowlist))
    signals.extend(_detect_http(aggregation.http_events, config, allowlist))
    signals.extend(_detect_files(aggregation.file_events, config, allowlist))
    return signals
