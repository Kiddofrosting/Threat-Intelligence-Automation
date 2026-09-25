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
from typing import Dict, List, Optional, Set

from analyzer.aggregator import (
    AggregationResult, DNSBehavior, DomainResolution, FileBehavior, HTTPBehavior,
)
from analyzer.allowlist import check_domain, check_ip, check_user_agent
from analyzer.beaconing import compute_interval_stats
from analyzer.config import DEFAULT_CONFIG
from analyzer.dga import score_domain
from analyzer.mitre_mapping import get_technique
from analyzer.network_events import AUTH_LIKE_PORTS, ConnectionAttempt, ScanCandidate
from analyzer.public_suffixes import apex_domain as _psl_apex_domain
from analyzer.web_attack_patterns import match_path
from utils.networking import is_useful_ip

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
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_note: Optional[str] = None


def _leftmost_label(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return parts[0] if parts else domain


def _shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _detect_dns(dns_events: List[DNSBehavior], domain_resolutions: Dict, config: dict,
                 allowlist: dict, known_domains: Optional[Set[str]]) -> List[DetectionSignal]:
    signals: List[DetectionSignal] = []
    cfg = config["dns"]

    by_apex: Dict[str, List[DNSBehavior]] = {}
    for ev in dns_events:
        by_apex.setdefault(_psl_apex_domain(ev.domain, config), []).append(ev)

    # Overall query totals per domain (across all clients) -- needed for DNS-004.
    domain_totals: Dict[str, int] = {}
    for ev in dns_events:
        domain_totals[ev.domain] = domain_totals.get(ev.domain, 0) + ev.occurrence_count

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

        # DNS-004: Rare External Domain
        if domain_totals.get(ev.domain, 0) <= cfg["rare_domain_occurrence_threshold"] and not suppression.matched:
            signals.append(DetectionSignal(
                rule_id="DNS-004", title="Rare External Domain", category="DNS",
                severity=INFORMATIONAL, confidence="Low", score=2,
                indicator=ev.domain, source_ip=ev.source_ip, destination_ip=None,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=ev.occurrence_count,
                evidence=[f"{ev.domain} was queried only {domain_totals.get(ev.domain, 0)} "
                          f"time(s) across the entire capture."],
                explanation=(f"{ev.domain} accounts for a very small share of observed DNS "
                             f"traffic. Rarity alone is not suspicious -- most legitimate "
                             f"domains are rare in a short capture -- but it raises the value "
                             f"of any corroborating signal for the same domain."),
                suppressed=False,
            ))

        # DNS-005: Suspicious Newly Observed Domain (local history baseline)
        if cfg.get("newly_observed_enabled", True) and known_domains is not None \
                and ev.domain not in known_domains and not suppression.matched:
            signals.append(DetectionSignal(
                rule_id="DNS-005", title="Suspicious Newly Observed Domain", category="DNS",
                severity=INFORMATIONAL, confidence="Low", score=2,
                indicator=ev.domain, source_ip=ev.source_ip, destination_ip=None,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=ev.occurrence_count,
                evidence=[f"{ev.domain} does not appear in this tool's local domain-history "
                          f"baseline (previously analyzed captures)."],
                explanation=(f"{ev.domain} has not been observed in any prior run of this tool "
                             f"against this local history baseline. This is not a passive-DNS/"
                             f"domain-age feed -- it only reflects captures previously analyzed "
                             f"here -- so it is a weak signal on a fresh installation and grows "
                             f"more useful over time as the baseline accumulates."),
                suppressed=False,
            ))

    # DNS-006 / DNS-007: apex-domain-level grouping (subdomain enumeration,
    # tunneling indicators).
    for apex, events in by_apex.items():
        unique_subdomains = {ev.domain for ev in events if ev.domain != apex}
        if not unique_subdomains:
            continue
        suppression = check_domain(apex, allowlist)
        first_seen = min(ev.first_seen for ev in events)
        last_seen = max(ev.last_seen for ev in events)
        total_occurrences = sum(ev.occurrence_count for ev in events)
        sources = sorted({ev.source_ip for ev in events})

        if len(unique_subdomains) >= cfg["excessive_subdomain_threshold"]:
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

        # DNS-006: DNS Tunneling Indicators -- needs BOTH enough unique
        # subdomains AND (long average label length OR a high TXT/NULL
        # query-type ratio). Excessive subdomains alone (DNS-007) is not
        # enough -- that's exactly the CDN/load-balancer false-positive
        # case this rule is designed to avoid.
        if len(unique_subdomains) >= cfg["tunneling_min_subdomains"]:
            labels = [_leftmost_label(d) for d in unique_subdomains]
            avg_label_len = sum(len(l) for l in labels) / len(labels)
            qtypes = [ev.query_type for ev in events for _ in range(ev.occurrence_count)]
            txt_null_count = sum(1 for q in qtypes if q in ("TXT", "NULL"))
            txt_null_ratio = txt_null_count / len(qtypes) if qtypes else 0.0

            long_labels = avg_label_len >= cfg["tunneling_avg_label_length_threshold"]
            high_txt = txt_null_ratio >= cfg["tunneling_txt_null_ratio_threshold"]
            if long_labels or high_txt:
                signals.append(DetectionSignal(
                    rule_id="DNS-006", title="DNS Tunneling Indicators", category="DNS",
                    severity=HIGH, confidence="Medium" if (long_labels and high_txt) else "Low",
                    score=14,
                    indicator=apex, source_ip=sources[0] if sources else None, destination_ip=None,
                    first_seen=first_seen, last_seen=last_seen, occurrence_count=total_occurrences,
                    evidence=[f"{len(unique_subdomains)} unique subdomains under {apex}, "
                              f"average label length {avg_label_len:.1f} chars, "
                              f"TXT/NULL query ratio {txt_null_ratio:.0%}."],
                    explanation=(f"Subdomain activity under {apex} shows "
                                 + ("long, high-entropy-looking labels" if long_labels else "")
                                 + (" and " if long_labels and high_txt else "")
                                 + (f"an elevated TXT/NULL query ratio ({txt_null_ratio:.0%})" if high_txt else "")
                                 + f", both consistent with data being encoded into DNS queries "
                                   f"(tunneling). Legitimate CDN/load-balancer subdomain churn "
                                   f"typically uses short labels and A/AAAA queries, not this "
                                   f"combination -- but this remains a heuristic, not confirmation."),
                    suppressed=suppression.matched, suppression_reason=suppression.reason,
                    suppression_entry=suppression.matched_entry,
                ))

    # DNS-008: Potential Fast-Flux Behavior (domain-level resolution view,
    # not per-client -- see analyzer/aggregator.py's DomainResolution).
    for (domain, qtype), res in domain_resolutions.items():
        if len(res.resolved_ips) < cfg["fastflux_min_distinct_ips"]:
            continue
        if res.duration_seconds > cfg["fastflux_window_seconds"]:
            continue  # distinct IPs spread over a long time is normal DNS load-balancing, not flux
        suppression = check_domain(domain, allowlist)
        signals.append(DetectionSignal(
            rule_id="DNS-008", title="Potential Fast-Flux Behavior", category="DNS",
            severity=MEDIUM, confidence="Low", score=10,
            indicator=domain, source_ip=None, destination_ip=None,
            first_seen=res.first_seen, last_seen=res.last_seen, occurrence_count=res.response_count,
            evidence=[f"{domain} resolved to {len(res.resolved_ips)} distinct IP(s) within "
                      f"{res.duration_seconds:.0f}s: {', '.join(sorted(res.resolved_ips)[:8])}"
                      f"{'...' if len(res.resolved_ips) > 8 else ''}"],
            explanation=(f"{domain} resolved to {len(res.resolved_ips)} distinct IP addresses "
                         f"within a {res.duration_seconds:.0f}-second window, exceeding the "
                         f"configured threshold of {cfg['fastflux_min_distinct_ips']}. Rapidly "
                         f"rotating resolution is one fast-flux indicator, but is also produced "
                         f"by legitimate anycast/load-balanced services; this heuristic has no "
                         f"visibility into ASN/geolocation diversity, which would substantially "
                         f"raise confidence if available."),
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


def _mime_looks_executable(content_type: str, http_cfg: dict) -> bool:
    ct = content_type.lower().split(";")[0].strip()
    return any(ct == m or ct.startswith(m) for m in http_cfg["executable_mime_types"])


def _mime_looks_benign(content_type: str, http_cfg: dict) -> bool:
    ct = content_type.lower().split(";")[0].strip()
    return any(ct.startswith(p) for p in http_cfg["benign_mime_prefixes"])


def _detect_http(http_events: List[HTTPBehavior], file_events: List[FileBehavior],
                  config: dict, allowlist: dict) -> List[DetectionSignal]:
    signals: List[DetectionSignal] = []
    cfg = config["http"]
    suspicious_ext = set(cfg["suspicious_extensions"])
    script_ext = set(cfg["script_extensions"])

    host_totals: Dict[str, int] = {}
    for ev in http_events:
        host_totals[ev.host] = host_totals.get(ev.host, 0) + ev.occurrence_count

    files_by_dest: Dict[str, List[FileBehavior]] = {}
    for f in file_events:
        files_by_dest.setdefault(f.dst_ip, []).append(f)
        files_by_dest.setdefault(f.src_ip, []).append(f)

    for ev in http_events:
        domain_suppression = check_domain(ev.host, allowlist)
        ip_suppression = check_ip(ev.dest_ip, allowlist)
        ua_suppression = check_user_agent(ev.user_agent, allowlist)
        host_suppressed = domain_suppression.matched or ip_suppression.matched
        combined_suppression = domain_suppression if domain_suppression.matched else ip_suppression
        is_suspicious_ua = _has_suspicious_ua(ev, cfg)
        is_rare_host = host_totals.get(ev.host, 0) <= cfg["rare_host_occurrence_threshold"]

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

            # HTTP-005: Suspicious Download Source -- the download-extension
            # signal above, corroborated specifically by *destination
            # rarity* (as opposed to HTTP-003's UA corroboration). Kept
            # distinct because a rare, unallowlisted download source is
            # actionable evidence about the infrastructure itself, not
            # just the request.
            if is_rare_host and not host_suppressed:
                signals.append(DetectionSignal(
                    rule_id="HTTP-005", title="Suspicious Download Source", category="HTTP",
                    severity=MEDIUM, confidence="Medium", score=8,
                    indicator=ev.host, source_ip=ev.source_ip, destination_ip=ev.dest_ip,
                    first_seen=ev.first_seen, last_seen=ev.last_seen,
                    occurrence_count=sum(ev.path_counts.get(p, 0) for p in flagged_paths),
                    evidence=[f"Executable/script download from {ev.host}, a destination contacted "
                              f"only {host_totals.get(ev.host, 0)} time(s) in this capture and not "
                              f"on the allowlist."],
                    explanation=(f"{ev.host} served an executable/script payload and is a rare, "
                                 f"unallowlisted destination -- the combination of the two is more "
                                 f"significant than either alone: a download-serving host with no "
                                 f"other traffic in this capture is not typical CDN/update-service "
                                 f"behaviour."),
                    suppressed=False,
                ))

            # HTTP-006: Executable / MIME Mismatch
            for content_type in ev.content_types:
                if _mime_looks_benign(content_type, cfg):
                    signals.append(DetectionSignal(
                        rule_id="HTTP-006", title="Executable / MIME Mismatch", category="HTTP",
                        severity=HIGH, confidence="Medium", score=12,
                        indicator=ev.host, source_ip=ev.source_ip, destination_ip=ev.dest_ip,
                        first_seen=ev.first_seen, last_seen=ev.last_seen,
                        occurrence_count=ev.occurrence_count,
                        evidence=[f"Response Content-Type '{content_type}' declared for a request "
                                  f"to an executable/script path ({', '.join(flagged_paths)}) from {ev.host}."],
                        explanation=(f"The server declared Content-Type '{content_type}' -- a type "
                                     f"normally associated with non-executable content -- for a "
                                     f"request to a path with an executable/script extension. "
                                     f"Serving executable content under a benign-looking MIME type "
                                     f"is a known technique for evading naive content filtering."),
                        suppressed=host_suppressed, suppression_reason=combined_suppression.reason,
                        suppression_entry=combined_suppression.matched_entry,
                    ))
                    break  # one mismatch signal per host is enough

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
        if is_rare_host and not host_suppressed:
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

        # HTTP-007: Repeated Payload Retrieval -- standalone, applies to
        # ANY repeated path (not just executable/script extensions), since
        # repeatedly re-fetching the same object is itself worth surfacing
        # (e.g. beaconing that re-downloads a config/second-stage file).
        repeated_any = [p for p, count in ev.path_counts.items()
                         if count >= cfg["repeated_payload_threshold"] and _extension_of(p) not in suspicious_ext]
        if repeated_any:
            signals.append(DetectionSignal(
                rule_id="HTTP-007", title="Repeated Payload Retrieval", category="HTTP",
                severity=LOW, confidence="Low", score=5,
                indicator=ev.host, source_ip=ev.source_ip, destination_ip=ev.dest_ip,
                first_seen=ev.first_seen, last_seen=ev.last_seen,
                occurrence_count=sum(ev.path_counts.get(p, 0) for p in repeated_any),
                evidence=[f"{ev.source_ip} retrieved {p} from {ev.host} "
                          f"{ev.path_counts.get(p, 0)} time(s)." for p in repeated_any[:3]],
                explanation=(f"One or more paths from {ev.host} were retrieved at least "
                             f"{cfg['repeated_payload_threshold']} times by the same client. "
                             f"Repeated retrieval of the same object can be normal polling/"
                             f"refresh behaviour, but is also consistent with periodic beaconing "
                             f"or re-fetching a staged payload/config."),
                suppressed=host_suppressed, suppression_reason=combined_suppression.reason,
                suppression_entry=combined_suppression.matched_entry,
            ))

        # HTTP-008: Suspicious Request Pattern (SQLi / traversal / command
        # injection / XSS / LFI-RFI) -- a pattern match on its own is
        # extremely prone to false positives, so this only fires when the
        # SAME attack category recurs across multiple distinct requests
        # to the same host (configurable; see require_web_attack_min_repetitions).
        category_matches: Dict[str, List] = {}
        for p in ev.paths:
            match = match_path(p)
            if match:
                category_matches.setdefault(match.category, []).append(match)
        for category, matches in category_matches.items():
            if len(matches) >= cfg["web_attack_min_repetitions"]:
                label = matches[0].label
                signals.append(DetectionSignal(
                    rule_id="HTTP-008", title=f"Suspicious Request Pattern ({label})", category="HTTP",
                    severity=HIGH, confidence="Medium", score=15,
                    indicator=ev.host, source_ip=ev.source_ip, destination_ip=ev.dest_ip,
                    first_seen=ev.first_seen, last_seen=ev.last_seen,
                    occurrence_count=len(matches),
                    evidence=[f"{len(matches)} distinct request(s) to {ev.host} matched a "
                              f"{label} pattern, e.g. '{matches[0].path}'."],
                    explanation=(f"{len(matches)} separate requests from {ev.source_ip} to {ev.host} "
                                 f"matched a {label} request-pattern signature. A single match of this "
                                 f"kind is common as a false positive (legitimate query strings, "
                                 f"security scanners, or crawler noise); recurrence across multiple "
                                 f"distinct requests is what makes this worth flagging. Response codes "
                                 f"were not used to gate this signal -- whether any attempt succeeded "
                                 f"is not established from this evidence alone."),
                    suppressed=host_suppressed, suppression_reason=combined_suppression.reason,
                    suppression_entry=combined_suppression.matched_entry,
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


def _detect_network(scan_candidates: Dict[str, ScanCandidate], config: dict,
                     allowlist: dict) -> List[DetectionSignal]:
    """NET-001/002/003: reconnaissance and repeated-connection-attempt
    detection from TCP-level connection attempts. No protocol decoding
    is attempted -- only SYN/SYN-ACK/RST fan-out and success ratios,
    which is exactly what a raw PCAP can support without an SSH/FTP/
    RDP/SMB parser."""
    signals: List[DetectionSignal] = []
    cfg = config["network"]

    for src_ip, cand in scan_candidates.items():
        suppression = check_ip(src_ip, allowlist)
        first_seen, last_seen = cand.first_seen, cand.last_seen
        if first_seen is None or last_seen is None:
            continue

        # NET-001: Port Scanning
        distinct_ports = cand.distinct_dst_ports
        if len(distinct_ports) >= cfg["port_scan_min_distinct_ports"] and \
                cand.success_ratio <= cfg["port_scan_max_success_ratio"]:
            signals.append(DetectionSignal(
                rule_id="NET-001", title="Port Scanning", category="Network",
                severity=MEDIUM, confidence="Medium", score=12,
                indicator=src_ip, source_ip=src_ip, destination_ip=None,
                first_seen=first_seen, last_seen=last_seen, occurrence_count=cand.total_syn,
                evidence=[f"{src_ip} attempted connections to {len(distinct_ports)} distinct "
                          f"destination port(s) with a {cand.success_ratio:.0%} success ratio."],
                explanation=(f"{src_ip} initiated connection attempts to {len(distinct_ports)} "
                             f"distinct destination ports with only a {cand.success_ratio:.0%} "
                             f"success rate (SYN-ACK received). This fan-out/low-success "
                             f"combination is consistent with port scanning; it does not by "
                             f"itself establish intent or attribute the activity to a specific tool."),
                suppressed=suppression.matched, suppression_reason=suppression.reason,
                suppression_entry=suppression.matched_entry,
            ))

        # NET-002: Host Scanning
        distinct_ips = cand.distinct_dst_ips
        if len(distinct_ips) >= cfg["host_scan_min_distinct_ips"] and \
                cand.success_ratio <= cfg["host_scan_max_success_ratio"]:
            signals.append(DetectionSignal(
                rule_id="NET-002", title="Host Scanning", category="Network",
                severity=MEDIUM, confidence="Medium", score=12,
                indicator=src_ip, source_ip=src_ip, destination_ip=None,
                first_seen=first_seen, last_seen=last_seen, occurrence_count=cand.total_syn,
                evidence=[f"{src_ip} attempted connections to {len(distinct_ips)} distinct "
                          f"destination IP(s) with a {cand.success_ratio:.0%} success ratio."],
                explanation=(f"{src_ip} initiated connection attempts to {len(distinct_ips)} "
                             f"distinct destination IPs with only a {cand.success_ratio:.0%} "
                             f"success rate. This fan-out/low-success combination is consistent "
                             f"with host discovery/sweep scanning."),
                suppressed=suppression.matched, suppression_reason=suppression.reason,
                suppression_entry=suppression.matched_entry,
            ))

        # NET-003: Repeated Connection Attempts to an Authentication-Gated Port
        for attempt in cand.attempts:
            service = attempt.auth_like_service
            if not service:
                continue
            if attempt.syn_count < cfg["auth_port_min_attempts"]:
                continue
            success_multiplier = max(1.0 / max(cfg["auth_port_max_success_ratio"], 0.01), 1.0)
            if attempt.succeeded and attempt.syn_count < cfg["auth_port_min_attempts"] * success_multiplier:
                # A handful of SYN retransmits ending in one normal,
                # successful connection is not brute-force-like; only
                # flag a successful attempt if the volume is still high
                # relative to the configured max success ratio.
                continue
            dst_suppression = check_ip(attempt.dst_ip, allowlist)
            signals.append(DetectionSignal(
                rule_id="NET-003", title="Repeated Connection Attempts to Authentication Service",
                category="Network", severity=MEDIUM, confidence="Low", score=10,
                indicator=attempt.dst_ip, source_ip=src_ip, destination_ip=attempt.dst_ip,
                first_seen=attempt.first_seen, last_seen=attempt.last_seen,
                occurrence_count=attempt.syn_count,
                evidence=[f"{src_ip} made {attempt.syn_count} connection attempt(s) to "
                          f"{attempt.dst_ip}:{attempt.dst_port} ({service}-like port)."],
                explanation=(f"{src_ip} made {attempt.syn_count} separate connection attempts "
                             f"to {attempt.dst_ip} on port {attempt.dst_port}, a port "
                             f"conventionally associated with {service}. This parser cannot "
                             f"decode {service} itself, so it is not established whether any "
                             f"authentication was actually attempted or what its outcome was -- "
                             f"only that repeated connection attempts to this port occurred, "
                             f"which is consistent with (but not proof of) credential-guessing "
                             f"activity."),
                suppressed=(suppression.matched or dst_suppression.matched),
                suppression_reason=suppression.reason or dst_suppression.reason,
                suppression_entry=suppression.matched_entry or dst_suppression.matched_entry,
            ))

    return signals


def _detect_exfiltration(connection_attempts: List[ConnectionAttempt], config: dict,
                          allowlist: dict) -> List[DetectionSignal]:
    """NET-004: asymmetric high-volume outbound traffic to an external
    destination -- a network-layer volume heuristic for possible data
    exfiltration. This never claims data actually left the environment
    or identifies what was sent; it only flags the byte-volume pattern."""
    signals: List[DetectionSignal] = []
    cfg = config["network"]

    for attempt in connection_attempts:
        outbound, inbound = attempt.bytes_src_to_dst, attempt.bytes_dst_to_src
        if outbound < cfg["exfil_min_outbound_bytes"]:
            continue
        ratio = outbound / max(inbound, 1)
        if ratio < cfg["exfil_min_outbound_ratio"]:
            continue
        if not is_useful_ip(attempt.dst_ip):
            continue  # internal/private destination -- not exfiltration to an external party
        suppression = check_ip(attempt.dst_ip, allowlist)
        signals.append(DetectionSignal(
            rule_id="NET-004", title="Possible Data Exfiltration", category="Network",
            severity=HIGH, confidence="Low", score=14,
            indicator=attempt.dst_ip, source_ip=attempt.src_ip, destination_ip=attempt.dst_ip,
            first_seen=attempt.first_seen, last_seen=attempt.last_seen,
            occurrence_count=attempt.packet_count,
            evidence=[f"{attempt.src_ip} sent {outbound:,} bytes to {attempt.dst_ip}:{attempt.dst_port}, "
                      f"receiving only {inbound:,} bytes back (ratio {ratio:.1f}x)."],
            explanation=(f"{attempt.src_ip} transferred {outbound:,} bytes to external host "
                         f"{attempt.dst_ip} on port {attempt.dst_port} versus {inbound:,} bytes "
                         f"received in return ({ratio:.1f}x outbound/inbound). Asymmetric "
                         f"high-volume outbound traffic is consistent with data exfiltration, but "
                         f"legitimate uploads and backups produce the same byte-volume pattern -- "
                         f"whether this represents actual data loss is not established from "
                         f"volume alone; the content, destination reputation, and any accompanying "
                         f"DNS/HTTP evidence should be reviewed."),
            suppressed=suppression.matched, suppression_reason=suppression.reason,
            suppression_entry=suppression.matched_entry,
        ))

    return signals


def _detect_beaconing(http_events: List[HTTPBehavior], dns_events: List[DNSBehavior],
                       config: dict, allowlist: dict) -> List[DetectionSignal]:
    """BEACON-001: repeated connections at a statistically regular
    interval -- a conventional C2 beaconing tell. Computed from the
    per-occurrence timestamps aggregator.py tracks; a single repeated
    request is never enough (compute_interval_stats requires at least
    4 occurrences / 3 intervals)."""
    signals: List[DetectionSignal] = []
    cfg = config["beaconing"]

    for ev in http_events:
        if ev.occurrence_count < cfg["min_occurrences"]:
            continue
        stats = compute_interval_stats(ev.timestamps)
        if not stats or not stats.is_regular:
            continue
        suppression = check_domain(ev.host, allowlist)
        if not suppression.matched:
            suppression = check_ip(ev.dest_ip, allowlist)
        signals.append(DetectionSignal(
            rule_id="BEACON-001", title="Possible Beaconing Behavior", category="Behavioral",
            severity=MEDIUM, confidence="Medium", score=10,
            indicator=ev.host, source_ip=ev.source_ip, destination_ip=ev.dest_ip,
            first_seen=ev.first_seen, last_seen=ev.last_seen, occurrence_count=ev.occurrence_count,
            evidence=[f"{ev.occurrence_count} connections from {ev.source_ip} to {ev.host} at a "
                      f"mean interval of {stats.mean_interval_seconds:.1f}s "
                      f"(coefficient of variation {stats.coefficient_of_variation:.2f})."],
            explanation=(f"{ev.source_ip} connected to {ev.host} {ev.occurrence_count} times at a "
                         f"mean interval of {stats.mean_interval_seconds:.1f} seconds with low "
                         f"relative variance (CV={stats.coefficient_of_variation:.2f}, threshold "
                         f"{cfg['max_coefficient_of_variation']}). Regular-interval repeated "
                         f"connections are a conventional beaconing indicator, but legitimate "
                         f"polling/heartbeat/telemetry traffic produces the same statistical "
                         f"signature -- this should be corroborated by destination reputation or "
                         f"other evidence before being treated as confirmed C2."),
            suppressed=suppression.matched, suppression_reason=suppression.reason,
            suppression_entry=suppression.matched_entry,
        ))

    return signals


def _annotate_mitre(signals: List[DetectionSignal]) -> None:
    for sig in signals:
        technique = get_technique(sig.rule_id)
        if technique:
            sig.mitre_technique_id = technique.technique_id
            sig.mitre_technique_name = technique.technique_name
            sig.mitre_note = technique.note


def run_detections(aggregation: AggregationResult, config: Optional[dict] = None,
                    allowlist: Optional[dict] = None,
                    known_domains: Optional[Set[str]] = None) -> List[DetectionSignal]:
    """Evaluate every rule against the aggregated behavioral events and
    return the full signal list, including suppressed signals (callers
    that need only active signals should filter on `.suppressed`).

    `known_domains` is the local domain-history baseline (see
    analyzer/domain_history.py) used by DNS-005; pass None to disable
    that rule entirely (e.g. in unit tests that don't want file I/O)."""
    config = config or DEFAULT_CONFIG
    allowlist = allowlist if allowlist is not None else {
        "domains": [], "ips": [], "user_agents": [], "internal_hosts": []}

    signals: List[DetectionSignal] = []
    signals.extend(_detect_dns(aggregation.dns_events, aggregation.dns_domain_resolutions,
                                config, allowlist, known_domains))
    signals.extend(_detect_http(aggregation.http_events, aggregation.file_events, config, allowlist))
    signals.extend(_detect_files(aggregation.file_events, config, allowlist))
    signals.extend(_detect_network(aggregation.scan_candidates, config, allowlist))
    signals.extend(_detect_exfiltration(aggregation.connection_attempts, config, allowlist))
    signals.extend(_detect_beaconing(aggregation.http_events, aggregation.dns_events, config, allowlist))
    _annotate_mitre(signals)
    return signals
