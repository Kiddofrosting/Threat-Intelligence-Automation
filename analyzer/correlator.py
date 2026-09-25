"""Correlation engine.

This is the heart of the tool. It does not build one Finding per IOC
-- it groups DNS, HTTP and file behavioral events by *source endpoint
and time window* into candidate incident chains (DNS -> connection ->
HTTP -> payload -> threat intelligence), and only promotes a chain to
a Finding when it is backed by a non-suppressed local detection signal
or a meaningful (SUSPICIOUS/MALICIOUS) threat-intelligence assessment.
Weak-reputation-only or no-record TI results never become findings on
their own.

Risk scoring is split into five capped dimensions (reputation,
behavior, payload, network context, asset context) specifically so
that many small correlated signals about the *same* underlying
behaviour cannot be added up into an inflated score, and so a weak
local heuristic alone can never reach a high severity band.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from analyzer.aggregator import AggregationResult, DNSBehavior, FileBehavior, HTTPBehavior
from analyzer.assets import AssetProfile, get_asset, highest_criticality
from analyzer.config import DEFAULT_CONFIG, band_from_score, min_severity
from analyzer.detector import INFORMATIONAL, DetectionSignal
from analyzer.ioc_extractor import IOC
from analyzer.kill_chain import stages_for
from analyzer.pcap_parser import ParsedCapture
from analyzer.ti_interpreter import MALICIOUS, SUSPICIOUS, TIAssessment, interpret
from feeds.base import FeedResult


@dataclass
class TimelineEvent:
    timestamp: datetime
    description: str
    finding_id: Optional[str] = None


@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: str
    risk_score: int
    affected_assets: List[str] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    destination_ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrence_count: int = 0
    detection_signals: List[DetectionSignal] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    threat_intelligence: List[str] = field(default_factory=list)
    explanation: str = ""
    recommended_actions: List[str] = field(default_factory=list)
    event_chain: Optional[str] = None
    asset_notes: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    kill_chain_stages: List[str] = field(default_factory=list)
    evidence_basis: Dict[str, List[str]] = field(default_factory=dict)
    analyst_questions: List[str] = field(default_factory=list)


@dataclass
class _Candidate:
    endpoint: str
    dns_event: Optional[DNSBehavior] = None
    http_events: List[HTTPBehavior] = field(default_factory=list)
    file_events: List[FileBehavior] = field(default_factory=list)


def interpret_ti_results(ti_results: Dict[str, List[FeedResult]],
                          config: dict) -> Dict[str, List[TIAssessment]]:
    """Run every raw FeedResult through the feed-specific interpreter."""
    ti_cfg = config.get("ti", DEFAULT_CONFIG["ti"])
    assessments: Dict[str, List[TIAssessment]] = {}
    for indicator, results in ti_results.items():
        assessments[indicator] = [interpret(r, {"ti": ti_cfg}) for r in results]
    return assessments


def _build_candidates(aggregation: AggregationResult) -> List[_Candidate]:
    dns_events = aggregation.dns_events
    http_events = aggregation.http_events
    file_events = aggregation.file_events

    endpoints: Set[str] = set()
    endpoints.update(ev.source_ip for ev in dns_events)
    endpoints.update(ev.source_ip for ev in http_events)
    http_dest_ips = {ev.dest_ip for ev in http_events}
    for f in file_events:
        # The file's "endpoint" is whichever side already appears as a
        # client elsewhere in this capture (i.e. is doing the querying);
        # default to the receiving side when neither is already known.
        if f.dst_ip in endpoints or f.dst_ip not in http_dest_ips:
            endpoints.add(f.dst_ip)
        else:
            endpoints.add(f.src_ip)

    # Sources whose only visible activity is TCP-level connection
    # fan-out (scanning/recon/exfiltration) still need a candidate so
    # their NET-00x signals get a chance to become a finding, even
    # though there is no DNS/HTTP/file stage to attach them to.
    scan_only_endpoints = set(aggregation.scan_candidates.keys()) - endpoints
    endpoints.update(scan_only_endpoints)

    candidates: List[_Candidate] = []
    used_http: Set[int] = set()
    used_file: Set[int] = set()

    for endpoint in sorted(endpoints):
        endpoint_dns = [d for d in dns_events if d.source_ip == endpoint]
        endpoint_http = [h for h in http_events if h.source_ip == endpoint]
        endpoint_file = [f for f in file_events if f.dst_ip == endpoint or f.src_ip == endpoint]

        for dns_ev in endpoint_dns:
            cand = _Candidate(endpoint=endpoint, dns_event=dns_ev)
            for h in endpoint_http:
                if id(h) in used_http:
                    continue
                if h.host.lower() == dns_ev.domain or h.dest_ip in dns_ev.resolved_ips:
                    used_http.add(id(h))
                    cand.http_events.append(h)
                    for f in endpoint_file:
                        if id(f) in used_file:
                            continue
                        if f.dst_ip == h.dest_ip or f.src_ip == h.dest_ip:
                            used_file.add(id(f))
                            cand.file_events.append(f)
            candidates.append(cand)

        for h in endpoint_http:
            if id(h) in used_http:
                continue
            used_http.add(id(h))
            cand = _Candidate(endpoint=endpoint, http_events=[h])
            for f in endpoint_file:
                if id(f) in used_file:
                    continue
                if f.dst_ip == h.dest_ip or f.src_ip == h.dest_ip:
                    used_file.add(id(f))
                    cand.file_events.append(f)
            candidates.append(cand)

        for f in endpoint_file:
            if id(f) in used_file:
                continue
            used_file.add(id(f))
            candidates.append(_Candidate(endpoint=endpoint, file_events=[f]))

        if endpoint in scan_only_endpoints:
            # Bare candidate: no DNS/HTTP/file stage, purely so NET-00x
            # signals keyed on this endpoint can be picked up below.
            candidates.append(_Candidate(endpoint=endpoint))

    return candidates


def _candidate_indicators(cand: _Candidate) -> Set[str]:
    indicators: Set[str] = set()
    if cand.dns_event:
        indicators.add(cand.dns_event.domain)
        indicators.update(cand.dns_event.resolved_ips)
    for h in cand.http_events:
        indicators.add(h.host)
        indicators.add(h.dest_ip)
    for f in cand.file_events:
        indicators.add(f.sha256)
        indicators.add(f.md5)
        indicators.add(f.sha1)
    return indicators


def _timestamps(cand: _Candidate) -> Tuple[Optional[datetime], Optional[datetime]]:
    times: List[datetime] = []
    if cand.dns_event:
        times += [cand.dns_event.first_seen, cand.dns_event.last_seen]
    for h in cand.http_events:
        times += [h.first_seen, h.last_seen]
    for f in cand.file_events:
        times += [f.first_seen, f.last_seen]
    if not times:
        return None, None
    return min(times), max(times)


def _event_chain(cand: _Candidate, sig_list: List[DetectionSignal]) -> Optional[str]:
    stages = []
    net_signals = [d for d in sig_list if d.category == "Network" and d.rule_id in ("NET-001", "NET-002")]
    if net_signals:
        stages.append(f"Network reconnaissance ({', '.join(sorted({d.rule_id for d in net_signals}))})")
    if cand.dns_event:
        stages.append(f"DNS ({cand.dns_event.domain})")
    if cand.http_events:
        hosts = ", ".join(sorted({h.host for h in cand.http_events}))
        stages.append(f"HTTP connection ({hosts})")
    if cand.file_events:
        sigs = ", ".join(sorted({f.signature or "unrecognized payload" for f in cand.file_events}))
        stages.append(f"File transfer ({sigs})")
    exfil_signals = [d for d in sig_list if d.rule_id == "NET-004"]
    if exfil_signals:
        stages.append("Outbound data transfer (possible exfiltration)")
    if len(stages) < 2:
        return None
    return "\n  \u2193\n".join(stages)


def _title_for(cand: _Candidate, sig_list: List[DetectionSignal], ti_meaningful: bool, ti_malicious: bool,
                has_signature: bool, dga_flagged: bool) -> Tuple[str, str]:
    rule_ids = {d.rule_id for d in sig_list}
    if cand.file_events and (ti_malicious or has_signature):
        return "Suspicious Payload Retrieval", "Payload Delivery"
    if "NET-004" in rule_ids:
        return f"Possible Data Exfiltration from {cand.endpoint}", "Data Exfiltration"
    if "NET-003" in rule_ids:
        return f"Repeated Authentication-Service Connection Attempts from {cand.endpoint}", "Credential Access"
    if "BEACON-001" in rule_ids:
        host = sorted({h.host for h in cand.http_events})[0] if cand.http_events else cand.endpoint
        return f"Possible Beaconing to {host}", "Command and Control"
    if "NET-001" in rule_ids or "NET-002" in rule_ids:
        label = "Port Scanning" if "NET-001" in rule_ids else "Host Scanning"
        return f"{label} from {cand.endpoint}", "Reconnaissance"
    if cand.dns_event and dga_flagged:
        return f"Potential DGA Domain Activity — {cand.dns_event.domain}", "DNS Behavior"
    if cand.http_events and ti_meaningful:
        host = sorted({h.host for h in cand.http_events})[0]
        return f"Suspicious Connection to {host}", "Network Connection"
    if ti_meaningful:
        return "Threat Intelligence Match", "Threat Intelligence"
    return "Suspicious Network Activity", "Behavioral"


def _evidence_basis(cand: _Candidate, sig_list: List[DetectionSignal], ti_list: List[TIAssessment],
                     ti_malicious: bool, has_signature: bool) -> Dict[str, List[str]]:
    """Splits what's known about this finding into four epistemic
    tiers, per the brief's explicit requirement to distinguish these:
    established (directly observed), strongly indicated (multiple
    independent signals agree), possible (a plausible but unconfirmed
    interpretation), and not established (explicitly not provable from
    this capture)."""
    established: List[str] = []
    strongly_indicated: List[str] = []
    possible: List[str] = []
    not_established: List[str] = []

    if cand.dns_event:
        established.append(f"{cand.endpoint} issued {cand.dns_event.occurrence_count} DNS "
                            f"quer(y/ies) for {cand.dns_event.domain}, directly observed in the capture.")
    for h in cand.http_events:
        established.append(f"{cand.endpoint} sent {h.occurrence_count} HTTP request(s) to {h.host} "
                            f"({h.dest_ip}), directly observed in the capture.")
    for f in cand.file_events:
        established.append(f"A {f.size}-byte payload was transferred between {f.src_ip} and "
                            f"{f.dst_ip}" + (f", identified as {f.signature} by magic bytes" if f.signature else "") + ".")

    rule_ids = {d.rule_id for d in sig_list}
    if "DNS-003" in rule_ids:
        strongly_indicated.append("Multi-signal heuristic scoring (entropy, digit/vowel ratio, "
                                   "dictionary-word absence) is consistent with algorithmic domain generation.")
    if ("NET-001" in rule_ids or "NET-002" in rule_ids) and len(rule_ids) >= 1:
        strongly_indicated.append(f"{cand.endpoint} shows a connection fan-out and success-ratio pattern "
                                   f"consistent with network reconnaissance/scanning.")
    if "BEACON-001" in rule_ids:
        strongly_indicated.append("Connection timing shows low-variance, regular intervals, a "
                                   "conventional beaconing indicator.")
    if ti_malicious and sig_list:
        strongly_indicated.append("Independent local-detection and threat-intelligence evidence "
                                   "point to the same conclusion.")
    elif ti_malicious:
        strongly_indicated.append("Threat intelligence reports this indicator as malicious.")

    if cand.file_events and has_signature:
        possible.append("The transferred executable/script may have been executed on the endpoint.")
        not_established.append("Whether the transferred payload was actually executed is not "
                                "established from network evidence alone.")
    if "NET-003" in rule_ids:
        possible.append("The repeated connection attempts may represent credential-guessing activity.")
        not_established.append("Whether any authentication was attempted, and its outcome, is not "
                                "established -- this parser does not decode the authentication protocol.")
    if "HTTP-008" in rule_ids:
        possible.append("The repeated suspicious request pattern may represent an exploitation attempt.")
        not_established.append("Whether any exploitation attempt succeeded is not established from "
                                "the request pattern alone; server-side response/behavior evidence "
                                "would be needed to confirm.")
    if "NET-004" in rule_ids:
        possible.append("The asymmetric outbound volume may represent data exfiltration.")
        not_established.append("What data, if any, was actually transferred is not established from "
                                "byte-volume evidence alone.")
    if cand.dns_event and "DNS-003" in rule_ids and not ti_list:
        not_established.append("No independent threat-intelligence evidence corroborates this domain; "
                                "the DGA classification rests on lexical/behavioral heuristics alone.")

    return {
        "established": established,
        "strongly_indicated": strongly_indicated,
        "possible": possible,
        "not_established": not_established,
    }


def _analyst_questions(cand: _Candidate, sig_list: List[DetectionSignal], ti_malicious: bool,
                        has_signature: bool) -> List[str]:
    rule_ids = {d.rule_id for d in sig_list}
    questions: List[str] = []
    if cand.file_events and has_signature:
        questions.append("Was the downloaded payload executed on the endpoint (EDR/AV logs)?")
    if ti_malicious or cand.dns_event or cand.http_events:
        questions.append(f"Did {cand.endpoint} communicate with this infrastructure prior to this capture?")
    if "NET-001" in rule_ids or "NET-002" in rule_ids:
        questions.append("Did the scanning activity yield any successful service access?")
    if "NET-003" in rule_ids:
        questions.append("Were valid credentials for the targeted service ever entered successfully?")
    if "BEACON-001" in rule_ids:
        questions.append("Is there evidence of data staged for transfer following these periodic connections?")
    if "NET-004" in rule_ids:
        questions.append("What data, specifically, was included in the outbound transfer?")
    if "DNS-006" in rule_ids:
        questions.append("What information is being encoded in these DNS queries?")
    questions.append(f"Has {cand.endpoint} shown similar behavior at other times, or authenticated to other systems?")
    return questions


def correlate(
    capture: ParsedCapture,
    iocs: List[IOC],
    aggregation: AggregationResult,
    detections: List[DetectionSignal],
    ti_results: Dict[str, List[FeedResult]],
    config: Optional[dict] = None,
    assets: Optional[Dict[str, AssetProfile]] = None,
) -> Tuple[List[Finding], dict]:
    """Returns (findings, stats). `stats` carries observability counters
    (candidates evaluated, findings before/after deduplication) used by
    the detection-tuning report; see analyzer/reporter.py.

    `assets` is an optional IP -> AssetProfile map (see
    analyzer/assets.py, config/assets.yaml). When an endpoint or
    destination IP involved in a finding has a known asset entry, its
    criticality raises the Asset Context risk dimension and is
    reported by name; unmapped IPs are always reported as Unknown."""
    config = config or DEFAULT_CONFIG
    assets = assets or {}
    risk_cfg = config["risk"]
    bands = risk_cfg["severity_bands"]
    caps = risk_cfg["caps"]
    asset_weights = risk_cfg.get("asset_criticality_weights", DEFAULT_CONFIG["risk"]["asset_criticality_weights"])

    ti_assessments = interpret_ti_results(ti_results, config)

    active_by_indicator: Dict[str, List[DetectionSignal]] = defaultdict(list)
    signals_by_source_ip: Dict[str, List[DetectionSignal]] = defaultdict(list)
    for det in detections:
        if not det.suppressed:
            active_by_indicator[det.indicator].append(det)
            # Network/Behavioral signals (scanning, exfiltration, beaconing)
            # are inherently about the SOURCE endpoint, not the destination
            # indicator they happen to be keyed on -- tracked separately so
            # exactly one candidate per endpoint absorbs them (see below),
            # rather than every candidate for that endpoint duplicating them.
            if det.category in ("Network", "Behavioral") and det.source_ip:
                signals_by_source_ip[det.source_ip].append(det)

    candidates = _build_candidates(aggregation)
    findings: List[Finding] = []
    counter = 0
    claimed_network_endpoints: Set[str] = set()

    for cand in candidates:
        indicators = _candidate_indicators(cand)
        sig_list: List[DetectionSignal] = []
        seen_sig_keys: Set[Tuple[str, str]] = set()
        for ind in indicators:
            for det in active_by_indicator.get(ind, []):
                key = (det.rule_id, det.indicator)
                if key not in seen_sig_keys:
                    seen_sig_keys.add(key)
                    sig_list.append(det)
        # Also catch signals keyed on this endpoint directly (e.g. DNS-007
        # keys on the apex domain, which is already in `indicators` for a
        # matching DNS event, but guard for the endpoint-only case too).
        for det in active_by_indicator.get(cand.endpoint, []):
            key = (det.rule_id, det.indicator)
            if key not in seen_sig_keys:
                seen_sig_keys.add(key)
                sig_list.append(det)
        # First candidate encountered for this endpoint absorbs its
        # Network/Behavioral signals (scanning, exfil, beaconing) --
        # ensures they appear in exactly one finding for that endpoint.
        if cand.endpoint not in claimed_network_endpoints:
            claimed_network_endpoints.add(cand.endpoint)
            for det in signals_by_source_ip.get(cand.endpoint, []):
                key = (det.rule_id, det.indicator)
                if key not in seen_sig_keys:
                    seen_sig_keys.add(key)
                    sig_list.append(det)

        ti_list: List[TIAssessment] = []
        for ind in indicators:
            for a in ti_assessments.get(ind, []):
                if a.state != "UNKNOWN":
                    ti_list.append(a)

        ti_meaningful = any(a.is_meaningful for a in ti_list)
        ti_malicious = any(a.state == MALICIOUS for a in ti_list)

        # Rarity/novelty-only signals (DNS-004, DNS-005, HTTP-004) are
        # Informational by design -- weak enough that, alone, they should
        # not promote a finding any more than a WEAK_REPUTATION TI result
        # does. They still contribute to the Behavior score below when
        # something more substantial fires alongside them.
        substantive_signals = [d for d in sig_list if d.severity != INFORMATIONAL]
        if not substantive_signals and not ti_meaningful:
            continue  # neither substantive local detection nor meaningful TI -- inventory only

        counter += 1
        first_seen, last_seen = _timestamps(cand)

        # --- Risk dimensions -------------------------------------------------
        reputation = min(sum(a.weight for a in ti_list), risk_cfg["weights"]["reputation"])

        # Behavior dimension: cap each evidence FAMILY (category) before
        # summing, so several signals restating the same underlying
        # behavior (e.g. three DNS rules firing for one beaconing domain)
        # don't each contribute full independent weight -- see
        # config/detection_config.yaml -> risk.category_caps.
        category_caps = risk_cfg.get("category_caps", {})
        category_sums: Dict[str, int] = {}
        for d in sig_list:
            category_sums[d.category] = category_sums.get(d.category, 0) + d.score
        behavior_raw = sum(min(v, category_caps.get(cat, v)) for cat, v in category_sums.items())
        behavior = min(behavior_raw, risk_cfg["weights"]["behavior"])

        has_signature = any(f.signature for f in cand.file_events)
        payload = 0
        if cand.file_events:
            if has_signature and (ti_malicious or any(d.rule_id == "FILE-001" for d in sig_list)):
                payload = risk_cfg["weights"]["payload"]
            elif has_signature:
                payload = risk_cfg["weights"]["payload"] // 2

        stage_count = sum([bool(cand.dns_event), bool(cand.http_events), bool(cand.file_events)])
        network_context = risk_cfg["weights"]["network_context"] if stage_count >= 3 else (
            risk_cfg["weights"]["network_context"] // 2 if stage_count == 2 else 0)

        # --- Asset context: real lookup against config/assets.yaml ---------
        involved_ips = {cand.endpoint}
        involved_ips.update(h.dest_ip for h in cand.http_events)
        if cand.dns_event:
            involved_ips.update(cand.dns_event.resolved_ips)
        involved_ips.update(f.src_ip for f in cand.file_events)
        involved_ips.update(f.dst_ip for f in cand.file_events)
        best_asset = highest_criticality(involved_ips, assets)
        asset_context = min(asset_weights.get(best_asset.criticality, 0), risk_cfg["weights"]["asset_context"])
        asset_notes = [get_asset(ip, assets).describe() for ip in sorted(involved_ips)
                       if get_asset(ip, assets).is_known]

        total = min(reputation + behavior + payload + network_context + asset_context, 100)
        severity = band_from_score(total, bands)

        # --- Severity caps: local-heuristics-only evidence is capped -------
        if reputation == 0 and payload == 0:
            severity = min_severity(severity, caps.get("behavior_only_max_severity", "Medium"))

        # --- Confidence: independent of severity, driven by evidence diversity
        diversity = sum([reputation > 0, behavior > 0, payload > 0])
        if diversity >= 2 and (ti_malicious or payload > 0):
            confidence = "High"
        elif diversity >= 2:
            confidence = "Medium"
        elif sig_list and any(d.confidence == "High" for d in sig_list):
            confidence = "Medium"
        else:
            confidence = "Low"

        dga_flagged = any(d.rule_id == "DNS-003" for d in sig_list)
        title, category = _title_for(cand, sig_list, ti_meaningful, ti_malicious, has_signature, dga_flagged)

        domains = [cand.dns_event.domain] if cand.dns_event else []
        source_ips = [cand.endpoint]
        destination_ips = sorted({h.dest_ip for h in cand.http_events} |
                                   (cand.dns_event.resolved_ips if cand.dns_event else set()))
        hashes = sorted({f.sha256 for f in cand.file_events})
        occurrence_count = ((cand.dns_event.occurrence_count if cand.dns_event else 0)
                             + sum(h.occurrence_count for h in cand.http_events)
                             + sum(f.transfer_count for f in cand.file_events))

        evidence = [d.evidence[0] for d in sig_list if d.evidence]
        ti_evidence = [a.summary for a in ti_list] or ["No meaningful threat-intelligence match."]

        explanation_parts = []
        if cand.dns_event:
            explanation_parts.append(f"{cand.endpoint} queried {cand.dns_event.domain} "
                                       f"{cand.dns_event.occurrence_count} time(s).")
        if cand.http_events:
            hosts = ", ".join(sorted({h.host for h in cand.http_events}))
            explanation_parts.append(f"HTTP activity was observed to {hosts}.")
        if cand.file_events:
            explanation_parts.append(f"{len(cand.file_events)} distinct payload(s) were transferred, "
                                       f"{sum(1 for f in cand.file_events if f.signature)} with a "
                                       f"recognizable file signature.")
        if sig_list:
            explanation_parts.append(f"Local detection rule(s) {', '.join(sorted({d.rule_id for d in sig_list}))} "
                                       f"fired for this activity.")
        if ti_list:
            explanation_parts.append(f"Threat-intelligence assessment: "
                                       f"{', '.join(sorted({a.state for a in ti_list}))}.")
        explanation_parts.append(f"Risk score {total}/100 (Reputation {reputation}, Behavior {behavior}, "
                                   f"Payload {payload}, Network context {network_context}, "
                                   f"Asset context {asset_context}"
                                   + (f", highest-criticality asset: {best_asset.criticality}"
                                      if best_asset.is_known else " — asset role unknown")
                                   + ").")
        explanation = " ".join(explanation_parts)

        recommended_actions = _recommended_actions(cand, ti_malicious, has_signature, best_asset)
        mitre_techniques = sorted({f"{d.mitre_technique_id} — {d.mitre_technique_name}"
                                     for d in sig_list if d.mitre_technique_id})
        kill_chain_stages = stages_for([d.rule_id for d in sig_list])
        evidence_basis = _evidence_basis(cand, sig_list, ti_list, ti_malicious, has_signature)
        analyst_questions = _analyst_questions(cand, sig_list, ti_malicious, has_signature)

        findings.append(Finding(
            finding_id=f"F-{counter:03d}",
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            risk_score=total,
            affected_assets=[cand.endpoint],
            source_ips=source_ips,
            destination_ips=destination_ips,
            domains=domains,
            hashes=hashes,
            first_seen=first_seen,
            last_seen=last_seen,
            occurrence_count=occurrence_count,
            detection_signals=sig_list,
            evidence=evidence,
            threat_intelligence=ti_evidence,
            explanation=explanation,
            recommended_actions=recommended_actions,
            event_chain=_event_chain(cand, sig_list),
            asset_notes=asset_notes,
            mitre_techniques=mitre_techniques,
            kill_chain_stages=kill_chain_stages,
            evidence_basis=evidence_basis,
            analyst_questions=analyst_questions,
        ))

    findings_before_dedup = len(findings)
    findings = _deduplicate(findings, config)
    findings.sort(key=lambda f: f.risk_score, reverse=True)
    # Renumber after sort/dedup so IDs stay dense and severity-ordered.
    for idx, f in enumerate(findings, start=1):
        f.finding_id = f"F-{idx:03d}"

    stats = {
        "candidates_evaluated": len(candidates),
        "findings_before_dedup": findings_before_dedup,
        "findings_after_dedup": len(findings),
    }
    return findings, stats


def _recommended_actions(cand: _Candidate, ti_malicious: bool, has_signature: bool,
                          best_asset: AssetProfile) -> List[str]:
    actions = [f"Investigate endpoint {cand.endpoint} for signs of compromise."]
    if best_asset.is_known and best_asset.criticality in ("High", "Critical"):
        actions.insert(0, f"Escalate immediately: this finding involves {best_asset.describe()}, "
                          f"a {best_asset.criticality}-criticality asset.")
    if cand.dns_event:
        actions.append(f"Review historical DNS logs for {cand.dns_event.domain} across the environment.")
    if cand.file_events:
        for f in cand.file_events:
            actions.append(f"Search EDR/AV for SHA256 {f.sha256}.")
        actions.append("Analyze the recovered payload in an isolated sandbox before further action.")
    if cand.http_events:
        hosts = sorted({h.host for h in cand.http_events})
        actions.append(f"Search proxy/web logs for prior connections to {', '.join(hosts)}.")
    if ti_malicious:
        actions.append("Block the associated infrastructure at the network boundary per policy.")
    return actions


def _fingerprint(f: Finding) -> Tuple:
    return (
        tuple(sorted(f.source_ips)),
        tuple(sorted(f.domains)),
        tuple(sorted(f.hashes)),
        tuple(sorted(f.destination_ips)),
    )


def _deduplicate(findings: List[Finding], config: dict) -> List[Finding]:
    """Merge findings that describe the same endpoint + indicator set
    (e.g. produced from overlapping candidates) rather than reporting
    them as separate incidents. Occurrence counts, evidence and
    first/last-seen are combined; nothing is discarded."""
    merged: Dict[Tuple, Finding] = {}
    for f in findings:
        key = _fingerprint(f)
        existing = merged.get(key)
        if existing is None:
            merged[key] = f
            continue
        existing.occurrence_count += f.occurrence_count
        existing.evidence = list(dict.fromkeys(existing.evidence + f.evidence))
        existing.threat_intelligence = list(dict.fromkeys(existing.threat_intelligence + f.threat_intelligence))
        existing.detection_signals = existing.detection_signals + [
            d for d in f.detection_signals if d not in existing.detection_signals]
        existing.recommended_actions = list(dict.fromkeys(existing.recommended_actions + f.recommended_actions))
        existing.asset_notes = list(dict.fromkeys(existing.asset_notes + f.asset_notes))
        existing.mitre_techniques = list(dict.fromkeys(existing.mitre_techniques + f.mitre_techniques))
        existing.kill_chain_stages = list(dict.fromkeys(existing.kill_chain_stages + f.kill_chain_stages))
        existing.analyst_questions = list(dict.fromkeys(existing.analyst_questions + f.analyst_questions))
        for tier in ("established", "strongly_indicated", "possible", "not_established"):
            existing.evidence_basis[tier] = list(dict.fromkeys(
                existing.evidence_basis.get(tier, []) + f.evidence_basis.get(tier, [])))
        if f.first_seen and (not existing.first_seen or f.first_seen < existing.first_seen):
            existing.first_seen = f.first_seen
        if f.last_seen and (not existing.last_seen or f.last_seen > existing.last_seen):
            existing.last_seen = f.last_seen
        if f.risk_score > existing.risk_score:
            existing.risk_score = f.risk_score
            existing.severity = f.severity
            existing.confidence = f.confidence
    return list(merged.values())


@dataclass
class Incident:
    """A higher-level grouping of Findings that share the same
    endpoint -- this is what turns "Finding 1, Finding 2, Finding 3"
    belonging to one host's activity into one coherent incident
    narrative, per the brief's incident-reconstruction requirement."""
    incident_id: str
    title: str
    severity: str
    confidence: str
    risk_score: int
    findings: List[Finding]
    affected_assets: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    narrative: str
    kill_chain_stages: List[str]
    mitre_techniques: List[str]


def build_incidents(findings: List[Finding]) -> List[Incident]:
    """Group findings by their (single) affected endpoint. An endpoint
    with only one finding still gets an Incident wrapper (so the report
    has one consistent structure to render), but the narrative and
    kill-chain view are most valuable when 2+ findings for the same
    endpoint combine into a single story."""
    by_endpoint: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        endpoint = f.affected_assets[0] if f.affected_assets else "unknown"
        by_endpoint[endpoint].append(f)

    severity_rank_order = ["Informational", "Low", "Medium", "High", "Critical"]
    incidents: List[Incident] = []
    for idx, (endpoint, group) in enumerate(sorted(by_endpoint.items(), key=lambda kv: -max(f.risk_score for f in kv[1])), start=1):
        group = sorted(group, key=lambda f: (f.first_seen or datetime.min))
        severity = max(group, key=lambda f: severity_rank_order.index(f.severity)).severity
        confidence = max((f.confidence for f in group),
                          key=lambda c: {"Low": 0, "Medium": 1, "High": 2}.get(c, 0))
        risk_score = max(f.risk_score for f in group)
        first_seen = min((f.first_seen for f in group if f.first_seen), default=None)
        last_seen = max((f.last_seen for f in group if f.last_seen), default=None)
        stages: List[str] = []
        for f in group:
            for s in f.kill_chain_stages:
                if s not in stages:
                    stages.append(s)
        techniques = sorted({t for f in group for t in f.mitre_techniques})

        if len(group) > 1:
            titles = [f.title for f in group]
            title = f"Multi-stage activity involving {endpoint}"
            narrative_steps = [f"{f.first_seen.strftime('%H:%M:%S') if f.first_seen else '??:??:??'} — "
                                f"{f.title} (severity {f.severity}, {f.finding_id})" for f in group]
            narrative = (f"{endpoint} is associated with {len(group)} correlated findings in this "
                         f"capture: {', '.join(titles)}. Chronologically: " + "; ".join(narrative_steps) + ".")
        else:
            title = group[0].title
            narrative = group[0].explanation

        incidents.append(Incident(
            incident_id=f"INC-{idx:03d}",
            title=title,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            findings=group,
            affected_assets=[endpoint],
            first_seen=first_seen,
            last_seen=last_seen,
            narrative=narrative,
            kill_chain_stages=stages,
            mitre_techniques=techniques,
        ))

    return incidents


def build_timeline(aggregation: AggregationResult, findings: List[Finding]) -> List[TimelineEvent]:
    """Behavioral timeline: one entry per behavioral event (not per
    packet), referencing the finding it contributed to when there is one."""
    finding_by_indicator: Dict[str, str] = {}
    for f in findings:
        for ind in (f.domains + f.destination_ips + f.hashes + f.source_ips):
            finding_by_indicator.setdefault(ind, f.finding_id)

    events: List[TimelineEvent] = []
    for ev in aggregation.dns_events:
        events.append(TimelineEvent(
            ev.first_seen,
            f"{ev.source_ip} queried {ev.domain} ({ev.occurrence_count} time(s), "
            f"{ev.first_seen.strftime('%H:%M:%S')}–{ev.last_seen.strftime('%H:%M:%S')})",
            finding_id=finding_by_indicator.get(ev.domain),
        ))
    for ev in aggregation.http_events:
        paths = ", ".join(ev.paths[:3]) + ("..." if len(ev.paths) > 3 else "") if ev.paths else "/"
        events.append(TimelineEvent(
            ev.first_seen,
            f"{ev.source_ip} \u2192 {ev.dest_ip} HTTP activity to {ev.host} "
            f"({ev.occurrence_count} request(s): {paths})",
            finding_id=finding_by_indicator.get(ev.dest_ip) or finding_by_indicator.get(ev.host),
        ))
    for ev in aggregation.file_events:
        events.append(TimelineEvent(
            ev.first_seen,
            f"Payload transferred {ev.src_ip} \u2192 {ev.dst_ip} "
            f"({ev.signature or 'unrecognized'}, SHA256 {ev.sha256[:16]}...)",
            finding_id=finding_by_indicator.get(ev.sha256),
        ))
    for src_ip, cand in aggregation.scan_candidates.items():
        if cand.first_seen is None:
            continue
        events.append(TimelineEvent(
            cand.first_seen,
            f"{src_ip} attempted connections to {len(cand.distinct_dst_ips)} distinct IP(s) / "
            f"{len(cand.distinct_dst_ports)} distinct port(s), {cand.success_ratio:.0%} success ratio "
            f"({cand.total_syn} attempt(s))",
            finding_id=finding_by_indicator.get(src_ip),
        ))
    events.sort(key=lambda e: e.timestamp)
    return events
