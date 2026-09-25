"""Builds the Markdown security report (reports/security_report.md).

Structure follows an analyst-investigation flow:
    1.  Executive Summary
    2.  Investigation Scope
    3.  Incidents & Key Findings   (findings grouped into incidents;
                                     each shows MITRE mapping, kill-chain
                                     stage, and an explicit "what we know /
                                     strongly indicated / possible / not
                                     established" breakdown)
    4.  Investigation Recommendations
    5.  Attack Timeline             (behavioral, not per-packet)
    6.  Attack Chain / Kill-Chain View
    7.  Entity / Infrastructure Summary
    8.  Threat Intelligence Summary
    9.  Technical Evidence          (drill-down: aggregated DNS/HTTP/file/
                                     network tables)
    10. IOC Inventory
    11. Detection Coverage Self-Test
    12. Unclassified / Observed Traffic
    13. Appendix                    (raw TI incl. no-record lookups,
                                     suppressed signals, rule tuning
                                     report, observability stats,
                                     limitations, references)

The same evidence is stated once and referenced by finding/incident ID
afterwards rather than being repeated block-for-block across sections.
"""

from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional

from analyzer.aggregator import AggregationResult
from analyzer.correlator import Finding, Incident, TimelineEvent
from analyzer.coverage import build_coverage_report
from analyzer.detector import DetectionSignal
from analyzer.ioc_extractor import IOC
from analyzer.ioc_scoring import IOCProfile, summarize_tiers
from analyzer.ti_interpreter import TIAssessment
from feeds.base import FeedResult

TOOL_NAME = "Threat Intelligence Automation Tool"
TOOL_VERSION = "3.0.0"


def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return "_No data available for this table._\n"
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        safe_row = [str(c).replace("|", "\\|").replace("\n", " ") for c in row]
        lines.append("| " + " | ".join(safe_row) + " |")
    return "\n".join(lines) + "\n"


def _rule_tuning_report(detections: List[DetectionSignal], findings: List[Finding]) -> List[List[str]]:
    by_rule: Dict[str, List[DetectionSignal]] = defaultdict(list)
    for d in detections:
        by_rule[d.rule_id].append(d)

    rule_in_findings: Dict[str, int] = defaultdict(int)
    for f in findings:
        for d in f.detection_signals:
            rule_in_findings[d.rule_id] += 1

    rows = []
    for rule_id, sigs in sorted(by_rule.items()):
        triggered = len(sigs)
        suppressed = sum(1 for s in sigs if s.suppressed)
        active = [s for s in sigs if not s.suppressed]
        avg_conf = Counter(s.confidence for s in active).most_common(1)
        avg_conf_str = avg_conf[0][0] if avg_conf else "N/A"
        avg_score = round(sum(s.score for s in active) / len(active), 1) if active else 0.0
        rows.append([rule_id, sigs[0].title, str(triggered), str(suppressed),
                     str(rule_in_findings.get(rule_id, 0)), avg_conf_str, str(avg_score)])
    return rows


def _unclassified_traffic(aggregation: AggregationResult, detections: List[DetectionSignal]) -> List[List[str]]:
    """Notable-volume activity that no rule flagged -- requirement #29:
    'do not ignore traffic simply because no rule matches'."""
    flagged_indicators = {d.indicator for d in detections if not d.suppressed}
    rows: List[List[str]] = []

    for ev in aggregation.dns_events:
        if ev.domain not in flagged_indicators and ev.occurrence_count >= 3:
            rows.append(["DNS", ev.source_ip, ev.domain, str(ev.occurrence_count)])
    for ev in aggregation.http_events:
        if ev.host not in flagged_indicators and ev.occurrence_count >= 3:
            rows.append(["HTTP", ev.source_ip, ev.host, str(ev.occurrence_count)])
    for src_ip, cand in aggregation.scan_candidates.items():
        if src_ip not in flagged_indicators and len(cand.attempts) >= 3:
            rows.append(["TCP", src_ip, f"{len(cand.distinct_dst_ips)} dest IP(s)", str(cand.total_syn)])

    rows.sort(key=lambda r: -int(r[3]))
    return rows[:20]


def generate_markdown_report(
    output_path: str,
    pcap_path: str,
    capture,
    iocs: List[IOC],
    aggregation: AggregationResult,
    detections: List[DetectionSignal],
    ti_results: Dict[str, List[FeedResult]],
    ti_assessments: Dict[str, List[TIAssessment]],
    ioc_profiles: Dict[str, IOCProfile],
    findings: List[Finding],
    timeline: List[TimelineEvent],
    unavailable_feeds: List[str],
    correlation_stats: dict,
    incidents: Optional[List[Incident]] = None,
    analyst: str = "SOC Analyst",
) -> None:
    lines: List[str] = []
    a = lines.append
    if not incidents and findings:
        # Defensive fallback: a caller that passes findings without also
        # building incidents should not silently produce a report that
        # claims no findings exist. build_incidents(findings) is cheap
        # and always non-empty when findings is non-empty.
        from analyzer.correlator import build_incidents
        incidents = build_incidents(findings)
    incidents = incidents if incidents is not None else []

    unique_ips = {i.indicator for i in iocs if i.type in ("ipv4", "ipv6")}
    unique_domains = {i.indicator for i in iocs if i.type == "domain"}
    active_detections = [d for d in detections if not d.suppressed]
    suppressed_detections = [d for d in detections if d.suppressed]
    severity_counts = Counter(f.severity for f in findings)
    tier_counts = summarize_tiers(ioc_profiles)
    internal_ips = capture.internal_ips() if hasattr(capture, "internal_ips") else set()
    external_ips = capture.external_ips() if hasattr(capture, "external_ips") else set()

    ti_meaningful = [a_ for assessments in ti_assessments.values() for a_ in assessments
                      if a_.is_meaningful]
    ti_weak = [a_ for assessments in ti_assessments.values() for a_ in assessments
                if a_.state == "WEAK_REPUTATION"]
    ti_clean_or_unknown = [a_ for assessments in ti_assessments.values() for a_ in assessments
                            if a_.state in ("CLEAN", "UNKNOWN")]

    # ================= Header =================
    a("# Threat Intelligence & Network Security Analysis Report")
    a("")
    a(f"- **PCAP file:** `{pcap_path}`")
    a(f"- **Analysis date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    a(f"- **Tool:** {TOOL_NAME} v{TOOL_VERSION}")
    a(f"- **Analyst:** {analyst}")
    a("")
    a("---")
    a("")

    # ================= 1. Executive Summary =================
    a("## 1. Executive Summary")
    a("")
    if severity_counts.get("Critical") or severity_counts.get("High"):
        status = "SUSPICIOUS ACTIVITY IDENTIFIED"
    elif findings:
        status = "LOW-SEVERITY ACTIVITY OBSERVED"
    else:
        status = "NO CORRELATED FINDINGS"
    a(f"**Status:** {status}")
    a("")

    involved_endpoints = sorted({ip for inc in incidents for ip in inc.affected_assets})
    all_categories = sorted({f.category for f in findings})
    strongest = max(findings, key=lambda f: f.risk_score, default=None)
    a(f"- **What happened:** " + (f"{len(incidents)} incident(s) covering {len(findings)} correlated "
      f"finding(s) were identified." if findings else
      "No activity in this capture met the bar for a correlated security finding."))
    if involved_endpoints:
        a(f"- **Host(s) involved:** {', '.join(involved_endpoints[:10])}"
          f"{' (+' + str(len(involved_endpoints) - 10) + ' more)' if len(involved_endpoints) > 10 else ''}")
    if all_categories:
        a(f"- **Behavior categories observed:** {', '.join(all_categories)}")
    if strongest:
        a(f"- **Strongest evidence:** {strongest.finding_id} ({strongest.title}), risk score "
          f"{strongest.risk_score}/100, confidence {strongest.confidence}.")
    not_established_all = sorted({item for f in findings for item in f.evidence_basis.get("not_established", [])})
    if not_established_all:
        a(f"- **What cannot be established from this capture:** {not_established_all[0]}"
          + (f" ({len(not_established_all) - 1} more point(s) noted per-finding below)"
             if len(not_established_all) > 1 else ""))
    a("")
    a(f"- Packets analyzed: {capture.total_packets}")
    a(f"- Unique source IPs: {len({p.src_ip for p in capture.packets if p.src_ip})}")
    a(f"- Unique destination IPs: {len({p.dst_ip for p in capture.packets if p.dst_ip})}")
    a(f"- Unique public IP indicators: {len(unique_ips)}")
    a(f"- Unique domains: {len(unique_domains)}")
    a(f"- IOCs extracted: {len(iocs)}")
    a(f"- Detection signals raised: {len(detections)} ({len(active_detections)} active, "
      f"{len(suppressed_detections)} suppressed by allowlist)")
    a(f"- Correlated findings: {len(findings)} grouped into {len(incidents)} incident(s)")
    a("")
    if findings:
        a("**Findings by severity**")
        a("")
        a(_md_table(["Severity", "Count"],
                    [[sev, str(severity_counts.get(sev, 0))]
                     for sev in ("Critical", "High", "Medium", "Low", "Informational")
                     if severity_counts.get(sev, 0)]))
    a("")

    # ================= 2. Investigation Scope =================
    a("## 2. Investigation Scope")
    a("")
    a(_md_table(["Item", "Value"], [
        ["PCAP analyzed", pcap_path],
        ["Capture duration", f"{capture.duration_seconds():.1f} seconds" if hasattr(capture, "duration_seconds") else "N/A"],
        ["Packet count", str(capture.total_packets)],
        ["Protocols observed", ", ".join(f"{p} ({c})" for p, c in capture.protocol_counts().items()) or "N/A"],
        ["Internal hosts observed", str(len(internal_ips))],
        ["External hosts observed", str(len(external_ips))],
    ]))
    a("Limitations affecting this analysis are detailed in full in Section 13.6; in brief: "
      "encrypted traffic is not inspected beyond metadata, TLS/JA3 fingerprinting and "
      "protocol-level (SSH/FTP/RDP/SMB) credential decoding are not implemented, and the "
      "risk score is a project-defined prioritization aid, not proof of compromise.")
    a("")

    # ================= 3. Incidents & Key Findings =================
    a("## 3. Incidents & Key Findings")
    a("")
    if incidents:
        a("Findings are grouped into incidents by shared endpoint. Only correlated, "
          "evidence-backed findings appear here -- an indicator observed with no "
          "corroborating evidence appears only in the IOC Inventory (Section 10).")
        a("")
        for inc in incidents:
            a(f"### {inc.incident_id} — {inc.title}")
            a("")
            a(f"- **Severity:** {inc.severity} &nbsp;|&nbsp; **Confidence:** {inc.confidence} "
              f"&nbsp;|&nbsp; **Risk score:** {inc.risk_score}/100")
            a(f"- **Affected endpoint(s):** {', '.join(inc.affected_assets)}")
            a(f"- **Time window:** {inc.first_seen.strftime('%H:%M:%S') if inc.first_seen else 'N/A'} "
              f"– {inc.last_seen.strftime('%H:%M:%S') if inc.last_seen else 'N/A'}")
            if inc.kill_chain_stages:
                a(f"- **Kill-chain stages observed:** {' \u2192 '.join(inc.kill_chain_stages)}")
            if inc.mitre_techniques:
                a(f"- **MITRE ATT&CK technique(s):** {', '.join(inc.mitre_techniques)}")
            a("")
            a(f"**Narrative:** {inc.narrative}")
            a("")
            for f in inc.findings:
                a(f"#### {f.finding_id} — {f.title}")
                a("")
                a(f"- Severity: {f.severity} | Confidence: {f.confidence} | Risk score: {f.risk_score}/100")
                a(f"- Category: {f.category}")
                a(f"- Destinations: {', '.join(f.destination_ips) or 'N/A'}"
                  + (f" | Domain(s): {', '.join(f.domains)}" if f.domains else "")
                  + (f" | Hash(es): {', '.join(h[:16] + '...' for h in f.hashes)}" if f.hashes else ""))
                a(f"- Detection rule(s): {', '.join(sorted({d.rule_id for d in f.detection_signals})) or 'None (TI-only)'}")
                a("")
                if f.evidence:
                    a("**Evidence:**")
                    for e in f.evidence:
                        a(f"- {e}")
                    a("")
                a("**Threat intelligence:**")
                for t in f.threat_intelligence:
                    a(f"- {t}")
                a("")
                basis = f.evidence_basis
                if any(basis.get(k) for k in ("established", "strongly_indicated", "possible", "not_established")):
                    a("**What we know:**")
                    if basis.get("established"):
                        a("- _Established:_ " + " ".join(basis["established"]))
                    if basis.get("strongly_indicated"):
                        a("- _Strongly indicated:_ " + " ".join(basis["strongly_indicated"]))
                    if basis.get("possible"):
                        a("- _Possible:_ " + " ".join(basis["possible"]))
                    if basis.get("not_established"):
                        a("- _Not established:_ " + " ".join(basis["not_established"]))
                    a("")
                if f.analyst_questions:
                    a("**Suggested next questions:**")
                    for q in f.analyst_questions:
                        a(f"- {q}")
                    a("")
    else:
        a("No correlated findings were produced. This means no substantive local "
          "detection signal and no meaningful (SUSPICIOUS/MALICIOUS) threat-intelligence "
          "assessment applied to any extracted indicator. See Section 10 for the full IOC "
          "inventory, Section 11 for detection coverage, and Section 13 for low-confidence/"
          "suppressed signals that did not meet the bar for a finding.")
        a("")

    # ================= 4. Investigation Recommendations =================
    a("## 4. Investigation Recommendations")
    a("")
    if findings:
        for f in findings:
            a(f"**{f.finding_id} — {f.title}:**")
            for rec in f.recommended_actions:
                a(f"- {rec}")
            a("")
    else:
        a("No finding-specific recommendations apply. Standing guidance: continue "
          "routine DNS/proxy log review and re-run threat-intelligence correlation "
          "periodically, since feed coverage changes over time even when the "
          "capture does not.")
        a("")

    # ================= 5. Attack Timeline =================
    a("## 5. Attack Timeline")
    a("")
    a("Aggregated behavioral events, not individual packets -- each row already "
      "summarizes every underlying observation it represents.")
    a("")
    if timeline:
        rows = [[ev.timestamp.strftime("%H:%M:%S"), ev.description, ev.finding_id or "-"]
                 for ev in timeline[:80]]
        a(_md_table(["Timestamp (UTC)", "Behavioral event", "Related finding"], rows))
    else:
        a("Not available in supplied PCAP.\n")

    # ================= 6. Attack Chain / Kill-Chain View =================
    a("## 6. Attack Chain / Kill-Chain View")
    a("")
    chained = [f for f in findings if f.event_chain]
    if chained:
        for f in chained:
            a(f"**{f.finding_id} — {f.title}**")
            a("")
            a("```")
            a(f.event_chain)
            if f.threat_intelligence and f.threat_intelligence != ["No meaningful threat-intelligence match."]:
                a("  \u2193")
                a("Threat Intelligence")
            a("```")
            if f.kill_chain_stages:
                a(f"MITRE tactics: {' \u2192 '.join(f.kill_chain_stages)}")
            a("")
    else:
        a("No finding in this capture was supported by a multi-stage event chain "
          "(reconnaissance/DNS \u2192 connection \u2192 HTTP \u2192 file/exfiltration). "
          "Single-stage findings are listed in Section 3 without a chain diagram.")
        a("")

    # ================= 7. Entity / Infrastructure Summary =================
    a("## 7. Entity / Infrastructure Summary")
    a("")
    a("### Internal entities")
    a("")
    internal_rows = []
    for ip in sorted(internal_ips)[:30]:
        related = [f.finding_id for f in findings if ip in f.affected_assets]
        internal_rows.append([ip, ", ".join(related) or "-"])
    a(_md_table(["IP", "Related finding(s)"], internal_rows))
    a("### External entities")
    a("")
    external_rows = []
    for ip in sorted(external_ips)[:30]:
        related = [f.finding_id for f in findings if ip in f.destination_ips]
        ti_states = sorted({a_.state for a_ in ti_assessments.get(ip, []) if a_.state != "UNKNOWN"})
        external_rows.append([ip, ", ".join(related) or "-", ", ".join(ti_states) or "-"])
    a(_md_table(["IP", "Related finding(s)", "TI state(s)"], external_rows))

    # ================= 8. Threat Intelligence Summary =================
    a("## 8. Threat Intelligence Summary")
    a("")
    a(f"- Indicators analyzed: {len(iocs)}")
    a(f"- Meaningful TI matches (Suspicious/Malicious): {len(ti_meaningful)}")
    a(f"- Weak reputation (not a finding on its own): {len(ti_weak)}")
    a(f"- Clean / no meaningful record: {len(ti_clean_or_unknown)}")
    if unavailable_feeds:
        a(f"- Feeds unavailable during this run: {', '.join(unavailable_feeds)} "
          f"(results from these feeds are incomplete, not a clean verdict)")
    a("")
    meaningful_rows = [[a_.indicator, a_.feed, a_.state, a_.confidence, a_.summary] for a_ in ti_meaningful]
    if meaningful_rows:
        a("**Meaningful indicators only** (full raw results, including no-record "
          "lookups, are in Section 13.2):")
        a("")
        a(_md_table(["IOC", "Feed", "State", "Confidence", "Summary"], meaningful_rows[:50]))
    a("")

    # ================= 9. Technical Evidence =================
    a("## 9. Technical Evidence")
    a("")
    a(f"Raw observations: {aggregation.raw_dns_observations} DNS record(s), "
      f"{aggregation.raw_http_observations} HTTP record(s), "
      f"{aggregation.raw_file_observations} file transfer(s), "
      f"{aggregation.raw_packet_observations} raw packet(s) — aggregated below into "
      f"{len(aggregation.dns_events)} DNS behavioral event(s), "
      f"{len(aggregation.http_events)} HTTP behavioral event(s), "
      f"{len(aggregation.file_events)} distinct file behavioral event(s), and "
      f"{len(aggregation.connection_attempts)} TCP connection-attempt behavioral event(s).")
    a("")

    a("### Protocol / traffic distribution")
    a("")
    proto_counts = capture.protocol_counts()
    a(_md_table(["Protocol", "Packet Count"], [[p, str(c)] for p, c in proto_counts.items()]))

    a("### DNS behavioral events")
    a("")
    if aggregation.dns_events:
        rows = [[ev.source_ip, ev.domain, ev.query_type, str(ev.occurrence_count),
                  f"{ev.nxdomain_ratio:.0%}" if ev.occurrence_count else "0%",
                  ", ".join(sorted(ev.resolved_ips)) or "-",
                  ev.first_seen.strftime("%H:%M:%S"), ev.last_seen.strftime("%H:%M:%S")]
                 for ev in aggregation.dns_events[:60]]
        a(_md_table(["Source", "Domain", "Type", "Occurrences", "NXDOMAIN %",
                      "Resolved IP(s)", "First seen", "Last seen"], rows))
    else:
        a("No DNS activity was observed in the supplied PCAP.\n")

    a("### HTTP behavioral events")
    a("")
    if aggregation.http_events:
        rows = [[ev.source_ip, ev.dest_ip, ev.host, str(ev.occurrence_count),
                  ", ".join(ev.paths[:3]) + ("..." if len(ev.paths) > 3 else ""),
                  ev.user_agent or "-"]
                 for ev in aggregation.http_events[:60]]
        a(_md_table(["Source", "Destination", "Host", "Requests", "Path(s)", "User-Agent"], rows))
    else:
        a("No HTTP activity was observed or parsable in the supplied PCAP "
          "(traffic may be encrypted or use an unsupported protocol version).\n")

    a("### File transfer behavioral events")
    a("")
    if aggregation.file_events:
        rows = [[ev.src_ip, ev.dst_ip, str(ev.size), ev.signature or "unrecognized",
                  str(ev.transfer_count), ev.sha256]
                 for ev in aggregation.file_events[:30]]
        a(_md_table(["Source", "Destination", "Size (bytes)", "Signature", "Transfers", "SHA256"], rows))
    else:
        a("No complete files could be reassembled from the supplied PCAP.\n")

    a("### TCP connection-attempt behavioral events")
    a("")
    if aggregation.connection_attempts:
        rows = [[a_.src_ip, a_.dst_ip, str(a_.dst_port), str(a_.syn_count), str(a_.synack_count),
                  str(a_.rst_count), f"{a_.bytes_src_to_dst:,}", f"{a_.bytes_dst_to_src:,}"]
                 for a_ in sorted(aggregation.connection_attempts, key=lambda x: -x.syn_count)[:40]]
        a(_md_table(["Source", "Destination", "Port", "SYN", "SYN-ACK", "RST",
                      "Bytes src\u2192dst", "Bytes dst\u2192src"], rows))
    else:
        a("No TCP connection metadata was available in the supplied PCAP.\n")

    # ================= 10. IOC Inventory =================
    a("## 10. IOC Inventory")
    a("")
    a("This inventory lists every indicator extracted from the capture. Listing an "
      "indicator here does **not** imply it is malicious -- see the significance "
      "tier and Section 3 for which indicators actually became findings.")
    a("")
    a(_md_table(["Tier", "Count"], [[t.replace("_", " ").title(), str(c)]
                                       for t, c in tier_counts.items()]))
    a("")
    priority_profiles = sorted(
        [p for p in ioc_profiles.values() if p.tier in ("suspicious", "high-priority")],
        key=lambda p: -p.significance)
    if priority_profiles:
        a("**Noteworthy and above:**")
        a("")
        rows = [[p.indicator, p.ioc_type, p.tier, str(p.significance),
                  ", ".join(sorted(set(p.detection_rule_ids))) or "-",
                  ", ".join(sorted(set(p.ti_states))) or "-"]
                 for p in priority_profiles[:40]]
        a(_md_table(["Indicator", "Type", "Tier", "Significance", "Detection rule(s)", "TI state(s)"], rows))
    else:
        a("No indicator scored above the 'noteworthy' significance threshold.\n")

    # ================= 11. Detection Coverage Self-Test =================
    a("## 11. Detection Coverage Self-Test")
    a("")
    a("For each conceptual detection category, whether it was detected IN THIS "
      "CAPTURE (not whether the capability generally exists) -- and, for categories "
      "genuinely not implemented in this build, that is stated plainly rather than "
      "silently omitted.")
    a("")
    coverage_rows = build_coverage_report(detections)
    rows = [[r.category, ", ".join(r.rule_ids) or "-",
              ("Yes" if r.detected else "No") if r.implemented else "Not implemented",
              str(r.signal_count), r.max_confidence]
             for r in coverage_rows]
    a(_md_table(["Category", "Rule(s)", "Detected?", "Signal count", "Max confidence"], rows))
    a("")

    # ================= 12. Unclassified / Observed Traffic =================
    a("## 12. Unclassified / Observed Traffic")
    a("")
    a("Notable-volume activity that no detection rule flagged. This is visibility, "
      "not a finding -- absence of a rule match does not mean the activity is safe, "
      "only that it did not meet any implemented rule's threshold.")
    a("")
    unclassified_rows = _unclassified_traffic(aggregation, detections)
    if unclassified_rows:
        a(_md_table(["Protocol", "Source", "Destination/Domain", "Volume"], unclassified_rows))
    else:
        a("No notable-volume activity was left unclassified in this capture.\n")

    # ================= 13. Appendix =================
    a("## 13. Appendix")
    a("")

    a("### 13.1 Threat-intelligence summary")
    a("")
    a(f"- Indicators analyzed: {len(iocs)}")
    a(f"- Meaningful TI matches (Suspicious/Malicious): {len(ti_meaningful)}")
    a(f"- Weak reputation (not a finding on its own): {len(ti_weak)}")
    a(f"- Clean / no meaningful record: {len(ti_clean_or_unknown)}")
    a("")

    a("### 13.2 Raw threat-intelligence results (including no-record lookups)")
    a("")
    ti_rows = []
    for indicator, assessments in ti_assessments.items():
        for asmt in assessments:
            ti_rows.append([indicator, asmt.feed, asmt.state, asmt.confidence, asmt.summary])
    if ti_rows:
        a(_md_table(["IOC", "Feed", "State", "Confidence", "Summary"], ti_rows[:150]))
    else:
        a("No indicators were submitted for threat-intelligence lookup "
          "(e.g. run with `--no-ti`, or no qualifying IOCs were extracted).\n")

    a("### 13.3 Suppressed and low-confidence detection signals")
    a("")
    if suppressed_detections:
        rows = [[d.rule_id, d.indicator, d.suppression_reason or "-",
                  d.suppression_entry or "-", str(d.occurrence_count)]
                 for d in suppressed_detections[:60]]
        a(_md_table(["Rule", "Indicator", "Suppression reason", "Matched allowlist entry", "Occurrences"], rows))
    else:
        a("No detection signals were suppressed by the allowlist in this run.\n")

    a("### 13.4 Detection tuning report")
    a("")
    tuning_rows = _rule_tuning_report(detections, findings)
    if tuning_rows:
        a(_md_table(["Rule", "Title", "Triggered", "Suppressed", "In findings", "Avg. confidence", "Avg. score"],
                     tuning_rows))
    else:
        a("No detection rule fired in this run.\n")

    a("### 13.5 Observability / pipeline statistics")
    a("")
    a(_md_table(["Metric", "Count"], [
        ["Raw packets", str(capture.total_packets)],
        ["Raw DNS observations", str(aggregation.raw_dns_observations)],
        ["Raw HTTP observations", str(aggregation.raw_http_observations)],
        ["Raw file observations", str(aggregation.raw_file_observations)],
        ["Behavioral events (DNS)", str(len(aggregation.dns_events))],
        ["Behavioral events (HTTP)", str(len(aggregation.http_events))],
        ["Behavioral events (File)", str(len(aggregation.file_events))],
        ["Behavioral events (Connection)", str(len(aggregation.connection_attempts))],
        ["Detection signals raised", str(len(detections))],
        ["Detection signals suppressed", str(len(suppressed_detections))],
        ["Correlation candidates evaluated", str(correlation_stats.get("candidates_evaluated", 0))],
        ["Findings before deduplication", str(correlation_stats.get("findings_before_dedup", 0))],
        ["Findings after deduplication", str(correlation_stats.get("findings_after_dedup", len(findings)))],
        ["Incidents", str(len(incidents))],
    ]))

    a("### 13.6 Limitations")
    a("")
    a("- Encrypted traffic cannot be inspected beyond metadata.")
    a("- TLS/JA3 fingerprinting, certificate inspection, and protocol-level decoding of "
      "SSH/FTP/RDP/SMB are NOT implemented -- this parser has no TLS or those protocols' "
      "layers available, so NET-003 (repeated authentication-service connection attempts) "
      "reports connection-level evidence only and explicitly does not claim any credential "
      "was actually attempted.")
    a("- DNS query<->response pairing uses the DNS transaction ID when present, which is "
      "exact; only when a response's transaction ID has no matching outstanding query in this "
      "capture does resolution data fall back to being merged into every client bucket for the "
      "same (domain, query type) pair.")
    a("- The apex-domain grouping used for DNS-006/007 is a last-two-labels/public-suffix-list "
      "approximation (see analyzer/public_suffixes.py) and may not cover every ccTLD.")
    a("- DNS-005's 'newly observed' baseline is local to this tool's own history "
      "(cache/domain_history.json), not a commercial passive-DNS/domain-age feed -- it starts "
      "empty and becomes more useful as more captures are analyzed.")
    a("- DNS-008 fast-flux and NET-001/002 scan detection have no ASN/geolocation diversity "
      "signal available in this environment; they rely on distinct-IP/port counts and timing.")
    a("- NET-004 (possible data exfiltration) is a byte-volume/asymmetry heuristic only -- it "
      "does not inspect payload content and cannot confirm what, if anything, was transferred.")
    a("- HTTP-008 (web attack request patterns) matches request structure only; it does not "
      "inspect server responses and cannot establish whether any attempt succeeded.")
    a("- Asset context (Section 3's affected-endpoint notes, and the Asset Context risk "
      "dimension) is populated from config/assets.yaml; an IP with no entry there is always "
      "reported as 'Asset role: Unknown' rather than guessed.")
    a("- Threat-intelligence feeds are rate-limited and may be unavailable at "
      "scan time; the report states this explicitly rather than treating an "
      "unavailable feed as a clean result.")
    a("- The risk score is a project-defined prioritization aid, not an "
      "industry-standard rating, and a single indicator match is never proof "
      "of compromise on its own.")
    a("")

    a("### 13.7 References")
    a("")
    a("- AbuseIPDB — <https://www.abuseipdb.com>")
    a("- VirusTotal — <https://www.virustotal.com>")
    a("- URLhaus (abuse.ch) — <https://urlhaus.abuse.ch>")
    a("- MITRE ATT&CK — <https://attack.mitre.org>")
    a("")

    # ================= Conclusion =================
    a("## Conclusion")
    a("")
    high_findings = [f for f in findings if f.severity in ("Critical", "High")]
    if high_findings:
        conclusion = (f"This analysis identified {len(high_findings)} finding(s) rated High or "
                       "Critical severity across " + f"{len({f.affected_assets[0] for f in high_findings})} "
                       "endpoint(s), each backed by correlated behavioral and/or threat-"
                       "intelligence evidence (Section 3). Analysts should prioritize review of "
                       "these findings and follow the recommendations in Section 4.")
    elif findings:
        conclusion = ("This analysis identified findings of Low or Medium severity only. None "
                       "reached High or Critical severity; the correlated evidence above warrants "
                       "routine follow-up consistent with local SOC procedure.")
    else:
        conclusion = ("Based on the evidence recovered from the supplied capture and the threat-"
                       "intelligence lookups performed, no indicator met the bar for a correlated "
                       "security finding. This does not guarantee the absence of malicious "
                       "activity, particularly within encrypted traffic not inspected by this tool.")
    a(conclusion)
    a("")

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
