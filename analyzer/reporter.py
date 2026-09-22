"""Builds the Markdown security report (reports/security_report.md).

Structure is analyst-first, per the refactor brief:
    1. Executive Summary
    2. Key Findings                 (correlated findings only)
    3. Investigation Recommendations
    4. Attack / Behavior Story      (event chains, when evidence supports one)
    5. Technical Evidence           (aggregated DNS/HTTP/file activity)
    6. IOC Inventory                (all IOCs, with significance tiers --
                                      not implying every IOC is malicious)
    7. Appendix                     (raw TI results incl. no-record lookups,
                                      suppressed/low-confidence signals,
                                      detection tuning report, debug stats)

The same evidence is stated once and referenced by finding ID
afterwards rather than being repeated block-for-block.
"""

from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List

from analyzer.aggregator import AggregationResult
from analyzer.correlator import Finding, TimelineEvent
from analyzer.detector import DetectionSignal
from analyzer.ioc_extractor import IOC
from analyzer.ioc_scoring import IOCProfile, summarize_tiers
from analyzer.ti_interpreter import TIAssessment
from feeds.base import FeedResult

TOOL_NAME = "Threat Intelligence Automation Tool"
TOOL_VERSION = "2.0.0"


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
    analyst: str = "SOC Analyst",
) -> None:
    lines: List[str] = []
    a = lines.append

    unique_ips = {i.indicator for i in iocs if i.type in ("ipv4", "ipv6")}
    unique_domains = {i.indicator for i in iocs if i.type == "domain"}
    active_detections = [d for d in detections if not d.suppressed]
    suppressed_detections = [d for d in detections if d.suppressed]
    severity_counts = Counter(f.severity for f in findings)
    tier_counts = summarize_tiers(ioc_profiles)

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
    a(f"- Packets analyzed: {capture.total_packets}")
    a(f"- Unique source IPs: {len({p.src_ip for p in capture.packets if p.src_ip})}")
    a(f"- Unique destination IPs: {len({p.dst_ip for p in capture.packets if p.dst_ip})}")
    a(f"- Unique public IP indicators: {len(unique_ips)}")
    a(f"- Unique domains: {len(unique_domains)}")
    a(f"- IOCs extracted: {len(iocs)}")
    a(f"- Detection signals raised: {len(detections)} ({len(active_detections)} active, "
      f"{len(suppressed_detections)} suppressed by allowlist)")
    a(f"- Correlated findings: {len(findings)}")
    a("")
    if findings:
        a("**Findings by severity**")
        a("")
        a(_md_table(["Severity", "Count"],
                    [[sev, str(severity_counts.get(sev, 0))]
                     for sev in ("Critical", "High", "Medium", "Low", "Informational")
                     if severity_counts.get(sev, 0)]))
    a("")

    # ================= 2. Key Findings =================
    a("## 2. Key Findings")
    a("")
    if findings:
        a("Only correlated, evidence-backed findings are shown here. Every finding "
          "combines behavioral detection signals and/or threat-intelligence evidence "
          "-- a domain, IP or hash observed with no corroborating evidence appears "
          "only in the IOC inventory (Section 6), not here.")
        a("")
        for f in findings:
            a(f"### {f.finding_id} — {f.title}")
            a("")
            a(f"- **Severity:** {f.severity} &nbsp;|&nbsp; **Confidence:** {f.confidence} "
              f"&nbsp;|&nbsp; **Risk score:** {f.risk_score}/100")
            a(f"- **Affected endpoint(s):** {', '.join(f.affected_assets)} (asset role: Unknown)")
            a(f"- **Destinations:** {', '.join(f.destination_ips) or 'N/A'}")
            if f.domains:
                a(f"- **Domain(s):** {', '.join(f.domains)}")
            if f.hashes:
                a(f"- **Hash(es):** {', '.join(h[:16] + '...' for h in f.hashes)}")
            a(f"- **First/last seen:** {f.first_seen.strftime('%H:%M:%S') if f.first_seen else 'N/A'} "
              f"– {f.last_seen.strftime('%H:%M:%S') if f.last_seen else 'N/A'} "
              f"({f.occurrence_count} occurrence(s))")
            a(f"- **Detection rule(s):** {', '.join(sorted({d.rule_id for d in f.detection_signals})) or 'None (TI-only)'}")
            a("")
            a(f"**Why this matters:** {f.explanation}")
            a("")
            if f.evidence:
                a("**Key evidence:**")
                for e in f.evidence:
                    a(f"- {e}")
                a("")
            a("**Threat intelligence:**")
            for t in f.threat_intelligence:
                a(f"- {t}")
            a("")
    else:
        a("No correlated findings were produced. This means no local detection "
          "signal and no meaningful (SUSPICIOUS/MALICIOUS) threat-intelligence "
          "assessment applied to any extracted indicator. See Section 6 for the "
          "full IOC inventory and Section 7 for low-confidence/suppressed signals "
          "that did not meet the bar for a finding.")
        a("")

    # ================= 3. Investigation Recommendations =================
    a("## 3. Investigation Recommendations")
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

    # ================= 4. Attack / Behavior Story =================
    a("## 4. Attack / Behavior Story")
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
            a("")
    else:
        a("No finding in this capture was supported by a multi-stage event chain "
          "(DNS \u2192 connection \u2192 HTTP \u2192 file). Single-stage findings are "
          "listed in Section 2 without a chain diagram.")
        a("")

    # ================= 5. Technical Evidence =================
    a("## 5. Technical Evidence")
    a("")
    a(f"Raw observations: {aggregation.raw_dns_observations} DNS record(s), "
      f"{aggregation.raw_http_observations} HTTP record(s), "
      f"{aggregation.raw_file_observations} file transfer(s) — aggregated below into "
      f"{len(aggregation.dns_events)} DNS behavioral event(s), "
      f"{len(aggregation.http_events)} HTTP behavioral event(s) and "
      f"{len(aggregation.file_events)} distinct file behavioral event(s).")
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

    a("### Investigation timeline")
    a("")
    if timeline:
        rows = [[ev.timestamp.strftime("%H:%M:%S"), ev.description, ev.finding_id or "-"]
                 for ev in timeline[:80]]
        a(_md_table(["Timestamp (UTC)", "Behavioral event", "Related finding"], rows))
    else:
        a("Not available in supplied PCAP.\n")

    # ================= 6. IOC Inventory =================
    a("## 6. IOC Inventory")
    a("")
    a("This inventory lists every indicator extracted from the capture. Listing an "
      "indicator here does **not** imply it is malicious -- see the significance "
      "tier and Section 2 for which indicators actually became findings.")
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

    # ================= 7. Appendix =================
    a("## 7. Appendix")
    a("")

    a("### 7.1 Threat-intelligence summary")
    a("")
    a(f"- Indicators analyzed: {len(iocs)}")
    a(f"- Meaningful TI matches (Suspicious/Malicious): {len(ti_meaningful)}")
    a(f"- Weak reputation (not a finding on its own): {len(ti_weak)}")
    a(f"- Clean / no meaningful record: {len(ti_clean_or_unknown)}")
    if unavailable_feeds:
        a(f"- Feeds unavailable during this run: {', '.join(unavailable_feeds)} "
          f"(results from these feeds are incomplete, not a clean verdict)")
    a("")

    a("### 7.2 Raw threat-intelligence results (including no-record lookups)")
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

    a("### 7.3 Suppressed and low-confidence detection signals")
    a("")
    if suppressed_detections:
        rows = [[d.rule_id, d.indicator, d.suppression_reason or "-",
                  d.suppression_entry or "-", str(d.occurrence_count)]
                 for d in suppressed_detections[:60]]
        a(_md_table(["Rule", "Indicator", "Suppression reason", "Matched allowlist entry", "Occurrences"], rows))
    else:
        a("No detection signals were suppressed by the allowlist in this run.\n")

    a("### 7.4 Detection tuning report")
    a("")
    tuning_rows = _rule_tuning_report(detections, findings)
    if tuning_rows:
        a(_md_table(["Rule", "Title", "Triggered", "Suppressed", "In findings", "Avg. confidence", "Avg. score"],
                     tuning_rows))
    else:
        a("No detection rule fired in this run.\n")

    a("### 7.5 Observability / pipeline statistics")
    a("")
    a(_md_table(["Metric", "Count"], [
        ["Raw packets", str(capture.total_packets)],
        ["Raw DNS observations", str(aggregation.raw_dns_observations)],
        ["Raw HTTP observations", str(aggregation.raw_http_observations)],
        ["Raw file observations", str(aggregation.raw_file_observations)],
        ["Behavioral events (DNS)", str(len(aggregation.dns_events))],
        ["Behavioral events (HTTP)", str(len(aggregation.http_events))],
        ["Behavioral events (File)", str(len(aggregation.file_events))],
        ["Detection signals raised", str(len(detections))],
        ["Detection signals suppressed", str(len(suppressed_detections))],
        ["Correlation candidates evaluated", str(correlation_stats.get("candidates_evaluated", 0))],
        ["Findings before deduplication", str(correlation_stats.get("findings_before_dedup", 0))],
        ["Findings after deduplication", str(correlation_stats.get("findings_after_dedup", len(findings)))],
    ]))

    a("### 7.6 Limitations")
    a("")
    a("- Encrypted traffic cannot be inspected beyond metadata.")
    a("- DNS response data (resolved IPs, response codes) is merged into every "
      "client bucket for the same (domain, query type) pair, since this layer "
      "does not retain DNS transaction IDs; captures with multiple distinct "
      "clients querying the same domain in the same run may see resolved-IP "
      "data shared across those clients' behavioral events.")
    a("- The apex-domain grouping used for DNS-007 is a last-two-labels "
      "approximation and is not authoritative for multi-part TLDs (e.g. .co.uk).")
    a("- Asset role/criticality context is not available in this environment; "
      "every finding explicitly reports 'Asset role: Unknown' rather than "
      "guessing at criticality.")
    a("- Threat-intelligence feeds are rate-limited and may be unavailable at "
      "scan time; the report states this explicitly rather than treating an "
      "unavailable feed as a clean result.")
    a("- The risk score is a project-defined prioritization aid, not an "
      "industry-standard rating, and a single indicator match is never proof "
      "of compromise on its own.")
    a("")

    a("### 7.7 References")
    a("")
    a("- AbuseIPDB — <https://www.abuseipdb.com>")
    a("- VirusTotal — <https://www.virustotal.com>")
    a("- URLhaus (abuse.ch) — <https://urlhaus.abuse.ch>")
    a("")

    # ================= Conclusion =================
    a("## Conclusion")
    a("")
    high_findings = [f for f in findings if f.severity in ("Critical", "High")]
    if high_findings:
        conclusion = (f"This analysis identified {len(high_findings)} finding(s) rated High or "
                       "Critical severity, each backed by correlated behavioral and/or threat-"
                       "intelligence evidence (Section 2). Analysts should prioritize review of "
                       "these findings and follow the recommendations in Section 3.")
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
