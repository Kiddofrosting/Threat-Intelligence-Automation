"""Builds the Markdown security report (reports/security_report.md).

Structure follows the assignment brief exactly:
    Introduction
    Scope and Objective
    Findings and Recommendations   (network analysis, threat detection,
                                     TI correlation, and recommendations
                                     live here, since these are the graded
                                     criteria)
    References
    Conclusion

Nothing here invents content: a field or feed with no data says so
explicitly rather than being left out silently or guessed at.
"""

from collections import Counter
from datetime import datetime
from typing import Dict, List

from analyzer.correlator import Finding, TimelineEvent
from analyzer.detector import Detection
from analyzer.ioc_extractor import IOC
from analyzer.pcap_parser import ParsedCapture
from feeds.base import FeedResult
from utils.hashing import hashes_for

TOOL_NAME = "Threat Intelligence Automation Tool"
TOOL_VERSION = "1.0.0"


def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return "_No data available for this table._\n"
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        # Escape pipe characters so long paths/UAs don't break the table.
        safe_row = [str(c).replace("|", "\\|").replace("\n", " ") for c in row]
        lines.append("| " + " | ".join(safe_row) + " |")
    return "\n".join(lines) + "\n"


def generate_markdown_report(
    output_path: str,
    pcap_path: str,
    capture: ParsedCapture,
    iocs: List[IOC],
    detections: List[Detection],
    ti_results: Dict[str, List[FeedResult]],
    findings: List[Finding],
    timeline: List[TimelineEvent],
    unavailable_feeds: List[str],
    analyst: str = "SOC Analyst",
) -> None:
    lines: List[str] = []
    a = lines.append

    unique_ips = {i.indicator for i in iocs if i.type in ("ipv4", "ipv6")}
    unique_domains = {i.indicator for i in iocs if i.type == "domain"}
    ti_match_count = sum(1 for results in ti_results.values() for r in results if r.matched)
    high_findings = [f for f in findings if f.severity in ("Critical", "High")]

    # ---------------- Header ----------------
    a("# Threat Intelligence & Network Security Analysis Report")
    a("")
    a(f"- **PCAP file:** `{pcap_path}`")
    a(f"- **Analysis date:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    a(f"- **Tool:** {TOOL_NAME} v{TOOL_VERSION}")
    a(f"- **Analyst:** {analyst}")
    a(f"- **Classification:** Security Analysis")
    a("")
    a("---")
    a("")

    # ---------------- Introduction ----------------
    a("## Introduction")
    a("")
    a(f"This report documents the automated analysis of `{pcap_path}` "
      f"({capture.total_packets} packets), performed by the "
      f"{TOOL_NAME}. The tool extracts network, DNS, HTTP and file-transfer "
      f"metadata from the capture, identifies indicators of compromise (IOCs), "
      f"correlates those indicators against three threat-intelligence feeds "
      f"(AbuseIPDB, VirusTotal, URLhaus), and reports the resulting findings "
      f"here for SOC analyst review.")
    a("")

    # ---------------- Scope and Objective ----------------
    a("## Scope and Objective")
    a("")
    a("**Objective:** determine whether the supplied packet capture contains "
      "evidence of suspicious or malicious network activity, using packet-level "
      "detection combined with external threat-intelligence correlation.")
    a("")
    a("**Scope:** analysis is limited to what is observable in the supplied "
      "PCAP file. Encrypted payloads are not decrypted. Threat-intelligence "
      "results reflect each feed's data at the time of the scan and are "
      "subject to that feed's own coverage and rate limits. This tool assists "
      "triage; it does not itself constitute a compromise determination.")
    a("")

    # ---------------- Findings and Recommendations ----------------
    a("## Findings and Recommendations")
    a("")

    # -- Network Analysis --
    a("### Network Analysis")
    a("")
    proto_counts = capture.protocol_counts()
    src_counter = Counter(p.src_ip for p in capture.packets if p.src_ip)
    dst_counter = Counter(p.dst_ip for p in capture.packets if p.dst_ip)
    port_counter = Counter(p.dst_port for p in capture.packets if p.dst_port)

    a(f"{capture.total_packets} packets analyzed, covering {len(unique_ips)} "
      f"unique public IP indicator(s) and {len(unique_domains)} unique domain(s).")
    a("")
    a("**Protocol distribution**")
    a("")
    a(_md_table(["Protocol", "Packet Count"],
                [[p, str(c)] for p, c in proto_counts.items()]))
    a("**Top source IPs**")
    a("")
    a(_md_table(["Source IP", "Packet Count"],
                [[ip, str(c)] for ip, c in src_counter.most_common(10)]))
    a("**Top destination IPs**")
    a("")
    a(_md_table(["Destination IP", "Packet Count"],
                [[ip, str(c)] for ip, c in dst_counter.most_common(10)]))
    a("**Top destination ports**")
    a("")
    a(_md_table(["Destination Port", "Packet Count"],
                [[str(p), str(c)] for p, c in port_counter.most_common(10)]))

    a("**DNS activity**")
    a("")
    if capture.dns_records:
        rows = [[rec.query or "Not available in supplied PCAP.", rec.query_type or "-",
                  ", ".join(rec.resolved_ips) or "-", rec.src_ip]
                 for rec in capture.dns_records[:40]]
        a(_md_table(["Query", "Type", "Resolved IP(s)", "Source IP"], rows))
    else:
        a("No DNS records were observed in the supplied PCAP.\n")

    a("**HTTP activity**")
    a("")
    if capture.http_records:
        rows = [[rec.method or "-", rec.host or "-", rec.path or "-",
                  rec.user_agent or rec.status_code or "Not available in supplied PCAP."]
                 for rec in capture.http_records[:40]]
        a(_md_table(["Method", "Host", "Path", "User-Agent / Status"], rows))
    else:
        a("No HTTP records were observed or parsable in the supplied PCAP "
          "(traffic may be encrypted or use an unsupported protocol version).\n")

    a("**Files and file signatures**")
    a("")
    if capture.files:
        rows = []
        for f in capture.files[:20]:
            digest = hashes_for(f.data)["sha256"]
            rows.append([f.src_ip, f.dst_ip, str(f.size), digest])
        a(_md_table(["Source", "Destination", "Size (bytes)", "SHA256"], rows))
    else:
        a("No complete files could be reassembled from the supplied PCAP. This "
          "is expected for encrypted transfers or captures without full TCP "
          "streams.\n")

    # -- Threat Detection --
    a("### Threat Detection")
    a("")
    a("Local, rule-based detections generated directly from the PCAP "
      "(log-based and PCAP-based threats). Each is explicitly classified; "
      "none is labeled malicious on local heuristics alone.")
    a("")
    if detections:
        rows = [[d.detection_id, d.timestamp.strftime("%H:%M:%S"), d.category,
                  d.classification, d.ioc or "-", d.evidence]
                 for d in detections]
        a(_md_table(["ID", "Time (UTC)", "Category", "Classification", "IOC", "Evidence"], rows))
    else:
        a("No local detections fired for this capture.\n")

    # -- Threat Intelligence Correlation --
    a("### Threat Intelligence Correlation")
    a("")
    ti_rows = []
    for indicator, results in ti_results.items():
        ioc_type = next((i.type for i in iocs if i.indicator == indicator), "-")
        for r in results:
            summary = r.summary if r.available else "Threat intelligence lookup unavailable."
            ti_rows.append([indicator, ioc_type, r.feed, summary, r.confidence])
    if ti_rows:
        a(_md_table(["IOC", "Type", "Feed", "Result", "Confidence"], ti_rows))
    else:
        a("No indicators were submitted for threat-intelligence lookup "
          "(e.g. run with `--no-ti`, or no qualifying IOCs were extracted).\n")
    if unavailable_feeds:
        a(f"> **Note:** the following feed(s) were unavailable during this run: "
          f"{', '.join(unavailable_feeds)}. Results from these feeds above are "
          f"incomplete, not a clean verdict.")
        a("")

    a(f"Threat-intelligence lookups produced **{ti_match_count}** matching "
      f"result(s) across the configured feeds.")
    a("")

    # -- Correlated findings --
    a("### Correlated Findings")
    a("")
    if findings:
        for f in findings:
            a(f"#### {f.finding_id} — {f.category}")
            a("")
            a(f"- **Severity:** {f.severity} (risk score {f.risk_score}/100)")
            a(f"- **Confidence:** {f.confidence}")
            a(f"- **IOC:** `{f.ioc}` ({f.ioc_type})")
            a(f"- **PCAP evidence:** {'; '.join(f.pcap_evidence)}")
            a(f"- **Threat intelligence:** {'; '.join(f.ti_evidence)}")
            a(f"- **Correlation:** {f.correlation_summary}")
            a(f"- **Recommended action:** {f.recommended_action}")
            a("")
    else:
        a("No correlated findings were produced: no local detection fired and "
          "no threat-intelligence feed returned a match for any extracted "
          "indicator.\n")

    # -- Investigation timeline --
    a("### Investigation Timeline")
    a("")
    if timeline:
        rows = [[ev.timestamp.strftime("%H:%M:%S"), ev.description] for ev in timeline[:60]]
        a(_md_table(["Timestamp (UTC)", "Event"], rows))
    else:
        a("Not available in supplied PCAP.\n")

    # -- Recommendations --
    a("### Recommendations")
    a("")
    recs = [
        "Investigate any endpoint associated with a High or Critical severity finding.",
        "Search historical SIEM/EDR logs for the indicators listed in this report.",
        "Where infrastructure is confirmed malicious by policy, block at the network boundary.",
        "Review DNS logs for repeated queries to the flagged domains.",
        "Analyze any recovered file payloads in an isolated sandbox before further action.",
        "Continue monitoring related infrastructure identified in the IOC inventory.",
    ]
    for r in recs:
        a(f"- {r}")
    a("")

    # ---------------- References ----------------
    a("## References")
    a("")
    a("Threat-intelligence feeds used for correlation:")
    a("")
    a("- AbuseIPDB — <https://www.abuseipdb.com>")
    a("- VirusTotal — <https://www.virustotal.com>")
    a("- URLhaus (abuse.ch) — <https://urlhaus.abuse.ch>")
    a("")
    a("Sample PCAP source: <https://www.malware-traffic-analysis.net/>")
    a("")

    # ---------------- Conclusion ----------------
    a("## Conclusion")
    a("")
    if high_findings:
        conclusion = (f"This analysis identified {len(high_findings)} finding(s) rated High "
                       "or Critical severity, supported by the packet-level and threat-"
                       "intelligence evidence above. Analysts should prioritize review of "
                       "these findings and follow the recommendations listed.")
    elif findings:
        conclusion = ("This analysis identified findings of Low or Medium severity. While "
                       "none reached High or Critical severity, the indicators above warrant "
                       "routine follow-up consistent with local SOC procedure.")
    else:
        conclusion = ("Based strictly on the evidence recovered from the supplied capture and "
                       "the threat-intelligence lookups performed, no indicators met the "
                       "criteria for a security finding. This does not guarantee the absence "
                       "of malicious activity, particularly within encrypted traffic not "
                       "inspected by this tool.")
    a(conclusion)
    a("")
    a("**Limitations:** encrypted traffic cannot be inspected beyond metadata; "
      "fields absent from the PCAP are reported as unavailable rather than guessed; "
      "threat-intelligence feeds are rate-limited and may be unavailable at scan "
      "time; a single indicator match is not proof of compromise; the risk score "
      "is a project-defined prioritization aid, not an industry-standard rating.")
    a("")

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
