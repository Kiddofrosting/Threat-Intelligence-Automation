#!/usr/bin/env python3
"""Threat Intelligence Automation Tool — CLI entry point.

    python main.py --pcap pcaps/sample.pcap --output reports/security_report.md

Pipeline:
    PCAP -> parsing -> IOC extraction -> behavioral aggregation
    -> detection (on aggregated events) -> TI feed queries
    -> feed-specific TI interpretation -> IOC significance scoring
    -> endpoint/time-window correlation -> risk scoring -> report

This mirrors the required data-model separation:
    raw observations -> behavioral events -> detection signals
    -> correlated findings -> report
"""

import argparse
import os
import sys

from dotenv import load_dotenv

from analyzer.aggregator import aggregate
from analyzer.allowlist import load_allowlist
from analyzer.assets import load_assets
from analyzer.config import load_config
from analyzer.correlator import build_incidents, build_timeline, correlate, interpret_ti_results
from analyzer.detector import run_detections
from analyzer.domain_history import load_history, save_history
from analyzer.ioc_extractor import extract_iocs
from analyzer.ioc_scoring import classify_iocs
from analyzer.json_export import build_json_report, write_json_report
from analyzer.pcap_parser import parse_pcap
from analyzer.reporter import generate_markdown_report
from feeds.abuseipdb import AbuseIPDBClient
from feeds.urlhaus import URLhausClient
from feeds.virustotal import VirusTotalClient
from utils.logging_config import setup_logging

# Which IOC types each feed is worth querying for — we don't blindly
# submit every indicator to every feed.
FEED_APPLICABLE_TYPES = {
    "AbuseIPDB": {"ipv4", "ipv6"},
    "VirusTotal": {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"},
    "URLhaus": {"url", "domain", "ipv4", "ipv6"},
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Automation Tool — analyze a PCAP and "
                    "produce a professional threat-intelligence security report.")
    parser.add_argument("--pcap", required=True, help="Path to the input PCAP file.")
    parser.add_argument("--output", default="reports/security_report.md",
                         help="Path to write the generated Markdown report to.")
    parser.add_argument("--no-ti", action="store_true",
                         help="Skip threat-intelligence feed lookups (offline mode).")
    parser.add_argument("--config", default="config/detection_config.yaml",
                         help="Path to the detection/risk-scoring configuration file.")
    parser.add_argument("--allowlist", default="config/allowlist.yaml",
                         help="Path to the allowlist/suppression configuration file.")
    parser.add_argument("--assets", default="config/assets.yaml",
                         help="Path to the asset inventory configuration file.")
    parser.add_argument("--domain-history", default="cache/domain_history.json",
                         help="Path to the local domain-history baseline used by DNS-005.")
    parser.add_argument("--no-domain-history", action="store_true",
                         help="Disable the newly-observed-domain rule and its history file entirely.")
    parser.add_argument("--json-output", default=None,
                         help="Also write a machine-readable JSON report (findings, detections, "
                              "IOC profiles, TI assessments, timeline) to this path, for SIEM/"
                              "automation ingestion.")
    parser.add_argument("--fail-on-high", action="store_true",
                         help="Exit with status 2 if any finding reaches High or Critical severity "
                              "(useful for CI/automation pipelines that should react to that).")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()


def _observation_counts(iocs, capture, aggregation):
    """How many raw observations named each IOC -- used by IOC
    significance scoring. Best-effort: counts DNS/HTTP occurrences by
    domain/host and file transfers by hash; IP-only observations fall
    back to raw packet counts."""
    counts = {}
    for ev in aggregation.dns_events:
        counts[ev.domain] = counts.get(ev.domain, 0) + ev.occurrence_count
        for ip in ev.resolved_ips:
            counts[ip] = counts.get(ip, 0) + 1
    for ev in aggregation.http_events:
        counts[ev.host] = counts.get(ev.host, 0) + ev.occurrence_count
        counts[ev.dest_ip] = counts.get(ev.dest_ip, 0) + ev.occurrence_count
    for ev in aggregation.file_events:
        counts[ev.sha256] = counts.get(ev.sha256, 0) + ev.transfer_count
    for ioc in iocs:
        counts.setdefault(ioc.indicator, 0)
    return counts


def main():
    args = parse_args()
    load_dotenv()
    logger = setup_logging(verbose=args.verbose)

    if not os.path.exists(args.pcap):
        logger.error(f"PCAP file not found: {args.pcap}")
        sys.exit(1)

    config = load_config(args.config)
    allowlist = load_allowlist(args.allowlist)
    assets = load_assets(args.assets)

    logger.info("[+] Loading PCAP")
    capture = parse_pcap(args.pcap, logger=logger)

    logger.info("[+] Extracting IOCs")
    iocs = extract_iocs(capture)
    logger.info(f"    {len(iocs)} unique IOC(s) extracted")

    logger.info("[+] Aggregating behavioral events")
    aggregation = aggregate(capture)
    logger.info(f"    {len(aggregation.dns_events)} DNS event(s), "
                f"{len(aggregation.http_events)} HTTP event(s), "
                f"{len(aggregation.file_events)} file event(s) "
                f"(from {aggregation.raw_dns_observations} + "
                f"{aggregation.raw_http_observations} + "
                f"{aggregation.raw_file_observations} raw observations)")

    logger.info("[+] Running detections")
    known_domains = None
    if not args.no_domain_history:
        known_domains = load_history(args.domain_history)
    detections = run_detections(aggregation, config=config, allowlist=allowlist, known_domains=known_domains)
    active = [d for d in detections if not d.suppressed]
    logger.info(f"    {len(detections)} detection signal(s) generated "
                f"({len(active)} active, {len(detections) - len(active)} suppressed)")

    ti_results = {}
    unavailable_feeds = []

    if args.no_ti:
        logger.info("[+] Skipping threat intelligence (--no-ti set)")
    else:
        clients = {
            "AbuseIPDB": AbuseIPDBClient(os.getenv("ABUSEIPDB_API_KEY")),
            "VirusTotal": VirusTotalClient(os.getenv("VIRUSTOTAL_API_KEY")),
            "URLhaus": URLhausClient(os.getenv("URLHAUS_AUTH_KEY")),
        }
        for feed_name, client in clients.items():
            logger.info(f"[+] Querying {feed_name}")
            feed_had_success = False
            feed_attempted = False
            for ioc in iocs:
                if ioc.type not in FEED_APPLICABLE_TYPES[feed_name]:
                    continue
                feed_attempted = True
                result = client.query(ioc.indicator, ioc.type)
                ti_results.setdefault(ioc.indicator, []).append(result)
                if result.available:
                    feed_had_success = True
            if feed_attempted and not feed_had_success:
                unavailable_feeds.append(feed_name)
                logger.warning(f"    {feed_name}: API unavailable")
            else:
                matches = sum(1 for results in ti_results.values()
                              for r in results if r.feed == feed_name and r.matched)
                logger.info(f"    {feed_name}: {matches} raw match(es)")

    logger.info("[+] Interpreting threat intelligence")
    ti_assessments = interpret_ti_results(ti_results, config)
    meaningful = sum(1 for assessments in ti_assessments.values()
                      for a in assessments if a.is_meaningful)
    logger.info(f"    {meaningful} indicator(s) with a meaningful (Suspicious/Malicious) TI assessment")

    logger.info("[+] Scoring IOC significance")
    observation_counts = _observation_counts(iocs, capture, aggregation)
    ioc_profiles = classify_iocs(iocs, detections, ti_assessments, observation_counts)

    logger.info("[+] Correlating findings")
    findings, correlation_stats = correlate(capture, iocs, aggregation, detections, ti_results,
                                             config=config, assets=assets)
    timeline = build_timeline(aggregation, findings)
    incidents = build_incidents(findings)
    logger.info(f"    {len(findings)} correlated finding(s) grouped into {len(incidents)} incident(s) "
                f"({correlation_stats['candidates_evaluated']} candidate(s) evaluated, "
                f"{correlation_stats['findings_before_dedup']} before dedup)")

    logger.info("[+] Generating Markdown report")
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    generate_markdown_report(
        output_path=args.output,
        pcap_path=args.pcap,
        capture=capture,
        iocs=iocs,
        aggregation=aggregation,
        detections=detections,
        ti_results=ti_results,
        ti_assessments=ti_assessments,
        ioc_profiles=ioc_profiles,
        findings=findings,
        incidents=incidents,
        timeline=timeline,
        unavailable_feeds=unavailable_feeds,
        correlation_stats=correlation_stats,
    )

    if args.json_output:
        logger.info("[+] Writing JSON report")
        json_data = build_json_report(
            pcap_path=args.pcap, capture=capture, iocs=iocs, detections=detections,
            ti_assessments=ti_assessments, ioc_profiles=ioc_profiles, findings=findings,
            timeline=timeline, unavailable_feeds=unavailable_feeds, correlation_stats=correlation_stats,
            incidents=incidents,
        )
        os.makedirs(os.path.dirname(args.json_output) or ".", exist_ok=True)
        write_json_report(args.json_output, json_data)

    logger.info(f"[+] Analysis complete — report written to {args.output}")

    if not args.no_domain_history:
        updated_history = (known_domains or set()) | {ev.domain for ev in aggregation.dns_events}
        save_history(updated_history, args.domain_history)

    if args.fail_on_high and any(f.severity in ("High", "Critical") for f in findings):
        logger.warning("[!] Exiting with status 2: a High or Critical severity finding was produced.")
        sys.exit(2)


if __name__ == "__main__":
    main()
