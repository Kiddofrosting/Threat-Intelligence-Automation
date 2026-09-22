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
from analyzer.config import load_config
from analyzer.correlator import build_timeline, correlate, interpret_ti_results
from analyzer.detector import run_detections
from analyzer.ioc_extractor import extract_iocs
from analyzer.ioc_scoring import classify_iocs
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
    detections = run_detections(aggregation, config=config, allowlist=allowlist)
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
    findings, correlation_stats = correlate(capture, iocs, aggregation, detections, ti_results, config=config)
    timeline = build_timeline(aggregation, findings)
    logger.info(f"    {len(findings)} correlated finding(s) "
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
        timeline=timeline,
        unavailable_feeds=unavailable_feeds,
        correlation_stats=correlation_stats,
    )

    logger.info(f"[+] Analysis complete — report written to {args.output}")


if __name__ == "__main__":
    main()
