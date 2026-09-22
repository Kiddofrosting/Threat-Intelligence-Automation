#!/usr/bin/env python3
"""Threat Intelligence Automation Tool — CLI entry point.

    python main.py --pcap pcaps/sample.pcap --output reports/security_report.md

Pipeline: PCAP -> parsing -> IOC extraction -> detection -> TI correlation
-> evidence correlation -> risk scoring -> Markdown report.
"""

import argparse
import os
import sys

from dotenv import load_dotenv

from analyzer.correlator import build_timeline, correlate
from analyzer.detector import run_detections
from analyzer.ioc_extractor import extract_iocs
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
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    return parser.parse_args()


def main():
    args = parse_args()
    load_dotenv()
    logger = setup_logging(verbose=args.verbose)

    if not os.path.exists(args.pcap):
        logger.error(f"PCAP file not found: {args.pcap}")
        sys.exit(1)

    logger.info("[+] Loading PCAP")
    capture = parse_pcap(args.pcap, logger=logger)

    logger.info("[+] Extracting network metadata")
    logger.info(f"    {capture.total_packets} packets parsed")

    logger.info("[+] Extracting IOCs")
    iocs = extract_iocs(capture)
    logger.info(f"    {len(iocs)} unique IOC(s) extracted")

    logger.info("[+] Running detections")
    detections = run_detections(capture)
    logger.info(f"    {len(detections)} local detection(s) generated")

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
                logger.info(f"    {feed_name}: {matches} match(es)")

    logger.info("[+] Correlating findings")
    findings = correlate(capture, iocs, detections, ti_results)
    timeline = build_timeline(capture)
    logger.info(f"    {len(findings)} correlated finding(s)")

    logger.info("[+] Generating Markdown report")
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    generate_markdown_report(
        output_path=args.output,
        pcap_path=args.pcap,
        capture=capture,
        iocs=iocs,
        detections=detections,
        ti_results=ti_results,
        findings=findings,
        timeline=timeline,
        unavailable_feeds=unavailable_feeds,
    )

    logger.info(f"[+] Analysis complete — report written to {args.output}")


if __name__ == "__main__":
    main()
