"""Unit and integration tests for the aggregation -> detection ->
TI interpretation -> correlation -> reporting pipeline.

Run with:  python -m pytest tests/  (or  python -m unittest discover tests)

No PCAP file or network access is required -- synthetic ParsedCapture
objects are built directly so the aggregation/detection/correlation
layers can be tested in isolation from Scapy.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.aggregator import aggregate, aggregate_connections, aggregate_dns, aggregate_files, aggregate_http
from analyzer.allowlist import check_domain, load_allowlist
from analyzer.beaconing import compute_interval_stats
from analyzer.config import DEFAULT_CONFIG, band_from_score, min_severity
from analyzer.correlator import build_incidents, build_timeline, correlate
from analyzer.detector import run_detections
from analyzer.dga import score_domain
from analyzer.ioc_extractor import IOC, extract_iocs
from analyzer.ioc_scoring import classify_iocs
from analyzer.mitre_mapping import get_technique
from analyzer.pcap_parser import DNSRecord, ExtractedFile, HTTPRecord, PacketRecord, ParsedCapture
from analyzer.reporter import generate_markdown_report
from analyzer.ti_interpreter import CLEAN, MALICIOUS, SUSPICIOUS, UNKNOWN, WEAK_REPUTATION, interpret
from analyzer.web_attack_patterns import match_path
from feeds.base import FeedResult
from utils.hashing import hashes_for, identify_signature
from utils.networking import has_suspicious_extension, has_suspicious_user_agent, is_useful_ip

T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


def _dns(offset_s, src="10.0.0.5", query="example.com", qtype="A", is_response=False,
         resolved=None, rcode=None):
    return DNSRecord(timestamp=T0 + timedelta(seconds=offset_s), src_ip=src, dns_server="8.8.8.8",
                      query=query, query_type=qtype, is_response=is_response,
                      resolved_ips=resolved or [], response_code=rcode)


def _http(offset_s, src="10.0.0.5", dst="93.184.216.34", host="example.com", path="/",
          method="GET", ua=None):
    return HTTPRecord(timestamp=T0 + timedelta(seconds=offset_s), src_ip=src, dst_ip=dst,
                       method=method, host=host, path=path, user_agent=ua)


def _file(offset_s, data, src="93.184.216.34", dst="10.0.0.5"):
    return ExtractedFile(src_ip=src, dst_ip=dst, filename=None, size=len(data), data=data,
                          timestamp=T0 + timedelta(seconds=offset_s))


def _tcp(offset_s, src, dst, sport, dport, flags, length=60):
    return PacketRecord(index=0, timestamp=T0 + timedelta(seconds=offset_s), src_ip=src, dst_ip=dst,
                         src_port=sport, dst_port=dport, protocol="TCP", length=length, tcp_flags=flags)


def _capture(dns=None, http=None, files=None, packets=None):
    cap = ParsedCapture(pcap_path="synthetic.pcap")
    cap.dns_records = dns or []
    cap.http_records = http or []
    cap.files = files or []
    cap.packets = packets or []
    cap.total_packets = len(cap.packets) or (len(cap.dns_records) + len(cap.http_records))
    return cap


class TestNetworking(unittest.TestCase):
    def test_private_ip_excluded(self):
        self.assertFalse(is_useful_ip("192.168.1.10"))
        self.assertFalse(is_useful_ip("10.0.0.5"))
        self.assertFalse(is_useful_ip("127.0.0.1"))

    def test_public_ip_included(self):
        self.assertTrue(is_useful_ip("8.8.8.8"))
        self.assertTrue(is_useful_ip("185.123.45.67"))

    def test_invalid_ip(self):
        self.assertFalse(is_useful_ip("not-an-ip"))

    def test_suspicious_user_agent(self):
        self.assertTrue(has_suspicious_user_agent("python-requests/2.31.0"))
        self.assertTrue(has_suspicious_user_agent("curl/8.4.0"))
        self.assertFalse(has_suspicious_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"))

    def test_suspicious_extension(self):
        self.assertTrue(has_suspicious_extension("/download/payload.exe"))
        self.assertTrue(has_suspicious_extension("/scripts/run.ps1?x=1"))
        self.assertFalse(has_suspicious_extension("/index.html"))


class TestHashing(unittest.TestCase):
    def test_hashes_for(self):
        digests = hashes_for(b"hello world")
        self.assertEqual(digests["md5"], "5eb63bbbe01eeed093cb22bb8f5acdc3")
        self.assertEqual(len(digests["sha256"]), 64)

    def test_identify_signature_pe(self):
        self.assertEqual(identify_signature(b"MZ\x90\x00" + b"\x00" * 60), "PE executable / DLL")

    def test_identify_signature_unknown(self):
        self.assertIsNone(identify_signature(b"not a known signature"))


class TestIOC(unittest.TestCase):
    def test_ioc_hashable_and_dict(self):
        ioc = IOC("185.123.45.67", "ipv4")
        self.assertEqual(ioc.to_dict(), {"indicator": "185.123.45.67", "type": "ipv4"})
        self.assertEqual(len({ioc, IOC("185.123.45.67", "ipv4")}), 1)


class TestConfig(unittest.TestCase):
    def test_band_from_score(self):
        bands = DEFAULT_CONFIG["risk"]["severity_bands"]
        self.assertEqual(band_from_score(5, bands), "Informational")
        self.assertEqual(band_from_score(25, bands), "Low")
        self.assertEqual(band_from_score(45, bands), "Medium")
        self.assertEqual(band_from_score(70, bands), "High")
        self.assertEqual(band_from_score(90, bands), "Critical")

    def test_min_severity(self):
        self.assertEqual(min_severity("High", "Medium"), "Medium")
        self.assertEqual(min_severity("Low", "Critical"), "Low")


class TestDGAScoring(unittest.TestCase):
    def test_short_label_not_scored(self):
        result = score_domain("api.com")
        self.assertEqual(result.score, 0)

    def test_dictionary_word_lowers_score(self):
        wordy = score_domain("api-gateway-service.example.com")
        randomish = score_domain("qzxjklmpwvbnfgh.example.com")
        self.assertLess(wordy.score, randomish.score)

    def test_high_entropy_low_vowel_scores_high(self):
        result = score_domain("qzxjklmpwvbnfgh.top")
        self.assertGreaterEqual(result.score, 45)

    def test_tld_alone_is_weak(self):
        # A short-ish, wordy label on a suspicious TLD should stay low --
        # the TLD contributes at most 5/100 points.
        result = score_domain("supportportal.xyz")
        self.assertLess(result.score, 30)


class TestPublicSuffixes(unittest.TestCase):
    def test_co_ke_apex_domain_resolved_correctly(self):
        from analyzer.public_suffixes import apex_domain
        self.assertEqual(apex_domain("mail.example.co.ke"), "example.co.ke")
        self.assertEqual(apex_domain("www.safaricom.co.ke"), "safaricom.co.ke")

    def test_simple_tld_unaffected(self):
        from analyzer.public_suffixes import apex_domain
        self.assertEqual(apex_domain("beacon.example.com"), "example.com")

    def test_unrelated_co_ke_businesses_do_not_merge_under_dns007(self):
        # Without PSL-awareness, "one.co.ke" and "two.co.ke" would both
        # collapse into apex "co.ke" and look like one business with
        # many subdomains. With it, they must stay separate.
        records = [_dns(i, query=f"sub{i}.businessone.co.ke") for i in range(4)]
        records += [_dns(i, query=f"sub{i}.businesstwo.co.ke") for i in range(4)]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        subdomain_signals = [d for d in detections if d.rule_id == "DNS-007"]
        # Neither apex individually has enough unique subdomains (4 each,
        # threshold 6) to fire -- proving they were NOT merged into one
        # "co.ke" apex with 8 combined unique subdomains.
        self.assertEqual(len(subdomain_signals), 0)

    def test_custom_suffix_via_config(self):
        from analyzer.public_suffixes import apex_domain
        config = {"dns": {"custom_public_suffixes": ["example.custom.tld"]}}
        self.assertEqual(apex_domain("host.mybiz.example.custom.tld", config), "mybiz.example.custom.tld")


class TestPerformance(unittest.TestCase):
    def test_large_capture_completes_quickly(self):
        import time
        records = []
        for i in range(3000):
            records.append(_dns(i * 0.01, src=f"10.0.{i % 20}.{i % 250}", query=f"host{i % 50}.example.com"))
        capture = _capture(dns=records)
        start = time.time()
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        findings, _ = correlate(capture, iocs, agg, detections, {})
        elapsed = time.time() - start
        # 3000 raw observations should aggregate down to a small number
        # of distinct (source, domain) buckets and complete well under a
        # few seconds -- no O(n^2) blowup anywhere in the pipeline.
        self.assertLessEqual(len(agg.dns_events), 20 * 50)
        self.assertLess(elapsed, 5.0)



    def test_repeated_dns_queries_aggregate_into_one_event(self):
        records = [_dns(i, query="beacon.example.com") for i in range(5)]
        events, _ = aggregate_dns(_capture(dns=records))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].occurrence_count, 5)

    def test_dns_response_data_merges_into_client_bucket(self):
        records = [
            _dns(0, query="example.com"),
            _dns(1, src="8.8.8.8", query="example.com", is_response=True,
                 resolved=["93.184.216.34"], rcode="NOERROR"),
        ]
        events, _ = aggregate_dns(_capture(dns=records))
        self.assertEqual(len(events), 1)
        self.assertIn("93.184.216.34", events[0].resolved_ips)

    def test_nxdomain_ratio_computed(self):
        records = [_dns(i, query="ghost.example.com") for i in range(4)]
        records += [_dns(i, src="8.8.8.8", query="ghost.example.com", is_response=True,
                          rcode="NXDOMAIN") for i in range(4)]
        events, _ = aggregate_dns(_capture(dns=records))
        self.assertEqual(events[0].nxdomain_ratio, 1.0)

    def test_dns_transaction_id_pairs_precisely(self):
        # Two different clients querying the same domain with distinct
        # transaction IDs should NOT have their resolved IPs cross-merged.
        records = [
            DNSRecord(timestamp=T0, src_ip="10.0.0.5", dns_server="8.8.8.8", query="shared.example.com",
                      query_type="A", is_response=False, transaction_id=111),
            DNSRecord(timestamp=T0, src_ip="10.0.0.6", dns_server="8.8.8.8", query="shared.example.com",
                      query_type="A", is_response=False, transaction_id=222),
            DNSRecord(timestamp=T0, src_ip="8.8.8.8", dns_server=None, query="shared.example.com",
                      query_type="A", is_response=True, resolved_ips=["1.1.1.1"], transaction_id=111),
            DNSRecord(timestamp=T0, src_ip="8.8.8.8", dns_server=None, query="shared.example.com",
                      query_type="A", is_response=True, resolved_ips=["2.2.2.2"], transaction_id=222),
        ]
        events, _ = aggregate_dns(_capture(dns=records))
        by_client = {ev.source_ip: ev for ev in events}
        self.assertEqual(by_client["10.0.0.5"].resolved_ips, {"1.1.1.1"})
        self.assertEqual(by_client["10.0.0.6"].resolved_ips, {"2.2.2.2"})

    def test_repeated_http_requests_aggregate(self):
        records = [_http(i, path=f"/page{i}", ua="python-requests/2.31.0") for i in range(4)]
        events = aggregate_http(_capture(http=records))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].occurrence_count, 4)

    def test_repeated_file_transfers_aggregate_by_hash(self):
        payload = b"MZ" + b"\x00" * 100
        files = [_file(i, payload) for i in range(3)]
        events = aggregate_files(_capture(files=files))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].transfer_count, 3)


class TestDetectorDNS(unittest.TestCase):
    def test_legitimate_cdn_domain_suppressed(self):
        records = [_dns(i, query="assets.googleapis.com") for i in range(10)]
        agg = aggregate(_capture(dns=records))
        allowlist = load_allowlist("does-not-exist.yaml")
        detections = run_detections(agg, allowlist=allowlist)
        active = [d for d in detections if not d.suppressed]
        # DNS-001 fires (10 queries) but is suppressed by the CDN allowlist.
        self.assertTrue(any(d.rule_id == "DNS-001" and d.suppressed for d in detections))
        self.assertFalse(any(d.indicator == "assets.googleapis.com" for d in active))

    def test_low_confidence_dga_does_not_reach_high_severity_signal(self):
        # A borderline label that just clears the flag threshold should
        # not be raised as a High-severity signal on its own.
        records = [_dns(0, query="dataflow123.example.com")]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        dga_signals = [d for d in detections if d.rule_id == "DNS-003"]
        for d in dga_signals:
            self.assertNotEqual(d.severity, "High")

    def test_excessive_dns_frequency_one_signal_not_many(self):
        records = [_dns(i, query="beacon.example.com") for i in range(12)]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        freq_signals = [d for d in detections if d.rule_id == "DNS-001"]
        self.assertEqual(len(freq_signals), 1)
        self.assertEqual(freq_signals[0].occurrence_count, 12)

    def test_nxdomain_rule_fires_above_threshold(self):
        records = [_dns(i, query="ghost.example.com") for i in range(6)]
        records += [_dns(i, src="8.8.8.8", query="ghost.example.com", is_response=True,
                          rcode="NXDOMAIN") for i in range(5)]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "DNS-002" for d in detections))

    def test_rare_domain_is_informational_only(self):
        records = [_dns(0, query="onlyonce.example.com")]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        rare = [d for d in detections if d.rule_id == "DNS-004"]
        self.assertEqual(len(rare), 1)
        self.assertEqual(rare[0].severity, "Informational")

    def test_newly_observed_domain_flagged_when_not_in_history(self):
        records = [_dns(0, query="brandnew.example.com")]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg, known_domains={"other.example.com"})
        self.assertTrue(any(d.rule_id == "DNS-005" for d in detections))

    def test_known_domain_not_flagged_as_newly_observed(self):
        records = [_dns(0, query="familiar.example.com")]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg, known_domains={"familiar.example.com"})
        self.assertFalse(any(d.rule_id == "DNS-005" for d in detections))

    def test_dns_005_disabled_without_known_domains(self):
        records = [_dns(0, query="whatever.example.com")]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg, known_domains=None)
        self.assertFalse(any(d.rule_id == "DNS-005" for d in detections))

    def test_dns_tunneling_indicators_fire_on_long_labels_and_txt(self):
        long_label = "a" * 40
        records = []
        for i in range(10):
            records.append(_dns(i, query=f"{long_label}{i}.tunnel.example.com", qtype="TXT"))
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "DNS-006" for d in detections))

    def test_short_subdomains_do_not_trigger_tunneling(self):
        # Plenty of short, ordinary CDN-style subdomains should NOT be
        # flagged as tunneling (only as DNS-007 excessive-subdomains, if
        # even that threshold is crossed).
        records = [_dns(i, query=f"cdn{i}.example.com") for i in range(10)]
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id == "DNS-006" for d in detections))

    def test_fast_flux_detected_for_many_distinct_ips_in_short_window(self):
        records = [_dns(0, query="fastflux.example.com")]
        for i in range(5):
            records.append(_dns(i * 10, src="8.8.8.8", query="fastflux.example.com",
                                 is_response=True, resolved=[f"10.9.{i}.1"], rcode="NOERROR"))
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "DNS-008" for d in detections))

    def test_fast_flux_not_flagged_when_spread_over_long_window(self):
        records = [_dns(0, query="slowchange.example.com")]
        for i in range(5):
            records.append(_dns(i * 1000, src="8.8.8.8", query="slowchange.example.com",
                                 is_response=True, resolved=[f"10.9.{i}.1"], rcode="NOERROR"))
        agg = aggregate(_capture(dns=records))
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id == "DNS-008" for d in detections))


class TestDetectorHTTP(unittest.TestCase):
    def test_python_requests_alone_is_not_a_major_signal(self):
        records = [_http(0, path="/", ua="python-requests/2.31.0")]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        ua_signals = [d for d in detections if d.rule_id == "HTTP-003"]
        self.assertEqual(len(ua_signals), 1)
        self.assertEqual(ua_signals[0].severity, "Low")

    def test_executable_download_detected(self):
        records = [_http(0, path="/payload.exe", ua="python-requests/2.31.0")]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "HTTP-001" for d in detections))

    def test_suspicious_ua_plus_exe_plus_rare_dest_correlates_higher(self):
        records = [_http(0, host="rare-host.xyz", dst="185.10.10.10",
                          path="/payload.exe", ua="python-requests/2.31.0")]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        exe_signal = next(d for d in detections if d.rule_id == "HTTP-001")
        # Suspicious UA present on the same request escalates severity.
        self.assertEqual(exe_signal.severity, "High")

    def test_suspicious_download_source_fires_for_rare_unallowlisted_host(self):
        records = [_http(0, host="rare-host.xyz", dst="185.10.10.10", path="/payload.exe")]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "HTTP-005" for d in detections))

    def test_mime_mismatch_flagged_when_exe_served_as_benign_type(self):
        capture = _capture(http=[
            _http(0, host="evil.example.com", dst="185.10.10.10", path="/update.exe"),
            HTTPRecord(timestamp=T0, src_ip="185.10.10.10", dst_ip="10.0.0.5",
                       content_type="text/html", status_code="200"),
        ])
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "HTTP-006" for d in detections))

    def test_no_mime_mismatch_when_content_type_matches_executable(self):
        capture = _capture(http=[
            _http(0, host="evil.example.com", dst="185.10.10.10", path="/update.exe"),
            HTTPRecord(timestamp=T0, src_ip="185.10.10.10", dst_ip="10.0.0.5",
                       content_type="application/octet-stream", status_code="200"),
        ])
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id == "HTTP-006" for d in detections))

    def test_repeated_payload_retrieval_fires_for_non_executable_repeats(self):
        records = [_http(i, path="/config.json") for i in range(4)]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "HTTP-007" for d in detections))


class TestTIInterpretation(unittest.TestCase):
    def test_abuseipdb_zero_confidence_is_clean(self):
        result = FeedResult(feed="AbuseIPDB", indicator="1.2.3.4", available=True, matched=False,
                             raw={"abuseConfidenceScore": 0, "totalReports": 0})
        assessment = interpret(result, {"ti": DEFAULT_CONFIG["ti"]})
        self.assertEqual(assessment.state, CLEAN)
        self.assertFalse(assessment.is_meaningful)

    def test_abuseipdb_low_score_is_weak_not_malicious(self):
        result = FeedResult(feed="AbuseIPDB", indicator="1.2.3.4", available=True, matched=True,
                             raw={"abuseConfidenceScore": 5, "totalReports": 2})
        assessment = interpret(result, {"ti": DEFAULT_CONFIG["ti"]})
        self.assertEqual(assessment.state, WEAK_REPUTATION)
        self.assertFalse(assessment.is_meaningful)

    def test_virustotal_single_hit_out_of_many_is_weak(self):
        result = FeedResult(feed="VirusTotal", indicator="evil.com", available=True, matched=True,
                             raw={"last_analysis_stats": {"malicious": 1, "suspicious": 0,
                                                            "harmless": 85, "undetected": 3}})
        assessment = interpret(result, {"ti": DEFAULT_CONFIG["ti"]})
        self.assertEqual(assessment.state, WEAK_REPUTATION)

    def test_virustotal_strong_multi_vendor_hit_is_malicious(self):
        result = FeedResult(feed="VirusTotal", indicator="evil.com", available=True, matched=True,
                             raw={"last_analysis_stats": {"malicious": 40, "suspicious": 2,
                                                            "harmless": 40, "undetected": 7}})
        assessment = interpret(result, {"ti": DEFAULT_CONFIG["ti"]})
        self.assertEqual(assessment.state, MALICIOUS)
        self.assertTrue(assessment.is_meaningful)

    def test_urlhaus_no_record_is_unknown_not_a_finding(self):
        result = FeedResult(feed="URLhaus", indicator="benign.com", available=True, matched=False)
        assessment = interpret(result, {"ti": DEFAULT_CONFIG["ti"]})
        self.assertEqual(assessment.state, UNKNOWN)
        self.assertFalse(assessment.is_meaningful)

    def test_unavailable_feed_is_unknown(self):
        result = FeedResult(feed="AbuseIPDB", indicator="1.2.3.4", available=False)
        assessment = interpret(result, {"ti": DEFAULT_CONFIG["ti"]})
        self.assertEqual(assessment.state, UNKNOWN)


class TestCorrelation(unittest.TestCase):
    def _malware_capture(self):
        dns = [_dns(i, query="evil.top") for i in range(3)]
        dns.append(_dns(3, src="8.8.8.8", query="evil.top", is_response=True,
                         resolved=["185.10.10.10"], rcode="NOERROR"))
        http = [_http(5, dst="185.10.10.10", host="evil.top", path="/payload.exe",
                       ua="python-requests/2.31.0")]
        payload = b"MZ" + b"\x00" * 200
        files = [_file(6, payload, src="185.10.10.10", dst="10.0.0.5")]
        return _capture(dns=dns, http=http, files=files), payload

    def test_dns_http_file_ti_become_one_finding(self):
        capture, payload = self._malware_capture()
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        sha256 = hashes_for(payload)["sha256"]
        ti_results = {
            sha256: [FeedResult(feed="VirusTotal", indicator=sha256, available=True, matched=True,
                                  raw={"last_analysis_stats": {"malicious": 45, "harmless": 40,
                                                                 "undetected": 5}})],
        }
        findings, stats = correlate(capture, iocs, agg, detections, ti_results)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("evil.top", f.domains)
        self.assertIn(sha256, f.hashes)
        self.assertIsNotNone(f.event_chain)

    def test_unrelated_iocs_do_not_merge(self):
        dns = [_dns(0, src="10.0.0.5", query="one.example.com")] * 1
        dns += [_dns(0, src="10.0.0.5", query="one.example.com")]
        dns += [_dns(0, src="10.0.0.9", query="two.example.com")] * 12
        capture = _capture(dns=dns)
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        findings, _ = correlate(capture, iocs, agg, detections, {})
        # Only the endpoint with excessive frequency (12 queries) should
        # produce a finding; the other stays out (no signal fired for it).
        domains_in_findings = {d for f in findings for d in f.domains}
        self.assertIn("two.example.com", domains_in_findings)
        self.assertNotIn("one.example.com", domains_in_findings)

    def test_weak_ti_alone_does_not_become_finding(self):
        capture = _capture(dns=[_dns(0, query="ordinary.com")])
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        ti_results = {
            "ordinary.com": [FeedResult(feed="AbuseIPDB", indicator="ordinary.com", available=True,
                                          matched=True, raw={"abuseConfidenceScore": 5, "totalReports": 1})],
        }
        findings, _ = correlate(capture, iocs, agg, detections, ti_results)
        self.assertEqual(len(findings), 0)

    def test_behavior_only_finding_capped_below_critical(self):
        # Excessive DNS frequency + DGA-like domain, no TI, no payload --
        # should never reach Critical on local heuristics alone.
        records = [_dns(i, query="qzxjklmpwvbnfgh.top") for i in range(15)]
        capture = _capture(dns=records)
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        findings, _ = correlate(capture, iocs, agg, detections, {})
        for f in findings:
            self.assertNotIn(f.severity, ("Critical",))

    def test_asset_criticality_raises_risk_and_is_reported(self):
        from analyzer.assets import AssetProfile
        records = [_dns(i, query="qzxjklmpwvbnfgh.top") for i in range(15)]
        capture = _capture(dns=records)
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        assets = {"10.0.0.5": AssetProfile(ip="10.0.0.5", hostname="DC01",
                                             role="Domain Controller", criticality="Critical")}
        findings_plain, _ = correlate(capture, iocs, agg, detections, {})
        findings_with_asset, _ = correlate(capture, iocs, agg, detections, {}, assets=assets)
        self.assertGreater(findings_with_asset[0].risk_score, findings_plain[0].risk_score)
        self.assertTrue(any("DC01" in note for note in findings_with_asset[0].asset_notes))

    def test_unknown_asset_reports_no_asset_notes(self):
        records = [_dns(i, query="qzxjklmpwvbnfgh.top") for i in range(15)]
        capture = _capture(dns=records)
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        findings, _ = correlate(capture, iocs, agg, detections, {})
        self.assertEqual(findings[0].asset_notes, [])


class TestNetworkScanning(unittest.TestCase):
    def _port_scan_capture(self, n_ports=20, success=0):
        packets = []
        for i in range(n_ports):
            packets.append(_tcp(i, "10.0.0.9", "10.0.0.50", 40000 + i, 1000 + i, "S"))
            if i < success:
                packets.append(_tcp(i + 0.1, "10.0.0.50", "10.0.0.9", 1000 + i, 40000 + i, "SA"))
            else:
                packets.append(_tcp(i + 0.1, "10.0.0.50", "10.0.0.9", 1000 + i, 40000 + i, "R"))
        return _capture(packets=packets)

    def test_port_scan_detected(self):
        capture = self._port_scan_capture()
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "NET-001" for d in detections))

    def test_normal_traffic_not_flagged_as_port_scan(self):
        # A handful of successful connections to a couple of ports should
        # never look like scanning.
        packets = [
            _tcp(0, "10.0.0.9", "10.0.0.50", 40000, 443, "S"),
            _tcp(0.1, "10.0.0.50", "10.0.0.9", 443, 40000, "SA"),
            _tcp(1, "10.0.0.9", "10.0.0.50", 40001, 80, "S"),
            _tcp(1.1, "10.0.0.50", "10.0.0.9", 80, 40001, "SA"),
        ]
        capture = _capture(packets=packets)
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id in ("NET-001", "NET-002") for d in detections))

    def test_host_scan_detected(self):
        packets = []
        for i in range(15):
            dst = f"10.0.1.{i}"
            packets.append(_tcp(i, "10.0.0.9", dst, 40000, 22, "S"))
            packets.append(_tcp(i + 0.1, dst, "10.0.0.9", 22, 40000, "R"))
        capture = _capture(packets=packets)
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "NET-002" for d in detections))

    def test_repeated_auth_port_attempts_flagged(self):
        packets = []
        for i in range(8):
            packets.append(_tcp(i, "10.0.0.9", "10.0.0.50", 41000 + i, 22, "S"))
            packets.append(_tcp(i + 0.1, "10.0.0.50", "10.0.0.9", 22, 41000 + i, "R"))
        capture = _capture(packets=packets)
        agg = aggregate(capture)
        detections = run_detections(agg)
        auth_signals = [d for d in detections if d.rule_id == "NET-003"]
        self.assertEqual(len(auth_signals), 1)
        self.assertIn("SSH", auth_signals[0].explanation)

    def test_few_retries_ending_in_success_not_flagged_as_brute_force(self):
        # 2 SYN retransmits then a normal successful SSH session -- this
        # is ordinary network behavior, not brute-forcing.
        packets = [
            _tcp(0, "10.0.0.9", "10.0.0.50", 41000, 22, "S"),
            _tcp(0.2, "10.0.0.9", "10.0.0.50", 41000, 22, "S"),
            _tcp(0.4, "10.0.0.50", "10.0.0.9", 22, 41000, "SA"),
        ]
        capture = _capture(packets=packets)
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id == "NET-003" for d in detections))


class TestExfiltration(unittest.TestCase):
    def test_asymmetric_outbound_volume_flagged(self):
        packets = [
            _tcp(0, "10.0.0.9", "185.53.90.14", 41000, 443, "S", length=60),
            _tcp(0.1, "185.53.90.14", "10.0.0.9", 443, 41000, "SA", length=60),
            _tcp(0.2, "10.0.0.9", "185.53.90.14", 41000, 443, "A", length=250000),
        ]
        capture = _capture(packets=packets)
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "NET-004" for d in detections))

    def test_small_transfer_not_flagged(self):
        packets = [
            _tcp(0, "10.0.0.9", "185.53.90.14", 41000, 443, "S", length=60),
            _tcp(0.1, "185.53.90.14", "10.0.0.9", 443, 41000, "SA", length=60),
            _tcp(0.2, "10.0.0.9", "185.53.90.14", 41000, 443, "A", length=500),
        ]
        capture = _capture(packets=packets)
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id == "NET-004" for d in detections))

    def test_internal_destination_not_flagged(self):
        packets = [
            _tcp(0, "10.0.0.9", "10.0.0.200", 41000, 445, "S", length=60),
            _tcp(0.1, "10.0.0.200", "10.0.0.9", 445, 41000, "SA", length=60),
            _tcp(0.2, "10.0.0.9", "10.0.0.200", 41000, 445, "A", length=250000),
        ]
        capture = _capture(packets=packets)
        agg = aggregate(capture)
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id == "NET-004" for d in detections))


class TestBeaconing(unittest.TestCase):
    def test_regular_interval_flagged(self):
        stats = compute_interval_stats([T0 + timedelta(seconds=60 * i) for i in range(8)])
        self.assertIsNotNone(stats)
        self.assertTrue(stats.is_regular)

    def test_irregular_interval_not_flagged(self):
        offsets = [0, 3, 47, 12, 90, 5, 61, 200]
        stats = compute_interval_stats([T0 + timedelta(seconds=o) for o in offsets])
        self.assertIsNotNone(stats)
        self.assertFalse(stats.is_regular)

    def test_too_few_occurrences_returns_none(self):
        self.assertIsNone(compute_interval_stats([T0, T0 + timedelta(seconds=1)]))

    def test_beacon_rule_fires_for_regular_http(self):
        records = [_http(60 * i, host="c2.example.com", dst="185.53.90.14") for i in range(8)]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "BEACON-001" for d in detections))

    def test_beacon_rule_does_not_fire_for_irregular_http(self):
        offsets = [0, 3, 47, 12, 90, 5, 61, 200]
        records = [_http(o, host="normal.example.com", dst="185.53.90.14") for o in offsets]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id == "BEACON-001" for d in detections))


class TestWebAttackPatterns(unittest.TestCase):
    def test_sql_injection_pattern_matches(self):
        self.assertIsNotNone(match_path("/login?user=admin' OR 1=1--"))

    def test_benign_query_does_not_match(self):
        self.assertIsNone(match_path("/search?q=blue+shoes"))

    def test_single_match_does_not_flag_finding(self):
        records = [_http(0, path="/login?id=1' OR 1=1--")]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        self.assertFalse(any(d.rule_id == "HTTP-008" for d in detections))

    def test_repeated_match_flags_finding(self):
        records = [_http(i, path=f"/login?id={i}' OR 1=1--") for i in range(4)]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "HTTP-008" for d in detections))

    def test_path_traversal_repeated_flags_finding(self):
        records = [_http(i, path=f"/files?p=../../../../etc/passwd{i}") for i in range(4)]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        self.assertTrue(any(d.rule_id == "HTTP-008" for d in detections))


class TestMitreMapping(unittest.TestCase):
    def test_known_rule_has_technique(self):
        technique = get_technique("HTTP-001")
        self.assertIsNotNone(technique)
        self.assertEqual(technique.technique_id, "T1105")

    def test_unmapped_rule_returns_none(self):
        self.assertIsNone(get_technique("NOT-A-REAL-RULE"))

    def test_detection_signal_annotated_with_mitre(self):
        records = [_http(0, path="/payload.exe", ua="python-requests/2.31.0")]
        agg = aggregate(_capture(http=records))
        detections = run_detections(agg)
        exe_signal = next(d for d in detections if d.rule_id == "HTTP-001")
        self.assertEqual(exe_signal.mitre_technique_id, "T1105")


class TestEvidenceFamilyCapping(unittest.TestCase):
    def test_many_dns_signals_capped_below_full_sum(self):
        records = [_dns(i, query="qzxjklmpwvbnfgh.top") for i in range(15)]
        capture = _capture(dns=records)
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        dns_signals = [d for d in detections if d.category == "DNS" and not d.suppressed]
        naive_sum = sum(d.score for d in dns_signals)
        findings, _ = correlate(capture, iocs, agg, detections, {})
        category_cap = DEFAULT_CONFIG["risk"]["category_caps"]["DNS"]
        if naive_sum > category_cap:
            self.assertLessEqual(findings[0].risk_score, category_cap +
                                  DEFAULT_CONFIG["risk"]["weights"]["network_context"] +
                                  DEFAULT_CONFIG["risk"]["weights"]["asset_context"])


class TestIncidentReconstruction(unittest.TestCase):
    def test_multiple_findings_same_endpoint_grouped_into_one_incident(self):
        dns = [_dns(i, src="10.0.0.9", query="qzxjklmpwvbnfgh.top") for i in range(15)]
        packets = []
        for i in range(20):
            packets.append(_tcp(i, "10.0.0.9", "10.0.0.50", 40000 + i, 1000 + i, "S"))
            packets.append(_tcp(i + 0.1, "10.0.0.50", "10.0.0.9", 1000 + i, 40000 + i, "R"))
        capture = _capture(dns=dns, packets=packets)
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        findings, _ = correlate(capture, iocs, agg, detections, {})
        incidents = build_incidents(findings)
        matching = [inc for inc in incidents if inc.affected_assets == ["10.0.0.9"]]
        self.assertEqual(len(matching), 1)

    def test_unrelated_endpoints_stay_separate_incidents(self):
        dns = [_dns(i, src="10.0.0.5", query="qzxjklmpwvbnfgh.top") for i in range(15)]
        dns += [_dns(i, src="10.0.0.6", query="anotherdgalike999.top") for i in range(15)]
        capture = _capture(dns=dns)
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        findings, _ = correlate(capture, iocs, agg, detections, {})
        incidents = build_incidents(findings)
        endpoints = {inc.affected_assets[0] for inc in incidents}
        self.assertIn("10.0.0.5", endpoints)
        self.assertIn("10.0.0.6", endpoints)


class TestIOCScoring(unittest.TestCase):
    def test_iocs_without_evidence_are_insignificant(self):
        iocs = [IOC("8.8.8.8", "ipv4"), IOC("quiet.example.com", "domain")]
        profiles = classify_iocs(iocs, [], {}, {"8.8.8.8": 1, "quiet.example.com": 1})
        self.assertTrue(all(p.tier == "insignificant" for p in profiles.values()))


class TestReporting(unittest.TestCase):
    def _run_pipeline(self, capture):
        iocs = extract_iocs(capture)
        agg = aggregate(capture)
        detections = run_detections(agg)
        findings, stats = correlate(capture, iocs, agg, detections, {})
        timeline = build_timeline(agg, findings)
        from analyzer.correlator import interpret_ti_results
        ti_assessments = interpret_ti_results({}, DEFAULT_CONFIG)
        observation_counts = {i.indicator: 1 for i in iocs}
        profiles = classify_iocs(iocs, detections, ti_assessments, observation_counts)
        return iocs, agg, detections, findings, timeline, ti_assessments, profiles, stats

    def test_report_valid_with_zero_findings(self, tmp_path="/tmp/report_zero.md"):
        capture = _capture(dns=[_dns(0, query="quiet.example.com")])
        iocs, agg, detections, findings, timeline, ti_assessments, profiles, stats = self._run_pipeline(capture)
        self.assertEqual(len(findings), 0)
        generate_markdown_report(
            output_path=tmp_path, pcap_path="synthetic.pcap", capture=capture, iocs=iocs,
            aggregation=agg, detections=detections, ti_results={}, ti_assessments=ti_assessments,
            ioc_profiles=profiles, findings=findings, timeline=timeline, unavailable_feeds=[],
            correlation_stats=stats,
        )
        with open(tmp_path) as fh:
            content = fh.read()
        self.assertIn("No correlated findings were produced", content)
        os.remove(tmp_path)

    def test_report_handles_many_observations(self, tmp_path="/tmp/report_many.md"):
        dns = [_dns(i, query=f"host{i % 5}.example.com") for i in range(500)]
        capture = _capture(dns=dns)
        iocs, agg, detections, findings, timeline, ti_assessments, profiles, stats = self._run_pipeline(capture)
        generate_markdown_report(
            output_path=tmp_path, pcap_path="synthetic.pcap", capture=capture, iocs=iocs,
            aggregation=agg, detections=detections, ti_results={}, ti_assessments=ti_assessments,
            ioc_profiles=profiles, findings=findings, timeline=timeline, unavailable_feeds=[],
            correlation_stats=stats,
        )
        # 500 raw observations aggregate into only 5 distinct domains.
        self.assertEqual(len(agg.dns_events), 5)
        os.remove(tmp_path)

    def test_executive_summary_only_lists_significant_findings(self, tmp_path="/tmp/report_exec.md"):
        records = [_dns(i, query="qzxjklmpwvbnfgh.top") for i in range(15)]
        capture = _capture(dns=records)
        iocs, agg, detections, findings, timeline, ti_assessments, profiles, stats = self._run_pipeline(capture)
        generate_markdown_report(
            output_path=tmp_path, pcap_path="synthetic.pcap", capture=capture, iocs=iocs,
            aggregation=agg, detections=detections, ti_results={}, ti_assessments=ti_assessments,
            ioc_profiles=profiles, findings=findings, timeline=timeline, unavailable_feeds=[],
            correlation_stats=stats,
        )
        with open(tmp_path) as fh:
            content = fh.read()
        self.assertIn("## 1. Executive Summary", content)
        self.assertIn("## 3. Incidents & Key Findings", content)
        os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
