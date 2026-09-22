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

from analyzer.aggregator import aggregate, aggregate_dns, aggregate_files, aggregate_http
from analyzer.allowlist import check_domain, load_allowlist
from analyzer.config import DEFAULT_CONFIG, band_from_score, min_severity
from analyzer.correlator import build_timeline, correlate
from analyzer.detector import run_detections
from analyzer.dga import score_domain
from analyzer.ioc_extractor import IOC, extract_iocs
from analyzer.ioc_scoring import classify_iocs
from analyzer.pcap_parser import DNSRecord, ExtractedFile, HTTPRecord, PacketRecord, ParsedCapture
from analyzer.reporter import generate_markdown_report
from analyzer.ti_interpreter import CLEAN, MALICIOUS, SUSPICIOUS, UNKNOWN, WEAK_REPUTATION, interpret
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


class TestAggregation(unittest.TestCase):
    def test_repeated_dns_queries_aggregate_into_one_event(self):
        records = [_dns(i, query="beacon.example.com") for i in range(5)]
        events = aggregate_dns(_capture(dns=records))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].occurrence_count, 5)

    def test_dns_response_data_merges_into_client_bucket(self):
        records = [
            _dns(0, query="example.com"),
            _dns(1, src="8.8.8.8", query="example.com", is_response=True,
                 resolved=["93.184.216.34"], rcode="NOERROR"),
        ]
        events = aggregate_dns(_capture(dns=records))
        self.assertEqual(len(events), 1)
        self.assertIn("93.184.216.34", events[0].resolved_ips)

    def test_nxdomain_ratio_computed(self):
        records = [_dns(i, query="ghost.example.com") for i in range(4)]
        records += [_dns(i, src="8.8.8.8", query="ghost.example.com", is_response=True,
                          rcode="NXDOMAIN") for i in range(4)]
        events = aggregate_dns(_capture(dns=records))
        self.assertEqual(events[0].nxdomain_ratio, 1.0)

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
        self.assertIn("## 2. Key Findings", content)
        os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
