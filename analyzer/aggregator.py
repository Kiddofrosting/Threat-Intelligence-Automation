"""Behavioral aggregation layer.

This sits between the raw parser output and the detection engine.
Nothing here decides whether something is suspicious -- it only
groups repeated raw observations (individual DNS queries, HTTP
requests, file transfers) into behavioral events with occurrence
counts, first/last-seen timestamps and references back to the
underlying evidence. This is what stops "one detection per query"
from happening: the detection engine (detector.py) evaluates the
*events* produced here, not the raw records.

No raw evidence is discarded -- every BehavioralEvent keeps enough
information to reconstruct which raw records it was built from.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from analyzer.pcap_parser import ParsedCapture
from utils.hashing import hashes_for, identify_signature


@dataclass
class DNSBehavior:
    """All DNS activity for one (client, domain, query type) tuple."""
    source_ip: str
    domain: str
    query_type: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 0
    nxdomain_count: int = 0
    response_codes: Dict[str, int] = field(default_factory=dict)
    resolved_ips: Set[str] = field(default_factory=set)

    @property
    def duration_seconds(self) -> float:
        return max((self.last_seen - self.first_seen).total_seconds(), 0.0)

    @property
    def nxdomain_ratio(self) -> float:
        return self.nxdomain_count / self.occurrence_count if self.occurrence_count else 0.0


@dataclass
class HTTPBehavior:
    """All HTTP request activity for one (client, server, UA) tuple."""
    source_ip: str
    dest_ip: str
    host: str
    user_agent: Optional[str]
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 0
    paths: List[str] = field(default_factory=list)     # de-duplicated, insertion order
    methods: Set[str] = field(default_factory=set)
    path_counts: Dict[str, int] = field(default_factory=dict)


@dataclass
class FileBehavior:
    """All transfers of one distinct payload (identified by SHA256)."""
    sha256: str
    md5: str
    sha1: str
    src_ip: str
    dst_ip: str
    size: int
    signature: Optional[str]
    first_seen: datetime
    last_seen: datetime
    transfer_count: int = 0


@dataclass
class AggregationResult:
    dns_events: List[DNSBehavior]
    http_events: List[HTTPBehavior]
    file_events: List[FileBehavior]
    raw_dns_observations: int
    raw_http_observations: int
    raw_file_observations: int


def aggregate_dns(capture: ParsedCapture) -> List[DNSBehavior]:
    """Group DNS queries by (client source IP, domain, query type).

    Query records (the actual client lookups) drive occurrence
    counting and timing, keyed by the querying client's IP. Response
    records carry resolved IPs and response codes but are emitted by
    the *server*, not the client, so they are folded in as side data
    keyed only by (domain, query type) and merged into every matching
    client bucket. With no DNS transaction ID retained at this layer,
    a domain queried by multiple distinct clients in the same capture
    will have response data merged into all of their buckets -- a
    known, documented approximation.
    """
    client_buckets: Dict[Tuple[str, str, str], DNSBehavior] = {}
    domain_side_data: Dict[Tuple[str, str], dict] = {}

    for rec in capture.dns_records:
        if not rec.query:
            continue
        domain = rec.query.lower()
        qtype = rec.query_type or "A"

        if not rec.is_response:
            key = (rec.src_ip, domain, qtype)
            beh = client_buckets.get(key)
            if beh is None:
                beh = DNSBehavior(source_ip=rec.src_ip, domain=domain, query_type=qtype,
                                   first_seen=rec.timestamp, last_seen=rec.timestamp)
                client_buckets[key] = beh
            beh.occurrence_count += 1
            beh.first_seen = min(beh.first_seen, rec.timestamp)
            beh.last_seen = max(beh.last_seen, rec.timestamp)
        else:
            side_key = (domain, qtype)
            side = domain_side_data.setdefault(side_key, {"resolved_ips": set(),
                                                            "response_codes": {},
                                                            "nxdomain_count": 0})
            for ip in rec.resolved_ips:
                side["resolved_ips"].add(ip)
            if rec.response_code:
                side["response_codes"][rec.response_code] = side["response_codes"].get(rec.response_code, 0) + 1
                if rec.response_code == "NXDOMAIN":
                    side["nxdomain_count"] += 1

    for beh in client_buckets.values():
        side = domain_side_data.get((beh.domain, beh.query_type))
        if side:
            beh.resolved_ips |= side["resolved_ips"]
            for code, count in side["response_codes"].items():
                beh.response_codes[code] = beh.response_codes.get(code, 0) + count
            beh.nxdomain_count += side["nxdomain_count"]

    return sorted(client_buckets.values(), key=lambda b: (-b.occurrence_count, b.domain))


def aggregate_http(capture: ParsedCapture) -> List[HTTPBehavior]:
    """Group HTTP requests by (client, server, User-Agent)."""
    buckets: Dict[Tuple[str, str, Optional[str]], HTTPBehavior] = {}

    for rec in capture.http_records:
        if not rec.method:
            continue  # response-only record; no request identity to group on
        host = (rec.host or rec.dst_ip or "unknown").split(":")[0]
        key = (rec.src_ip, rec.dst_ip, rec.user_agent)
        beh = buckets.get(key)
        if beh is None:
            beh = HTTPBehavior(source_ip=rec.src_ip, dest_ip=rec.dst_ip, host=host,
                                user_agent=rec.user_agent,
                                first_seen=rec.timestamp, last_seen=rec.timestamp)
            buckets[key] = beh
        beh.occurrence_count += 1
        beh.first_seen = min(beh.first_seen, rec.timestamp)
        beh.last_seen = max(beh.last_seen, rec.timestamp)
        beh.methods.add(rec.method)
        if rec.path:
            if rec.path not in beh.path_counts:
                beh.paths.append(rec.path)
            beh.path_counts[rec.path] = beh.path_counts.get(rec.path, 0) + 1

    return sorted(buckets.values(), key=lambda b: (-b.occurrence_count, b.host))


def aggregate_files(capture: ParsedCapture) -> List[FileBehavior]:
    """Group recovered file payloads by content (SHA256) -- the same
    payload transferred more than once becomes one behavioral event
    with a transfer_count, not N separate ones."""
    buckets: Dict[str, FileBehavior] = {}

    for f in capture.files:
        digests = hashes_for(f.data)
        sha256 = digests["sha256"]
        beh = buckets.get(sha256)
        if beh is None:
            beh = FileBehavior(sha256=sha256, md5=digests["md5"], sha1=digests["sha1"],
                                src_ip=f.src_ip, dst_ip=f.dst_ip, size=f.size,
                                signature=identify_signature(f.data),
                                first_seen=f.timestamp, last_seen=f.timestamp)
            buckets[sha256] = beh
        beh.transfer_count += 1
        beh.first_seen = min(beh.first_seen, f.timestamp)
        beh.last_seen = max(beh.last_seen, f.timestamp)

    return sorted(buckets.values(), key=lambda b: (-b.transfer_count, b.sha256))


def aggregate(capture: ParsedCapture) -> AggregationResult:
    return AggregationResult(
        dns_events=aggregate_dns(capture),
        http_events=aggregate_http(capture),
        file_events=aggregate_files(capture),
        raw_dns_observations=len(capture.dns_records),
        raw_http_observations=len(capture.http_records),
        raw_file_observations=len(capture.files),
    )
