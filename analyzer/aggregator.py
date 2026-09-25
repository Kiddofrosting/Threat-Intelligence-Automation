"""Behavioral aggregation layer.

This sits between the raw parser output and the detection engine.
Nothing here decides whether something is suspicious -- it only
groups repeated raw observations (individual DNS queries, HTTP
requests/responses, file transfers) into behavioral events with
occurrence counts, first/last-seen timestamps, and enough information
to reconstruct the underlying evidence. This is what stops "one
detection per query" from happening: the detection engine
(detector.py) evaluates the *events* produced here, not raw records.

No raw evidence is discarded.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from analyzer.network_events import ConnectionAttempt, ScanCandidate, aggregate_connections
from analyzer.pcap_parser import ParsedCapture
from utils.hashing import hashes_for, identify_signature

# Cap on how many per-occurrence timestamps a single behavioral event
# keeps (for beaconing interval statistics) -- prevents unbounded
# memory growth against a pathological single-bucket flood while
# still giving interval analysis a large, representative sample.
MAX_STORED_TIMESTAMPS = 500


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
    timestamps: List[datetime] = field(default_factory=list)  # capped -- see aggregate_dns

    @property
    def duration_seconds(self) -> float:
        return max((self.last_seen - self.first_seen).total_seconds(), 0.0)

    @property
    def nxdomain_ratio(self) -> float:
        return self.nxdomain_count / self.occurrence_count if self.occurrence_count else 0.0


@dataclass
class DomainResolution:
    """Domain-level (not per-client) view of what a name resolved to --
    used for fast-flux detection, where what matters is how many
    *distinct* IPs a name resolves to across all queriers, not any one
    client's slice of that activity."""
    domain: str
    query_type: str
    resolved_ips: Set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    response_count: int = 0

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return max((self.last_seen - self.first_seen).total_seconds(), 0.0)


@dataclass
class HTTPBehavior:
    """All HTTP request activity for one (client, server, UA) tuple,
    with response metadata (status/content-type) folded in when a
    matching response was observed on the same client<->server pair."""
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
    content_types: Dict[str, int] = field(default_factory=dict)
    status_codes: Dict[str, int] = field(default_factory=dict)
    timestamps: List[datetime] = field(default_factory=list)  # capped -- see aggregate_http


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
    dns_domain_resolutions: Dict[Tuple[str, str], DomainResolution]
    connection_attempts: List[ConnectionAttempt]
    scan_candidates: Dict[str, ScanCandidate]
    raw_dns_observations: int
    raw_http_observations: int
    raw_file_observations: int
    raw_packet_observations: int


def aggregate_dns(capture: ParsedCapture) -> Tuple[List[DNSBehavior], Dict[Tuple[str, str], DomainResolution]]:
    """Group DNS queries by (client source IP, domain, query type).

    Query records drive occurrence counting and timing, keyed by the
    querying client's IP. Response records are emitted by the
    *server*, not the client, so pairing them back to the right
    client uses the DNS transaction ID (query and response share the
    same 16-bit header ID) whenever it is available -- this is exact,
    unlike matching purely on domain name. Only when a response's
    transaction ID has no matching outstanding query (e.g. an
    out-of-order or truncated capture) do we fall back to merging the
    response into every client bucket for the same (domain, query
    type), which is the best available approximation in that case.

    A second, domain-level (not per-client) resolution view is built
    alongside the client buckets -- this is what fast-flux detection
    (DNS-008) needs, since fast-flux is about how many distinct IPs a
    name resolves to in aggregate, not any one client's slice of it.
    """
    client_buckets: Dict[Tuple[str, str, str], DNSBehavior] = {}
    query_client_by_txid: Dict[int, Tuple[str, str, str]] = {}
    fallback_side_data: Dict[Tuple[str, str], dict] = {}
    domain_resolutions: Dict[Tuple[str, str], DomainResolution] = {}

    def _apply_response_to_bucket(beh: DNSBehavior, rec) -> None:
        beh.resolved_ips.update(rec.resolved_ips)
        if rec.response_code:
            beh.response_codes[rec.response_code] = beh.response_codes.get(rec.response_code, 0) + 1
            if rec.response_code == "NXDOMAIN":
                beh.nxdomain_count += 1

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
            if len(beh.timestamps) < MAX_STORED_TIMESTAMPS:
                beh.timestamps.append(rec.timestamp)
            if rec.transaction_id is not None:
                query_client_by_txid[rec.transaction_id] = key
        else:
            # Domain-level resolution view (independent of pairing precision).
            dom_key = (domain, qtype)
            dom = domain_resolutions.get(dom_key)
            if dom is None:
                dom = DomainResolution(domain=domain, query_type=qtype)
                domain_resolutions[dom_key] = dom
            dom.resolved_ips.update(rec.resolved_ips)
            dom.response_count += 1
            dom.first_seen = rec.timestamp if dom.first_seen is None else min(dom.first_seen, rec.timestamp)
            dom.last_seen = rec.timestamp if dom.last_seen is None else max(dom.last_seen, rec.timestamp)

            matched_key = None
            if rec.transaction_id is not None:
                matched_key = query_client_by_txid.get(rec.transaction_id)
            if matched_key is not None and matched_key in client_buckets:
                _apply_response_to_bucket(client_buckets[matched_key], rec)
            else:
                # No exact query<->response pairing available -- fall back
                # to a domain-keyed side table merged into every matching
                # client bucket below.
                side = fallback_side_data.setdefault(dom_key, {"resolved_ips": set(),
                                                                  "response_codes": {},
                                                                  "nxdomain_count": 0})
                side["resolved_ips"].update(rec.resolved_ips)
                if rec.response_code:
                    side["response_codes"][rec.response_code] = side["response_codes"].get(rec.response_code, 0) + 1
                    if rec.response_code == "NXDOMAIN":
                        side["nxdomain_count"] += 1

    for key, beh in client_buckets.items():
        side = fallback_side_data.get((beh.domain, beh.query_type))
        if side:
            beh.resolved_ips |= side["resolved_ips"]
            for code, count in side["response_codes"].items():
                beh.response_codes[code] = beh.response_codes.get(code, 0) + count
            beh.nxdomain_count += side["nxdomain_count"]

    events = sorted(client_buckets.values(), key=lambda b: (-b.occurrence_count, b.domain))
    return events, domain_resolutions


def aggregate_http(capture: ParsedCapture) -> List[HTTPBehavior]:
    """Group HTTP requests by (client, server, User-Agent), then fold
    in response-only records (status code, content type) observed on
    the same client<->server pair -- the response packet is emitted by
    the server, so its src/dst are the request's dst/src."""
    buckets: Dict[Tuple[str, str, Optional[str]], HTTPBehavior] = {}
    by_pair: Dict[Tuple[str, str], List[HTTPBehavior]] = defaultdict(list)

    for rec in capture.http_records:
        if not rec.method:
            continue  # handled in the response pass below
        host = (rec.host or rec.dst_ip or "unknown").split(":")[0]
        key = (rec.src_ip, rec.dst_ip, rec.user_agent)
        beh = buckets.get(key)
        if beh is None:
            beh = HTTPBehavior(source_ip=rec.src_ip, dest_ip=rec.dst_ip, host=host,
                                user_agent=rec.user_agent,
                                first_seen=rec.timestamp, last_seen=rec.timestamp)
            buckets[key] = beh
            by_pair[(rec.src_ip, rec.dst_ip)].append(beh)
        beh.occurrence_count += 1
        beh.first_seen = min(beh.first_seen, rec.timestamp)
        beh.last_seen = max(beh.last_seen, rec.timestamp)
        beh.methods.add(rec.method)
        if len(beh.timestamps) < MAX_STORED_TIMESTAMPS:
            beh.timestamps.append(rec.timestamp)
        if rec.path:
            if rec.path not in beh.path_counts:
                beh.paths.append(rec.path)
            beh.path_counts[rec.path] = beh.path_counts.get(rec.path, 0) + 1

    for rec in capture.http_records:
        if rec.method or not rec.status_code:
            continue  # a response record has no method
        # Response is server -> client: src=server, dst=client. The
        # matching request bucket was keyed on client -> server.
        matching = by_pair.get((rec.dst_ip, rec.src_ip))
        if not matching:
            continue
        for beh in matching:
            if rec.status_code:
                beh.status_codes[rec.status_code] = beh.status_codes.get(rec.status_code, 0) + 1
            if rec.content_type:
                beh.content_types[rec.content_type] = beh.content_types.get(rec.content_type, 0) + 1

    return sorted(buckets.values(), key=lambda b: (-b.occurrence_count, b.host))


def aggregate_files(capture: ParsedCapture) -> List[FileBehavior]:
    """Group recovered file payloads by content (SHA256)."""
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
    dns_events, domain_resolutions = aggregate_dns(capture)
    connection_attempts, scan_candidates = aggregate_connections(capture)
    return AggregationResult(
        dns_events=dns_events,
        http_events=aggregate_http(capture),
        file_events=aggregate_files(capture),
        dns_domain_resolutions=domain_resolutions,
        connection_attempts=connection_attempts,
        scan_candidates=scan_candidates,
        raw_dns_observations=len(capture.dns_records),
        raw_http_observations=len(capture.http_records),
        raw_file_observations=len(capture.files),
        raw_packet_observations=len(capture.packets),
    )
