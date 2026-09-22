"""Reads a PCAP file with Scapy and turns raw packets into plain,
structured Python objects (dataclasses) that the rest of the pipeline
can work with without ever touching Scapy again.

Every layer is optional here on purpose — real-world captures are messy,
and a packet missing a field should never crash the run.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

try:
    # Scapy's HTTP layer needs the load_layer call before it will parse.
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    import scapy.all as scapy_all
    scapy_all.load_layer("http")
    HTTP_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    HTTP_AVAILABLE = False


@dataclass
class PacketRecord:
    """One packet's worth of metadata. Fields are None when the layer
    that would provide them wasn't present in this packet."""
    index: int
    timestamp: datetime
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    length: int = 0


@dataclass
class DNSRecord:
    timestamp: datetime
    src_ip: str
    dns_server: Optional[str]
    query: Optional[str]
    query_type: Optional[str]
    is_response: bool
    resolved_ips: List[str] = field(default_factory=list)
    response_code: Optional[str] = None  # NOERROR / NXDOMAIN / SERVFAIL / ... (responses only)


@dataclass
class HTTPRecord:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    method: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None
    content_type: Optional[str] = None
    status_code: Optional[str] = None
    content_length: Optional[int] = None


@dataclass
class ExtractedFile:
    """A file (or file-like blob) reassembled from raw TCP payload.
    Best-effort only — plain HTTP file transfers are the realistic case
    for a Scapy-based tool; anything encrypted is out of reach."""
    src_ip: str
    dst_ip: str
    filename: Optional[str]
    size: int
    data: bytes
    timestamp: datetime  # evidence timestamp from the capture, never processing time


@dataclass
class ParsedCapture:
    pcap_path: str
    packets: List[PacketRecord] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    http_records: List[HTTPRecord] = field(default_factory=list)
    files: List[ExtractedFile] = field(default_factory=list)
    total_packets: int = 0

    def protocol_counts(self):
        counts = {}
        for p in self.packets:
            counts[p.protocol or "OTHER"] = counts.get(p.protocol or "OTHER", 0) + 1
        return counts


DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def _pkt_time(pkt) -> datetime:
    try:
        return datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _looks_like_pe_or_script(payload: bytes) -> bool:
    return payload.startswith((b"MZ", b"PK\x03\x04", b"#!")) or payload[:2] in (b"MZ",)


def parse_pcap(pcap_path: str, logger=None) -> ParsedCapture:
    """Load the capture and extract network metadata, DNS, HTTP and any
    recoverable file payloads. Missing layers are simply skipped."""
    packets = rdpcap(pcap_path)
    capture = ParsedCapture(pcap_path=pcap_path, total_packets=len(packets))

    for idx, pkt in enumerate(packets):
        ts = _pkt_time(pkt)
        record = PacketRecord(index=idx, timestamp=ts, length=len(pkt))

        if IP in pkt:
            record.src_ip = pkt[IP].src
            record.dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
            if TCP in pkt:
                record.protocol = "TCP"
                record.src_port = int(pkt[TCP].sport)
                record.dst_port = int(pkt[TCP].dport)
            elif UDP in pkt:
                record.protocol = "UDP"
                record.src_port = int(pkt[UDP].sport)
                record.dst_port = int(pkt[UDP].dport)
            else:
                record.protocol = f"IP-PROTO-{proto_num}"
        else:
            record.protocol = pkt.__class__.__name__

        capture.packets.append(record)

        # --- DNS ---
        if DNS in pkt and pkt.haslayer(DNS):
            dns_layer = pkt[DNS]
            is_response = bool(dns_layer.qr)
            query_name, query_type = None, None
            if dns_layer.qdcount and DNSQR in pkt:
                try:
                    query_name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    query_type = DNS_QTYPES.get(int(pkt[DNSQR].qtype), str(pkt[DNSQR].qtype))
                except Exception:
                    pass
            response_code = None
            if is_response:
                try:
                    response_code = DNS_RCODES.get(int(dns_layer.rcode), str(dns_layer.rcode))
                except Exception:
                    pass

            resolved = []
            if is_response and dns_layer.ancount:
                an = dns_layer.an
                for _ in range(dns_layer.ancount):
                    if an is None:
                        break
                    try:
                        if hasattr(an, "rdata"):
                            rdata = an.rdata
                            resolved.append(rdata if isinstance(rdata, str) else rdata.decode(errors="ignore"))
                    except Exception:
                        pass
                    an = an.payload if isinstance(an.payload, type(an)) else None

            capture.dns_records.append(DNSRecord(
                timestamp=ts,
                src_ip=record.src_ip or "unknown",
                dns_server=record.dst_ip if not is_response else record.src_ip,
                query=query_name,
                query_type=query_type,
                is_response=is_response,
                resolved_ips=[ip for ip in resolved if ip],
                response_code=response_code,
            ))

        # --- HTTP (Scapy's http layer, when it recognises the stream) ---
        if HTTP_AVAILABLE and pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            def _dec(v):
                if v is None:
                    return None
                return v.decode(errors="ignore") if isinstance(v, bytes) else str(v)
            capture.http_records.append(HTTPRecord(
                timestamp=ts,
                src_ip=record.src_ip or "unknown",
                dst_ip=record.dst_ip or "unknown",
                method=_dec(req.Method),
                host=_dec(req.Host),
                path=_dec(req.Path),
                user_agent=_dec(getattr(req, "User_Agent", None)),
                content_type=_dec(getattr(req, "Content_Type", None)),
            ))
        elif HTTP_AVAILABLE and pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            def _dec2(v):
                if v is None:
                    return None
                return v.decode(errors="ignore") if isinstance(v, bytes) else str(v)
            capture.http_records.append(HTTPRecord(
                timestamp=ts,
                src_ip=record.src_ip or "unknown",
                dst_ip=record.dst_ip or "unknown",
                status_code=_dec2(getattr(resp, "Status_Code", None)),
                content_type=_dec2(getattr(resp, "Content_Type", None)),
                content_length=int(resp.Content_Length) if getattr(resp, "Content_Length", None) else None,
            ))

        # --- Best-effort file recovery from raw TCP payloads ---
        if Raw in pkt and TCP in pkt:
            payload = bytes(pkt[Raw].load)
            if _looks_like_pe_or_script(payload) and len(payload) > 64:
                capture.files.append(ExtractedFile(
                    src_ip=record.src_ip or "unknown",
                    dst_ip=record.dst_ip or "unknown",
                    filename=None,
                    size=len(payload),
                    data=payload,
                    timestamp=ts,
                ))

    if logger:
        logger.info(f"[+] Parsed {capture.total_packets} packets, "
                     f"{len(capture.dns_records)} DNS records, "
                     f"{len(capture.http_records)} HTTP records, "
                     f"{len(capture.files)} candidate file payload(s)")

    return capture
