"""Pulls a de-duplicated set of indicators of compromise (IPs, domains,
URLs, file hashes) out of a ParsedCapture.

Every IOC returned here is something that was actually observed in the
capture — nothing is guessed or added for effect.
"""

from dataclasses import dataclass
from typing import List, Set

from analyzer.pcap_parser import ParsedCapture
from utils.hashing import hashes_for
from utils.networking import is_useful_ip


@dataclass(frozen=True)
class IOC:
    indicator: str
    type: str  # ipv4 | ipv6 | domain | url | md5 | sha1 | sha256

    def to_dict(self):
        return {"indicator": self.indicator, "type": self.type}


def extract_iocs(capture: ParsedCapture) -> List[IOC]:
    iocs: Set[IOC] = set()

    # IPs from raw packet metadata, filtered to routable/public addresses.
    for pkt in capture.packets:
        for ip in (pkt.src_ip, pkt.dst_ip):
            if ip and is_useful_ip(ip):
                ip_type = "ipv6" if ":" in ip else "ipv4"
                iocs.add(IOC(ip, ip_type))

    # Domains (and resolved IPs) from DNS traffic.
    for rec in capture.dns_records:
        if rec.query:
            iocs.add(IOC(rec.query, "domain"))
        for resolved in rec.resolved_ips:
            if is_useful_ip(resolved):
                ip_type = "ipv6" if ":" in resolved else "ipv4"
                iocs.add(IOC(resolved, ip_type))

    # URLs and hosts from HTTP traffic.
    for rec in capture.http_records:
        if rec.host and rec.path and rec.method:
            url = f"http://{rec.host}{rec.path}"
            iocs.add(IOC(url, "url"))
        if rec.host:
            # Host header alone is still a useful domain-level indicator.
            host_only = rec.host.split(":")[0]
            if not is_useful_ip(host_only):
                iocs.add(IOC(host_only, "domain"))

    # Hashes of any recovered file payloads.
    for f in capture.files:
        digests = hashes_for(f.data)
        iocs.add(IOC(digests["md5"], "md5"))
        iocs.add(IOC(digests["sha1"], "sha1"))
        iocs.add(IOC(digests["sha256"], "sha256"))

    return sorted(iocs, key=lambda i: (i.type, i.indicator))
