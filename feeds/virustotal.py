"""VirusTotal client — IPs, domains, URLs and file hashes."""

import base64

import requests

from feeds.base import BaseFeedClient, FeedResult

ENDPOINTS = {
    "ipv4": "https://www.virustotal.com/api/v3/ip_addresses/{}",
    "ipv6": "https://www.virustotal.com/api/v3/ip_addresses/{}",
    "domain": "https://www.virustotal.com/api/v3/domains/{}",
    "url": "https://www.virustotal.com/api/v3/urls/{}",
    "md5": "https://www.virustotal.com/api/v3/files/{}",
    "sha1": "https://www.virustotal.com/api/v3/files/{}",
    "sha256": "https://www.virustotal.com/api/v3/files/{}",
}


class VirusTotalClient(BaseFeedClient):
    name = "VirusTotal"

    def _query(self, indicator: str, ioc_type: str) -> FeedResult:
        template = ENDPOINTS.get(ioc_type)
        if not template:
            return FeedResult(feed=self.name, indicator=indicator, available=True,
                               matched=False, summary="Indicator type not applicable to VirusTotal.")

        lookup_value = indicator
        if ioc_type == "url":
            # VT identifies URLs by the base64 (no padding) of the URL string.
            lookup_value = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")

        resp = requests.get(
            template.format(lookup_value),
            headers={"x-apikey": self.api_key},
            timeout=self.timeout_seconds,
        )
        if resp.status_code == 404:
            return FeedResult(feed=self.name, indicator=indicator, available=True,
                               matched=False, confidence="Low",
                               summary="No VirusTotal record found for this indicator.")
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        confidence = "High" if malicious >= 5 else "Medium" if malicious >= 1 else "Low"

        return FeedResult(
            feed=self.name,
            indicator=indicator,
            available=True,
            matched=malicious > 0 or suspicious > 0,
            confidence=confidence,
            summary=(f"{malicious}/{total} security vendors flagged this indicator as "
                     f"malicious, {suspicious} as suspicious."),
            raw={"last_analysis_stats": stats, "reputation": attrs.get("reputation")},
        )
