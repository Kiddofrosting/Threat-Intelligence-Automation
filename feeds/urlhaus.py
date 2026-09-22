"""URLhaus client — malicious URLs and related malware-distribution
infrastructure. URLhaus's public API does not require a key for basic
lookups, but we still allow an auth key (URLHAUS_AUTH_KEY) for the
higher rate-limit tier."""

import requests

from feeds.base import BaseFeedClient, FeedResult


class URLhausClient(BaseFeedClient):
    name = "URLhaus"
    url_lookup = "https://urlhaus-api.abuse.ch/v1/url/"
    host_lookup = "https://urlhaus-api.abuse.ch/v1/host/"

    def query(self, indicator: str, ioc_type: str) -> FeedResult:
        # URLhaus doesn't require an API key for read lookups, so we
        # bypass the base class's "no key -> unavailable" short-circuit.
        cached = self._load_cache(indicator)
        if cached is not None:
            import logging
            logging.getLogger("tia").info(f"[+] Cache hit: {self.name} <- {indicator}")
            result = FeedResult(**cached)
            result.from_cache = True
            return result
        try:
            result = self._query(indicator, ioc_type)
        except Exception as exc:
            import logging
            logging.getLogger("tia").warning(f"[-] {self.name} lookup failed for {indicator}: {exc}")
            return FeedResult(feed=self.name, indicator=indicator, available=False,
                               summary="Threat intelligence lookup unavailable.")
        self._save_cache(indicator, result.__dict__)
        return result

    def _query(self, indicator: str, ioc_type: str) -> FeedResult:
        headers = {"Auth-Key": self.api_key} if self.api_key else {}

        if ioc_type == "url":
            resp = requests.post(self.url_lookup, data={"url": indicator},
                                  headers=headers, timeout=self.timeout_seconds)
        elif ioc_type in ("domain", "ipv4", "ipv6"):
            resp = requests.post(self.host_lookup, data={"host": indicator},
                                  headers=headers, timeout=self.timeout_seconds)
        else:
            return FeedResult(feed=self.name, indicator=indicator, available=True,
                               matched=False, summary="Indicator type not applicable to URLhaus.")

        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")

        if status != "ok":
            return FeedResult(feed=self.name, indicator=indicator, available=True,
                               matched=False, confidence="Low",
                               summary="No URLhaus record found for this indicator.")

        urls = data.get("urls", [data]) if "urls" in data else [data]
        threat_types = sorted({u.get("threat", "unknown") for u in urls if u.get("threat")})
        # Most-recent entry drives status/recency -- URLhaus returns
        # newest-first, but sort defensively on date_added just in case.
        dated = sorted(urls, key=lambda u: u.get("date_added") or "", reverse=True)
        newest = dated[0] if dated else {}

        return FeedResult(
            feed=self.name,
            indicator=indicator,
            available=True,
            matched=True,
            confidence="High",
            summary=(f"URLhaus lists this indicator as associated with malware "
                     f"distribution ({', '.join(threat_types) or 'type unspecified'})."),
            raw={
                "threat_types": threat_types,
                "url_count": len(urls),
                "url_status": newest.get("url_status"),
                "date_added": newest.get("date_added") or data.get("firstseen"),
                "tags": newest.get("tags", []),
            },
        )
