"""AbuseIPDB client — IP reputation only."""

import requests

from feeds.base import BaseFeedClient, FeedResult


class AbuseIPDBClient(BaseFeedClient):
    name = "AbuseIPDB"
    url = "https://api.abuseipdb.com/api/v2/check"

    def _query(self, indicator: str, ioc_type: str) -> FeedResult:
        if ioc_type not in ("ipv4", "ipv6"):
            return FeedResult(feed=self.name, indicator=indicator, available=True,
                               matched=False, summary="Indicator type not applicable to AbuseIPDB.")

        resp = requests.get(
            self.url,
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": indicator, "maxAgeInDays": 90},
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        confidence = "High" if score >= 75 else "Medium" if score >= 25 else "Low"

        return FeedResult(
            feed=self.name,
            indicator=indicator,
            available=True,
            matched=score > 0 or reports > 0,
            confidence=confidence,
            summary=(f"Abuse confidence score {score}/100 from {reports} report(s). "
                     f"Country: {data.get('countryCode', 'N/A')}, "
                     f"ISP: {data.get('isp', 'N/A')}. "
                     f"Last reported: {data.get('lastReportedAt', 'never')}."),
            raw={"abuseConfidenceScore": score, "totalReports": reports,
                 "countryCode": data.get("countryCode"), "isp": data.get("isp"),
                 "lastReportedAt": data.get("lastReportedAt")},
        )
