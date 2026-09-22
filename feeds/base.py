"""Shared plumbing for threat-intel feed clients: JSON disk caching and
a uniform result object."""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("tia")


@dataclass
class FeedResult:
    feed: str
    indicator: str
    available: bool           # False = feed unreachable / errored, not "clean"
    matched: bool = False     # True = feed returned reputation data worth reporting
    confidence: str = "N/A"   # Low / Medium / High / N/A
    summary: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    from_cache: bool = False


class BaseFeedClient:
    """Base class handling caching and the connect/timeout error path.
    Subclasses implement _query() and return a FeedResult."""

    name = "base"
    timeout_seconds = 10

    def __init__(self, api_key: Optional[str], cache_dir: str = "cache"):
        self.api_key = api_key
        self.cache_dir = os.path.join(cache_dir, self.name.lower())
        os.makedirs(self.cache_dir, exist_ok=True)

    def _cache_path(self, indicator: str) -> str:
        digest = hashlib.sha256(indicator.encode()).hexdigest()[:24]
        return os.path.join(self.cache_dir, f"{digest}.json")

    def _load_cache(self, indicator: str) -> Optional[dict]:
        path = self._cache_path(indicator)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                return None
        return None

    def _save_cache(self, indicator: str, data: dict) -> None:
        try:
            with open(self._cache_path(indicator), "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as exc:  # caching is best-effort, never fatal
            logger.debug(f"Could not write cache for {self.name}: {exc}")

    def query(self, indicator: str, ioc_type: str) -> FeedResult:
        cached = self._load_cache(indicator)
        if cached is not None:
            logger.info(f"[+] Cache hit: {self.name} <- {indicator}")
            result = FeedResult(**cached)
            result.from_cache = True
            return result

        if not self.api_key:
            return FeedResult(feed=self.name, indicator=indicator, available=False,
                               summary=f"{self.name} API key not configured.")

        logger.info(f"[+] Querying threat intelligence feed: {self.name} <- {indicator}")
        try:
            result = self._query(indicator, ioc_type)
        except Exception as exc:
            logger.warning(f"[-] {self.name} lookup failed for {indicator}: {exc}")
            return FeedResult(feed=self.name, indicator=indicator, available=False,
                               summary="Threat intelligence lookup unavailable.")

        self._save_cache(indicator, result.__dict__)
        return result

    def _query(self, indicator: str, ioc_type: str) -> FeedResult:
        raise NotImplementedError
