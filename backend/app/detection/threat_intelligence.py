"""Optional reputation lookups; requests go only to fixed provider APIs."""

from datetime import datetime, timezone
import base64
import hashlib
import json
import threading
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app.core.config import settings


TIMEOUT_SECONDS = 3.0
CACHE_SECONDS = 600
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()


class ThreatIntelProvider(Protocol):
    name: str

    def lookup(self, url: str) -> dict[str, Any]: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = build_opener(_NoRedirect)


def _request(request: Request) -> tuple[int, dict[str, Any]]:
    try:
        with _opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, json.loads(response.read(1_000_000).decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            return 404, {}
        if exc.code == 429:
            return 429, {}
        raise


class VirusTotalProvider:
    name = "VirusTotal"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, url: str) -> dict[str, Any]:
        if not self.api_key:
            return {"provider": self.name, "status": "unavailable", "reason": "API key not configured."}
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        request = Request(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                          headers={"x-apikey": self.api_key, "Accept": "application/json"})
        code, body = _request(request)
        if code == 404:
            return {"provider": self.name, "status": "not_found", "reason": "No report exists for this URL."}
        if code == 429:
            return {"provider": self.name, "status": "unavailable", "reason": "Provider rate limit reached."}
        stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        result_status = "malicious" if malicious else "suspicious" if suspicious else "no_match"
        return {"provider": self.name, "status": result_status, "malicious_count": malicious,
                "suspicious_count": suspicious, "checked_at": datetime.now(timezone.utc).isoformat()}


class GoogleSafeBrowsingProvider:
    name = "Google Safe Browsing"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, url: str) -> dict[str, Any]:
        if not self.api_key:
            return {"provider": self.name, "status": "unavailable", "reason": "API key not configured."}
        endpoint = "https://safebrowsing.googleapis.com/v5/urls:search?" + urlencode(
            {"key": self.api_key, "urls": url}
        )
        request = Request(endpoint, headers={"Accept": "application/json"})
        code, body = _request(request)
        if code == 429:
            return {"provider": self.name, "status": "unavailable", "reason": "Provider rate limit reached."}
        matches = body.get("threats", [])
        return {"provider": self.name, "status": "malicious" if matches else "no_match",
                "match_count": len(matches),
                "threat_types": sorted({threat_type for match in matches
                                         for threat_type in match.get("threatTypes", [])}),
                "checked_at": datetime.now(timezone.utc).isoformat()}


def _run_provider(provider: ThreatIntelProvider, url: str) -> dict[str, Any]:
    try:
        return provider.lookup(url)
    except Exception:
        return {"provider": provider.name, "status": "unavailable",
                "reason": "Provider lookup failed or timed out."}


def lookup_url(url: str) -> dict[str, Any]:
    """Query enabled providers without letting provider failures fail a scan."""
    providers: list[ThreatIntelProvider] = [
        VirusTotalProvider(settings.virustotal_api_key),
        GoogleSafeBrowsingProvider(settings.google_safe_browsing_api_key),
    ]
    results: list[dict[str, Any]] = []
    for provider in providers:
        key = hashlib.sha256(f"{provider.name}\0{url}".encode("utf-8")).hexdigest()
        with _cache_lock:
            cached = _cache.get(key)
            if cached and cached[0] > time.monotonic():
                results.append(cached[1])
                continue
        result = _run_provider(provider, url)
        if result["status"] != "unavailable":
            with _cache_lock:
                if len(_cache) >= 1000:
                    _cache.clear()
                _cache[key] = (time.monotonic() + CACHE_SECONDS, result)
        results.append(result)

    statuses = {item["status"] for item in results}
    if "malicious" in statuses:
        overall = "match"
    elif "suspicious" in statuses:
        overall = "partial"
    elif statuses == {"no_match"}:
        overall = "no_match"
    elif "no_match" in statuses or "not_found" in statuses:
        overall = "partial"
    else:
        overall = "unavailable"
    return {
        "status": overall,
        "providers": results,
        "note": "Provider results are external signals, not a guarantee. URLs are sent only to providers with configured API keys; stored secret query values are redacted before lookup.",
    }
