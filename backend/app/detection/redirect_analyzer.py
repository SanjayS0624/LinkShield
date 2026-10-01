"""Bounded HEAD-only redirect checks with DNS-pinned public-address connections."""

import http.client
from ipaddress import ip_address
import socket
import ssl
from typing import Any
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver

from app.detection.url_analyzer import URLValidationError, analyze_url
from app.detection.network_safety import is_special_use_hostname


MAX_REDIRECTS = 4
REQUEST_TIMEOUT_SECONDS = 2.0
REDIRECT_CODES = {301, 302, 303, 307, 308}
USER_AGENT = "LinkShield-Redirect-Check/1.0"


class UnsafeTarget(ValueError):
    pass


def _resolve_public(host: str) -> list[str]:
    if is_special_use_hostname(host):
        return []
    try:
        try:
            parsed_ip = ip_address(host)
            addresses = [parsed_ip.compressed]
        except ValueError:
            answer = dns.resolver.resolve_name(host, family=socket.AF_UNSPEC,
                                               lifetime=REQUEST_TIMEOUT_SECONDS, search=False)
            addresses = sorted(set(answer.addresses()))
    except (dns.exception.DNSException, OSError, ValueError):
        return []
    try:
        if not addresses or any(not ip_address(item).is_global for item in addresses):
            return []
    except ValueError:
        return []
    return addresses


def _connect_pinned(host: str, port: int) -> socket.socket:
    """Resolve, check, and connect to one exact public IP to resist DNS rebinding."""
    addresses = _resolve_public(host)
    if not addresses:
        raise UnsafeTarget("Host has no usable globally routable address.")
    for address in addresses[:2]:
        ip = ip_address(address)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        target = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(REQUEST_TIMEOUT_SECONDS)
        try:
            sock.connect(target)
            return sock
        except OSError:
            sock.close()
    raise OSError("Could not connect to the resolved public host.")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = _connect_pinned(self.host, self.port)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        raw = _connect_pinned(self.host, self.port)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _head(url: str) -> tuple[int, str | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UnsafeTarget("Only HTTP and HTTPS redirect targets are allowed.")
    port = parsed.port or (443 if scheme == "https" else 80)
    if port != (443 if scheme == "https" else 80):
        raise UnsafeTarget("Only standard HTTP and HTTPS ports are checked.")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTarget("Redirect targets containing user information are not followed.")

    if scheme == "https":
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
            parsed.hostname or "", port, timeout=REQUEST_TIMEOUT_SECONDS,
            context=ssl.create_default_context())
    else:
        conn = _PinnedHTTPConnection(parsed.hostname or "", port, timeout=REQUEST_TIMEOUT_SECONDS)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        conn.request("HEAD", path, headers={"User-Agent": USER_AGENT,
                                            "Accept": "*/*",
                                            "Accept-Encoding": "identity",
                                            "Connection": "close"})
        response = conn.getresponse()
        return response.status, response.getheader("Location")
    finally:
        conn.close()


def inspect_redirects(url: str) -> dict[str, Any]:
    """Inspect at most four redirect hops; returns sanitized host-only chain evidence."""
    try:
        initial = analyze_url(url)
    except URLValidationError:
        return {"status": "unavailable", "redirect_count": 0, "chain": [],
                "reason": "The starting URL could not be normalized for redirect inspection."}

    current = initial.storage_url
    current_host = initial.domain
    seen = {current}
    visited_hosts = [current_host]
    chain: list[dict[str, Any]] = []
    redirect_count = 0

    while True:
        try:
            status_code, location = _head(current)
        except UnsafeTarget as exc:
            return {"status": "blocked", "redirect_count": redirect_count, "chain": chain,
                    "final_domain": current_host, "reason": str(exc)}
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
            return {"status": "unavailable", "redirect_count": redirect_count, "chain": chain,
                    "final_domain": current_host, "reason": "A bounded HEAD request failed or timed out."}

        if status_code not in REDIRECT_CODES or not location:
            chain.append({"domain": current_host, "status_code": status_code})
            return {"status": "complete", "redirect_count": redirect_count, "chain": chain,
                    "final_domain": current_host,
                    "domain_changed": len(set(visited_hosts)) > 1,
                    "domains": list(dict.fromkeys(visited_hosts))}
        if redirect_count >= MAX_REDIRECTS:
            chain.append({"domain": current_host, "status_code": status_code})
            return {"status": "limit_reached", "redirect_count": redirect_count, "chain": chain,
                    "final_domain": current_host, "reason": f"Stopped at the limit of {MAX_REDIRECTS} redirects."}

        try:
            target = analyze_url(urljoin(current, location))
        except (URLValidationError, ValueError):
            chain.append({"domain": current_host, "status_code": status_code})
            return {"status": "blocked", "redirect_count": redirect_count, "chain": chain,
                    "final_domain": current_host, "reason": "Redirect target was malformed or used a disallowed scheme."}
        if any(item["title"] == "Credentials embedded in URL" for item in target.findings):
            chain.append({"domain": current_host, "status_code": status_code})
            return {"status": "blocked", "redirect_count": redirect_count, "chain": chain,
                    "final_domain": current_host, "reason": "Redirect target contains user information."}
        target_parts = urlsplit(target.storage_url)
        target_port = target_parts.port or (443 if target_parts.scheme == "https" else 80)
        expected_port = 443 if target_parts.scheme == "https" else 80
        if target_port != expected_port:
            chain.append({"domain": current_host, "status_code": status_code})
            return {"status": "blocked", "redirect_count": redirect_count, "chain": chain,
                    "final_domain": current_host, "reason": "Redirect target uses a non-standard port."}

        chain.append({"domain": current_host, "status_code": status_code, "redirect_to": target.domain})
        redirect_count += 1
        current = target.storage_url
        current_host = target.domain
        visited_hosts.append(current_host)
        if current in seen:
            return {"status": "loop_detected", "redirect_count": redirect_count, "chain": chain,
                    "final_domain": current_host, "reason": "A redirect loop was detected."}
        seen.add(current)
