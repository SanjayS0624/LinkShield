"""Bounded public-domain DNS and TLS metadata lookups for scan enrichment."""

from datetime import datetime, timezone
from ipaddress import ip_address
import socket
import ssl
from typing import Any

import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from app.detection.network_safety import is_special_use_hostname


DNS_TIMEOUT_SECONDS = 2.0
TLS_TIMEOUT_SECONDS = 2.0


def _public_addresses(host: str) -> list[str]:
    """Resolve a host and reject the entire answer if any address is non-public."""
    try:
        answers = dns.resolver.resolve_name(host, family=socket.AF_UNSPEC,
                                           lifetime=DNS_TIMEOUT_SECONDS, search=False)
        addresses = sorted(set(answers.addresses()))
    except (dns.exception.DNSException, OSError, ValueError):
        return []
    if not addresses:
        return []
    try:
        if any(not ip_address(item).is_global for item in addresses):
            return []
    except ValueError:
        return []
    return addresses


def _certificate(host: str, addresses: list[str]) -> dict[str, Any]:
    # Keep total enrichment time bounded even for hosts with large DNS answer sets.
    for address in addresses[:2]:
        try:
            ip = ip_address(address)
            family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            target = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.socket(family, socket.SOCK_STREAM) as raw:
                raw.settimeout(TLS_TIMEOUT_SECONDS)
                raw.connect(target)
                with context.wrap_socket(raw, server_hostname=host) as secured:
                    cert = x509.load_der_x509_certificate(secured.getpeercert(binary_form=True))
            expiry = cert.not_valid_after_utc.timestamp()
            issuer = cert.issuer.rfc4514_string() or None
            try:
                sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                subject_alt_name_count = len(sans.get_values_for_type(x509.DNSName))
            except x509.ExtensionNotFound:
                subject_alt_name_count = 0
            return {
                "status": "available",
                "issuer": issuer,
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "expires_at": datetime.fromtimestamp(expiry, timezone.utc).isoformat() if expiry else None,
                "days_until_expiry": max(0, int((expiry - datetime.now(timezone.utc).timestamp()) // 86400)) if expiry else None,
                "subject_alt_name_count": subject_alt_name_count,
                "verification": "not_performed",
                "note": "Certificate metadata was collected; trust-chain validation is not part of this phase.",
            }
        except (OSError, ssl.SSLError, ValueError):
            continue
    return {"status": "unavailable", "reason": "No public HTTPS certificate could be retrieved within the timeout."}


def inspect_domain(host: str, is_ip: bool = False) -> dict[str, Any]:
    """Return DNS, certificate, and registration-age status without opening a URL."""
    if is_ip:
        return {
            "dns": {"status": "not_applicable", "addresses": []},
            "certificate": {"status": "not_checked", "reason": "Certificate lookup is only performed for hostnames."},
            "registration": {"status": "unavailable", "reason": "Registration age requires a registered domain name."},
        }

    if is_special_use_hostname(host):
        return {
            "dns": {"status": "blocked", "addresses": [],
                    "reason": "Special-use hostname was not sent to external DNS."},
            "certificate": {"status": "not_checked", "reason": "TLS lookup is skipped for special-use hostnames."},
            "registration": {"status": "unavailable", "reason": "Registration age requires a public registered domain."},
        }

    addresses = _public_addresses(host)
    if addresses:
        dns_result: dict[str, Any] = {"status": "available", "addresses": addresses}
        certificate = _certificate(host, addresses)
    else:
        dns_result = {"status": "unavailable", "addresses": [],
                      "reason": "DNS returned no usable public addresses, or the answer included a local/private address."}
        certificate = {"status": "not_checked", "reason": "TLS lookup is skipped unless all resolved addresses are public."}

    return {
        "dns": dns_result,
        "certificate": certificate,
        "registration": {"status": "unavailable", "reason": "A registration data provider is not configured; domain age was not inferred."},
    }
