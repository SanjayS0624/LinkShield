"""Pure URL parsing and structural analysis. This module never makes network requests."""

from dataclasses import dataclass
from ipaddress import ip_address
import re
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


MAX_URL_LENGTH = 4096
SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "mov", "work", "support", "country", "gq", "tk", "ml"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.su", "rb.gy", "ow.ly"}
SUSPICIOUS_TERMS = {"login", "signin", "verify", "verification", "secure", "account", "password", "wallet", "payment", "invoice", "unlock", "update"}
SENSITIVE_QUERY_KEYS = {"token", "accesstoken", "auth", "authorization", "password", "passwd", "secret", "session", "sessionid", "code", "apikey", "key"}
BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


class URLValidationError(ValueError):
    pass


@dataclass(frozen=True)
class AnalyzedURL:
    normalized_url: str
    storage_url: str
    domain: str
    findings: list[dict]


def _finding(category: str, severity: str, title: str, description: str, evidence: str) -> dict:
    return {"category": category, "severity": severity, "title": title,
            "description": description, "evidence": evidence}


def _normalize_host(host: str) -> tuple[str, bool, bool]:
    unicode_host = any(ord(char) > 127 for char in host)
    bare_host = host.rstrip(".")
    try:
        parsed_ip = ip_address(bare_host)
        return parsed_ip.compressed.lower(), True, unicode_host
    except ValueError:
        pass
    try:
        ascii_host = bare_host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise URLValidationError("The hostname cannot be converted to a valid IDN hostname") from exc
    if len(ascii_host) > 253 or not ascii_host:
        raise URLValidationError("The hostname is invalid or too long")
    labels = ascii_host.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or
           not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        raise URLValidationError("The hostname contains an invalid label")
    if len(labels) < 2 and ascii_host != "localhost":
        raise URLValidationError("Enter a fully qualified hostname")
    return ascii_host, False, unicode_host


def _redact_query(query: str) -> str:
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    redacted = []
    for key, value in pairs:
        normalized_key = re.sub(r"[^a-z0-9]", "", key.casefold())
        sensitive = normalized_key in SENSITIVE_QUERY_KEYS or normalized_key.endswith(
            ("token", "password", "passwd", "secret", "session", "apikey")
        )
        redacted.append((key, "[REDACTED]" if sensitive else value))
    return urlencode(redacted, doseq=True)


def analyze_url(value: str) -> AnalyzedURL:
    raw = value.strip()
    if not raw:
        raise URLValidationError("Enter a URL to analyze")
    if len(raw) > MAX_URL_LENGTH:
        raise URLValidationError(f"URL must be {MAX_URL_LENGTH} characters or fewer")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise URLValidationError("URL contains control characters")
    if BAD_PERCENT_ESCAPE.search(raw):
        # Preserve malformed escapes as evidence; URL parsing itself does not execute or dereference them.
        malformed_encoding = True
    else:
        malformed_encoding = False

    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", raw)
    if scheme_match and scheme_match.group(1).lower() not in {"http", "https"} and (
        scheme_match.group(1).lower() in {"javascript", "data", "file", "ftp"} or
        raw[scheme_match.end():].startswith("//")
    ):
        raise URLValidationError("Only HTTP and HTTPS URLs can be analyzed")
    candidate = raw if scheme_match and scheme_match.group(1).lower() in {"http", "https"} else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise URLValidationError("Only HTTP and HTTPS URLs can be analyzed")
        host = parsed.hostname
        if not host:
            raise URLValidationError("URL must include a hostname")
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("URL is malformed") from exc

    domain, is_ip, unicode_host = _normalize_host(host)
    has_credentials = parsed.username is not None or parsed.password is not None
    if ":" in domain:
        netloc = f"[{domain}]"
    else:
        netloc = domain
    if port is not None and not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
        netloc = f"{netloc}:{port}"
    path_source = BAD_PERCENT_ESCAPE.sub("%25", parsed.path or "/")
    path = quote(path_source, safe="/%:@!$&'()*+,;=-._~")
    query_source = BAD_PERCENT_ESCAPE.sub("%25", parsed.query)
    normalized_query = quote(query_source, safe="/%?@!$&'()*+,;=:-._~%[]")
    normalized_url = urlunsplit((scheme, netloc, path, normalized_query, ""))
    storage_url = urlunsplit((scheme, netloc, path, _redact_query(normalized_query), ""))

    findings: list[dict] = []
    if len(raw) > 200:
        findings.append(_finding("URL_STRUCTURE", "MEDIUM", "Unusually long URL",
                                 "Long URLs can obscure their destination or carry complex parameters.", f"URL length: {len(raw)} characters"))
    if has_credentials:
        findings.append(_finding("URL_STRUCTURE", "HIGH", "Credentials embedded in URL",
                                 "The URL contains a username or password before the hostname.", "User information component is present; it is omitted from the normalized URL."))
    if is_ip:
        findings.append(_finding("DOMAIN", "MEDIUM", "IP address used as hostname",
                                 "The link points to a numeric IP address instead of a registered hostname.", f"Host: {domain}"))
    labels = domain.split(".") if not is_ip else []
    if not is_ip and len(domain) > 100:
        findings.append(_finding("DOMAIN", "LOW", "Long hostname",
                                 "Long hostnames can make the registered domain harder to inspect.", f"Hostname length: {len(domain)} characters"))
    if len(labels) > 3:
        findings.append(_finding("DOMAIN", "LOW", "Many hostname labels",
                                 "The hostname has several subdomain levels; this can make its registered domain harder to spot.", f"Hostname label count: {len(labels)}"))
    if labels and labels[-1] in SUSPICIOUS_TLDS:
        findings.append(_finding("DOMAIN", "LOW", "TLD often seen in abuse reports",
                                 "This top-level domain is sometimes used in abusive campaigns and is not proof of malicious activity.", f"TLD: .{labels[-1]}"))
    if labels and domain in SHORTENERS:
        findings.append(_finding("URL_STRUCTURE", "LOW", "Known link-shortening domain",
                                 "Shortened links hide their eventual destination. This scan does not follow redirects.", f"Shortener: {domain}"))
    if unicode_host or any(label.startswith("xn--") for label in labels):
        findings.append(_finding("URL_STRUCTURE", "MEDIUM", "Internationalized hostname",
                                 "The hostname uses Unicode or punycode. Similar-looking characters can be difficult to distinguish.", f"ASCII hostname: {domain}"))
    if malformed_encoding:
        findings.append(_finding("URL_STRUCTURE", "LOW", "Malformed percent encoding",
                                 "The URL contains percent signs that are not followed by two hexadecimal digits.", "Malformed percent escape detected."))
    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    if encoded_count >= 4:
        findings.append(_finding("URL_STRUCTURE", "LOW", "Repeated percent encoding",
                                 "Several percent-encoded characters may make parts of the URL harder to read.", f"Encoded octets: {encoded_count}"))
    if port is not None and port not in {80, 443}:
        findings.append(_finding("URL_STRUCTURE", "LOW", "Non-standard port",
                                 "The URL specifies a port other than the usual HTTP or HTTPS port.", f"Port: {port}"))
    if domain.count("-") >= 3:
        findings.append(_finding("DOMAIN", "LOW", "Several hyphens in hostname",
                                 "Multiple hyphens can make a hostname harder to read; this is a weak signal by itself.", f"Hyphen count: {domain.count('-')}"))
    target_text = f"{parsed.path}?{parsed.query}".casefold()
    redirect_keys = {"url", "redirect", "redirect_url", "next", "continue", "return", "return_to", "dest", "destination"}
    redirect_params = [key for key, value in parse_qsl(parsed.query, keep_blank_values=True)
                       if key.casefold() in redirect_keys and re.search(r"https?%3a|https?://", value, re.IGNORECASE)]
    if redirect_params:
        findings.append(_finding("URL_STRUCTURE", "MEDIUM", "Encoded redirect destination",
                                 "A query parameter appears to contain another web address. The destination is not followed.",
                                 "Redirect-like parameter names: " + ", ".join(sorted(set(redirect_params)))))
    matched_terms = sorted(term for term in SUSPICIOUS_TERMS if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", target_text))
    if matched_terms:
        findings.append(_finding("URL_STRUCTURE", "LOW", "Sensitive-action wording in URL",
                                 "The path or query includes wording commonly used in sign-in or account prompts; context matters.",
                                 "Matched terms: " + ", ".join(matched_terms)))
    if parsed.fragment:
        findings.append(_finding("URL_STRUCTURE", "INFO", "URL fragment present",
                                 "The URL has a fragment that may affect client-side navigation. It is omitted from the normalized URL.", "Fragment present."))

    return AnalyzedURL(normalized_url=normalized_url, storage_url=storage_url, domain=domain, findings=findings)
