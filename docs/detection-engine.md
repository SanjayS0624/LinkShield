# Detection engine

The scan pipeline is implemented in `backend/app/detection/` and called synchronously by `POST /api/scans`. A scan is an evidence-based assessment, not a verdict. No single weak heuristic labels a URL malicious.

## URL validation and normalization

`url_analyzer.py` accepts HTTP and HTTPS URLs. A bare hostname is treated as HTTPS. The request is limited to 4096 characters; control characters, malformed hosts, missing hosts, invalid ports, and disallowed schemes are rejected. The host is normalized with IDNA, and a trailing dot and URL fragment are omitted from stored addresses. User information is not retained. Common secret-bearing query keys (for example `token`, `password`, `session`, and `key`) have their values replaced before persistence or provider lookup.

Structural indicators include long URLs/hosts, many host labels, selected high-abuse TLDs, known shorteners, Unicode/punycode, IP-address hosts, unusual ports, repeated encoding, encoded redirect destinations, hyphens, and sensitive-action wording. A fragment is reported but has zero score impact. Encoded data is parsed as text; submitted scripts are never run.

## Domain intelligence

DNS answers are discarded if empty, invalid, or if any address is not globally routable. TLS metadata is requested only after public DNS validation, using a direct connection to a validated address and the hostname for SNI. The TLS socket has a short timeout. The code records certificate metadata without validating a trust chain. Domain registration age remains unavailable because no registration provider is configured.

Special-use suffixes (including `.localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`, `.test`, `.invalid`, `.example`, and `.onion`) are not sent to public DNS or TLS checks.

## Brand matching

The database is seeded with Google, Microsoft, Apple, Amazon, PayPal, Instagram, Facebook, Netflix, GitHub, and LinkedIn. Matching checks configured names, aliases, keywords, hostname labels, common character substitutions, and a limited set of Unicode/punycode lookalikes. Official domains and their subdomains are excluded. Results include matched text and a label-similarity value; this value is not a probability. At most five matches are returned, but only the strongest match contributes to score.

## Threat-intelligence providers

VirusTotal and Google Safe Browsing are optional. A missing key, timeout, or provider error produces an unavailable result without failing the scan. Confirmed malicious matches are recorded as evidence. Provider lookups receive the normalized stored URL after common sensitive query values are redacted. See [threat intelligence](threat-intelligence.md) for status meanings and configuration.

## Redirect inspection

Redirect analysis makes HEAD requests only. It follows at most four hops, uses short per-connection timeouts, disables automatic HTTP-library redirect following, and does not download response bodies. Only HTTP/HTTPS and standard ports are allowed. Every hop is resolved independently; all returned addresses must be public and the connection is pinned to a validated IP. Private, loopback, link-local, reserved, and metadata targets are blocked. Redirect chains expose hostnames and status codes, not full destination paths or query values.

## Risk calculation

Each finding has a fixed score impact in `risk_engine.py`. Current positive weights include:

| Signal | Points |
| --- | ---: |
| Confirmed threat-intelligence match | +40 |
| Strongest configured brand lookalike | +30 |
| Embedded credentials or IP-address hostname | +20 |
| Encoded redirect destination or multiple redirects | +15 |
| Sensitive-action wording or selected suspicious TLD | +10 |
| Long URL/hostname, many labels, known shortener, non-standard port, several hyphens, malformed/repeated encoding | +5 each |
| URL fragment | 0 |
| HTTPS transport observed | −5 |

The raw sum is clamped to 0–100. Bands are LOW 0–29, MEDIUM 30–59, HIGH 60–79, and CRITICAL 80–100. The API returns the component titles, impacts, raw total, formula, and final score. HTTPS is only a small transport offset; it does not establish trust.

The AI explanation is optional and runs after scoring. It receives the score and bounded finding labels, not the submitted URL, hostname, query values, or free-form evidence. The deterministic score remains authoritative. A built-in explanation is used when AI is not configured or unavailable.

## Testing

Backend regression tests are in `backend/tests/`. They cover URL parsing, score behavior, authentication, account scoping, role protection, reserved-host network blocking, private redirect blocking, headers, and scan throttling. Run them with `python -m pytest tests -q` from `backend/` after installing `requirements-dev.txt`.
