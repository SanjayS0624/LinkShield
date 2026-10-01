# Threat intelligence

LinkShield has optional fixed-endpoint adapters for VirusTotal and Google Safe Browsing in `backend/app/detection/threat_intelligence.py`. A provider is constructed from its environment key. Blank keys produce an `unavailable` provider result; they do not disable URL analysis or fail the scan.

## Provider behavior

| Provider | Configuration | Main statuses |
| --- | --- | --- |
| VirusTotal URL report | `VIRUSTOTAL_API_KEY` | `malicious`, `suspicious`, `no_match`, `not_found`, `unavailable` |
| Google Safe Browsing v5 URL lookup | `GOOGLE_SAFE_BROWSING_API_KEY` | `malicious`, `no_match`, `unavailable` |

Each provider call uses a 3-second timeout. Redirect following is disabled. A provider failure, rate-limit response, or missing key is represented as unavailable and does not add risk. A confirmed malicious result creates a threat-intelligence finding and contributes +40 once, even when both services report it. Suspicious, not-found, no-match, and unavailable responses do not add risk.

The aggregate result is `match` if any provider reports malicious, `partial` when some evidence exists but not all providers have a clean no-match, `no_match` when all providers report no match, and `unavailable` when neither provider returns a usable report. Individual provider results and timestamps are retained in the scan report.

## Privacy and caching

Provider requests are made only to the provider endpoints in the application code. They receive the normalized persisted URL; common secret-bearing query values are redacted first. The frontend warns that configured providers may receive this redacted URL. Do not put personal or confidential information in a scanned URL.

Google lookups use the Safe Browsing v5 `urls.search` endpoint. Google's Safe Browsing API is for non-commercial use; use Google Web Risk for commercial URL detection.

Usable responses are cached in process memory for ten minutes, keyed by provider and redacted URL. The cache is not shared between backend replicas and is cleared when it reaches its in-process size limit. Unavailable responses are not cached. Provider quotas, terms, privacy policies, and key-management obligations remain the operator’s responsibility.

## API and score semantics

Scan responses expose a `threat_intelligence` object containing an aggregate status, per-provider results, and an explanatory note. Analysts and admins can call `GET /api/threat-intelligence/{indicator}`. Public provider matches are external evidence, not a guarantee or a standalone verdict. The score does not infer maliciousness from a missing report, provider error, or absent API key.

The optional OpenAI explanation service is separate from threat-intelligence providers. It receives the deterministic score and bounded finding labels only and cannot alter provider evidence or the score.

## Current limits

Only VirusTotal and Google Safe Browsing are implemented. URLhaus, PhishTank, and URLScan are not currently integrated. Provider results are checked synchronously during a scan, not by a background job. No provider key is required for local development.
