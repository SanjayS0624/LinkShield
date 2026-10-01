# Security model and limitations

LinkShield handles untrusted URLs and account credentials. Its outputs are risk assessments from available signals and never guarantee a link is safe or malicious.

## URL-fetching and SSRF controls

- Submitted pages are never rendered, downloaded, or executed. Structural parsing itself makes no network request.
- Domain intelligence performs bounded DNS resolution. TLS metadata is requested only if all resolved addresses are globally routable; it connects to a validated address and uses the host only for SNI. Certificate chain verification is not implemented for this metadata feature, so certificate results are observational.
- Special-use hostnames (`localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`, `.test`, `.invalid`, `.example`, `.onion`) are not sent to public DNS/TLS lookups.
- Redirect inspection uses HEAD only, at most four hops, standard HTTP/HTTPS ports, short timeouts, and no automatic redirect behavior. Each hop is resolved and every answer must be public; connections are pinned to validated IPs. Private, loopback, link-local, reserved, and metadata destinations are rejected.
- Threat-intelligence calls go only to fixed provider endpoints. They are not made when keys are unset. Submitted secret query values are redacted before provider lookup.

These guards reduce SSRF exposure but are not a substitute for network egress controls in a deployed environment. Run the application with outbound access restricted to required providers and DNS where practical.

## Authentication and authorization

- Passwords are bcrypt-hashed; plaintext passwords are not stored.
- JWT algorithms are restricted to HS256. Access tokens carry subject, role, type, issue/expiry times, and a unique token ID. Default lifetime is 15 minutes. Refresh tokens have a separate type and ID, are stored in `refresh_sessions`, rotate on refresh, and are revoked on logout; default lifetime is 7 days.
- Registration always creates an active viewer. There is no public role-change or user-administration endpoint. Assigning an admin role requires a separate trusted operational process.
- Viewers can access only their own history and scans. Analyst/admin roles can access account-wide history. Brand writes require admin. Threat-intelligence inspection requires analyst/admin.
- Private endpoints use bearer headers. CORS credentials are disabled; allowed browser origins come from `CORS_ORIGINS`.

## Rate limits

`POST /api/scans` uses a Redis Lua counter with an hourly expiry. Defaults are 5 scans per direct client IP for anonymous users, 30 per user account for viewers/analysts, and 300 per admin. Limits are configurable with `SCAN_LIMIT_ANONYMOUS_PER_HOUR`, `SCAN_LIMIT_AUTHENTICATED_PER_HOUR`, and `SCAN_LIMIT_ADMIN_PER_HOUR`. `X-Forwarded-For` is not trusted. If Redis is unavailable, scan creation returns 503 rather than bypassing the quota.

## HTTP protections and data handling

Responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a restrictive `Permissions-Policy`. API and health responses use `Cache-Control: no-store` and `Cross-Origin-Resource-Policy: same-origin`.

Stored URLs omit fragments and user information; common secret-bearing query parameter values are redacted. Threat providers receive the redacted URL only when configured. The optional AI explainer receives the deterministic score and bounded finding labels only; it does not receive URLs, hostnames, query values, or free-form evidence. The AI has no tools and cannot set or alter a score.

Do not commit `.env` or share API keys. Local sample credentials/secrets are for development only. Production deployments need strong secrets, TLS termination, restricted database/network access, backups, monitoring, and an operational key-rotation process.

## Known gaps

- Audit-log storage and an audit-log API are not implemented.
- There is no built-in admin bootstrap/user-management flow.
- Access tokens are short-lived but do not have a server-side revocation list; logout revokes the refresh token, not an already issued access token.
- Registration/provider lookup throttling beyond scan submissions is not implemented.
- The API scan route performs its enrichment synchronously; Celery is present but is not used for scans.
- Python dependency ranges are not locked to exact versions. A `pip-audit` run on 2026-09-29 found cryptography advisories, which were addressed by requiring cryptography 50.x; the follow-up audit reported no known vulnerabilities. Re-run audits regularly because dependency and advisory data changes. The frontend dependency audit was not run in this session.
- No deployment-specific threat model, penetration test, certificate trust validation, or egress firewall is included.

## Security regression checks

`backend/tests/test_security_phase11.py` covers role escalation resistance, viewer write denial, invalid bearer rejection, API security headers, special-use DNS blocking, private-IP redirect blocking, URL input boundaries, and anonymous scan limits. Run the backend suite from `backend/` with `python -m pytest tests -q`.
