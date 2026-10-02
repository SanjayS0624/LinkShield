# LinkShield

LinkShield is a risk assessment platform for suspicious links. Results are based on available signals and do not guarantee that a URL is safe or malicious.

## Phase 1 foundation

The foundation provides a React/Vite frontend, FastAPI backend, PostgreSQL, Redis, and a Celery worker in Docker Compose. The API exposes `/health`, `/health/ready`, and `/api/health` endpoints. Readiness checks PostgreSQL and Redis connectivity. Database migrations run before the API starts.

### Run

1. Copy `.env.example` to `.env` and set a strong `POSTGRES_PASSWORD` and `JWT_SECRET_KEY`. Keep the password in `DATABASE_URL` synchronized with `POSTGRES_PASSWORD`.
2. Run `docker compose up --build`.
3. Open the deployed frontend at <https://mellow-lily-b8c9de.netlify.app/> and check the local API at <http://localhost:8000/health/ready>.

The default local values are for development only. Do not use them in a deployed environment.

## Phase status

| Phase | Status |
| --- | --- |
| 1. Foundation | Running in the user's Docker Desktop environment |
| 2. Authentication | Implemented |
| 3. URL scanner | User verified structural findings in the browser |
| 4. Risk engine | User verified the weighted score and explanation in the browser |
| 5. Domain intelligence | Implemented; DNS and public-host TLS certificate metadata are returned with each scan |
| 6. Brand detection | Implemented; configurable brands, lookalike indicators, and admin API are available |
| 7. Threat intelligence | Implemented with optional VirusTotal and Google Safe Browsing lookups; keys are not configured by default |
| 8. Redirect analysis | Implemented with bounded HEAD-only checks, pinned public IP connections, and private-network blocking |
| 9. Dashboard | Implemented with account-scoped statistics, charts, scan history, filters, and report access |
| 10. AI explanation | Implemented as an optional narrative layer; deterministic score remains authoritative |
| 11. Security hardening | Controls implemented; all 25 backend tests pass; Python dependency audit is clean after a cryptography update; Docker integration check remains |
| 12. Documentation | Complete: architecture, API, security, deployment, detection-engine, and threat-intelligence guides are in `docs/` |

## Documentation

- [Architecture](docs/architecture.md)
- [API reference](docs/api.md)
- [Security model and limitations](docs/security.md)
- [Development deployment](docs/deployment.md)
- [Hosted demo deployment on Netlify and Render](docs/deployment.md#hosted-demo-netlify-frontend--render-api)
- [Detection engine](docs/detection-engine.md)
- [Threat intelligence](docs/threat-intelligence.md)
- [Changelog](CHANGELOG.md)

## Authentication API

- `POST /api/auth/register` creates an active viewer account and returns access and refresh tokens.
- `POST /api/auth/login` authenticates an account and returns a new token pair.
- `POST /api/auth/refresh` rotates a valid refresh token; the previous token is revoked.
- `POST /api/auth/logout` revokes the submitted refresh token.
- `GET /api/auth/me` returns the current user and requires `Authorization: Bearer <access_token>`.

Passwords are bcrypt-hashed. Registration requires at least 12 characters (maximum 72 UTF-8 bytes). Access tokens default to 15 minutes and refresh tokens to 7 days. Self-registration always creates a viewer; privileged roles are not accepted from registration input. Protected route handlers can use `require_roles("admin")`, `require_roles("analyst", "admin")`, or another allowed role set.

## URL scanner API

- `POST /api/scans` accepts `{ "url": "https://example.com/path" }` and returns a completed scan with URL, domain, brand, and configured threat-intelligence results. Unauthenticated requests are allowed; when a bearer token is provided, the scan is associated with that account.
- `GET /api/scans` lists the authenticated user's scans. Admins and analysts can view all scans.
- `GET /api/scans/{scan_id}` returns a scan visible to the caller.
- `DELETE /api/scans/{scan_id}` deletes a scan visible to the caller.

`GET /api/scans` accepts optional `risk_level`, `domain`, `brand`, `date_from`, and `date_to` filters. `GET /api/dashboard/stats` returns account-scoped risk counts, recent scan activity, detected brands, threat categories, and recent scans. Both endpoints require a bearer token; analysts and admins see all scans, while viewers see only their own. The frontend includes sign-in and viewer registration, a dashboard, filtered history, and full report access. Registration passwords must be at least 12 characters.

The URL analyzer parses URLs without rendering or downloading submitted pages. Phase 5 makes DNS queries and a bounded TLS handshake to public addresses; Phase 8 can issue limited HEAD requests to inspect redirect responses. Findings are weighted by the deterministic risk engine, with component impacts and the clamp formula returned in `risk_calculation`. Results are assessments, not proof. For privacy, persisted URL values omit fragments and redact common credential/token query values.

Phase 5 adds bounded DNS and TLS certificate metadata to each scan response as `domain_intelligence`. DNS answers are discarded if any address is not globally routable, and TLS is connected to a resolved public IP with the submitted hostname used only for SNI. Scanned web pages are never requested. Certificate details are descriptive; trust-chain validation is not performed. Domain age is marked unavailable until a registration-data provider is configured, and no age is guessed. These enrichment results do not alter the risk score.

Phase 6 adds `brand_analysis` with textual similarity matches against the built-in Google, Microsoft, Apple, Amazon, PayPal, Instagram, Facebook, Netflix, GitHub, and LinkedIn configurations. Matches check brand aliases, keywords, common character substitutions, and a limited set of Unicode lookalikes. A single strongest brand match contributes +30 to the score; multiple brand matches do not stack. Similarity is a review indicator, not a probability or proof. Official subdomains are excluded when their hostname ends in a configured official domain.

`GET /api/brands` lists the active brand configuration. Admins can use `POST /api/brands`, `PUT /api/brands/{id}`, and `DELETE /api/brands/{id}` to manage brands. Public registration creates viewer accounts only. Assign admin access through a trusted administrative process; do not expose role changes through public registration.

Phase 7 supports optional VirusTotal and Google Safe Browsing providers. Add `VIRUSTOTAL_API_KEY` and/or `GOOGLE_SAFE_BROWSING_API_KEY` to `.env` to enable them; blank keys leave those providers unavailable without interrupting scans. Google Safe Browsing uses the v5 URL lookup API for non-commercial use; commercial applications should use Web Risk. Configured providers receive the normalized stored URL after common secret-bearing query values have been redacted. The frontend discloses this before scanning. Confirmed provider matches contribute +40 once; provider errors, missing keys, and no-report results do not increase risk. Provider results are cached briefly and are evidence, not a verdict. Analysts and admins can query `GET /api/threat-intelligence/{indicator}`.

Phase 8 checks up to four redirect hops using HEAD requests only; it does not download or render response bodies. Only standard HTTP/HTTPS ports are permitted. Each hostname is resolved, all answers must be globally routable, and the connection is pinned to a resolved IP to resist DNS rebinding. Local/private/link-local and metadata addresses are blocked at every hop. Network failures or blocked destinations are recorded as unavailable/blocked enrichment and do not fail the URL scan. Two or more redirects contribute +15; a single cross-host redirect is shown without a score impact.

Phase 10 adds a short, optional OpenAI explanation to each scan. Configure `OPENAI_API_KEY` in `.env` to enable it; `OPENAI_EXPLANATION_MODEL` selects the model. The backend sends only the deterministic score and bounded finding category/severity/title/score-impact labels, with no submitted URL, hostname, query values, or free-form evidence. The model has no tools and cannot change the score or findings. If the key is absent or the request fails, a built-in explanation and safety recommendation are returned instead. Explanations are stored with scan reports; older scans without this field continue to display normally.

## Phase 11 security hardening

Scan submissions use Redis-backed hourly limits: anonymous callers are limited by the hash of their direct client IP (5/hour by default), signed-in viewers and analysts by account (30/hour), and admins by account (300/hour). Set `SCAN_LIMIT_ANONYMOUS_PER_HOUR`, `SCAN_LIMIT_AUTHENTICATED_PER_HOUR`, or `SCAN_LIMIT_ADMIN_PER_HOUR` in `.env` to adjust these limits. The endpoint fails closed with a temporary-unavailable response if Redis cannot enforce the limit. Forwarded client-IP headers are not trusted.

Special-use hostnames such as `.localhost`, `.local`, `.internal`, `.test`, `.invalid`, and `.onion` do not trigger public DNS, TLS, or redirect lookups. Existing redirect checks continue to require public IPs, standard ports, bounded HEAD requests, and IP-pinned connections. API responses use `no-store`; CORS does not allow credentials because authentication uses bearer tokens. These protections reduce exposure but do not make a scan a safety guarantee.

## 🌐 Live Demo

🚀 [Try LinkShield](https://mellow-lily-b8c9de.netlify.app/)
