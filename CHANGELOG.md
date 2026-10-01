# Changelog

## Phase 1 — Foundation

- Added Docker Compose services for frontend, FastAPI backend, PostgreSQL, Redis, and Celery worker.
- Added backend configuration and database/cache readiness endpoints.
- Added a minimal LinkShield frontend shell and environment examples.
- Docker startup and live health checks could not be run because Docker is not installed or available in this environment.

## Phase 2 — Authentication

- Added bcrypt password hashing, short-lived signed access tokens, rotating refresh tokens, logout revocation, and authenticated identity lookup.
- Added viewer-only self-registration, role dependency helpers for future protected routes, and the initial users/refresh-sessions migration.
- Added security response headers and required JWT secret configuration.
- Added focused pytest coverage for registration, login, refresh rotation, logout revocation, `/me`, and role enforcement. Tests could not run because Python dependencies (including pytest) are not installed here.

## Phase 3 — URL scanner

- Added URL validation, normalization, IDN/IP recognition, and structural indicators without fetching submitted links.
- Added scan and finding persistence plus authenticated, owner-scoped scan history and deletion; unauthenticated users may submit a scan.
- Added UI submission and explainable structural findings. Risk scores remain unassigned until Phase 4.
- Added URL analyzer and API tests. The local analyzer smoke check and Python syntax checks pass; pytest/runtime checks remain unavailable in this environment.

## Phase 4 — Risk engine

- Added deterministic evidence weights, HTTPS as a modest negative offset, 0–100 clamping, and LOW/MEDIUM/HIGH/CRITICAL bands.
- Persisted the score, risk level, per-finding impacts, and a reproducible formula breakdown.
- Updated scan results to display score, risk band, and expandable calculation details.
- Added risk-band, weighting, and weak-signal tests. Full pytest and browser verification require rebuilding and running the Docker stack.

## Phase 11 — Security hardening

- Added Redis-backed per-hour scan limits for anonymous IPs and authenticated accounts, with configurable defaults and fail-closed behavior when Redis cannot enforce limits.
- Prevented public DNS, TLS, and redirect lookups for special-use hostnames; retained public-IP validation and pinned redirect connections.
- Disabled credentialed CORS, added Permissions-Policy and no-store API headers, and kept rate-limit connection errors free of deployment details.
- Added regression coverage for registration role escalation, viewer authorization, invalid tokens, response headers, special-use DNS, private IP redirects, URL input boundaries, and rate limiting.
- Made frontend dependency installation reproducible by pinning package versions to the lockfile and using `npm ci` in the container build.
- All 25 backend tests pass, and the frontend TypeScript/production build passes. The test run exposed identical access tokens issued within the same second; access tokens now include a unique token ID. `pip-audit` initially found cryptography advisories; the permitted version range was updated to 50.x and the follow-up audit found no known vulnerabilities. Docker-based integration verification remains unavailable because the Docker CLI is not available in this environment.

## Phase 12 — Documentation

- Rewrote the architecture and detection-engine guides to match the implemented synchronous scan flow, scoring, provider boundaries, and known limitations.
- Added API, security, deployment, and threat-intelligence references, including endpoint access levels, environment variables, operational setup, privacy behavior, and unimplemented roadmap items.
- Linked the six guides from the README and corrected descriptions that previously implied asynchronous scans or features that do not exist.
- Recorded the audited cryptography constraint and the remaining Docker-runtime verification limitation in project documentation.
