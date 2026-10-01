# HTTP API

The API base URL in local Compose is `http://localhost:8000`. Interactive OpenAPI documentation is available at `/docs` while the API is running. JSON request/response bodies use UTF-8. Authentication uses `Authorization: Bearer <access_token>`; no cookie session is used.

## Health

| Method and path | Access | Behavior |
| --- | --- | --- |
| `GET /health` | Public | Liveness response. |
| `GET /api/health` | Public | API liveness response. |
| `GET /health/ready` | Public | Checks PostgreSQL and Redis; returns 503 if either check fails. |

## Authentication

| Method and path | Access | Success |
| --- | --- | --- |
| `POST /api/auth/register` | Public | 201; creates a viewer and returns access/refresh tokens and user profile. |
| `POST /api/auth/login` | Public | 200; returns a new token pair. |
| `POST /api/auth/refresh` | Public, refresh token required | 200; rotates the refresh token and returns a new pair. |
| `POST /api/auth/logout` | Public, refresh token accepted | 204; revokes that refresh session. |
| `GET /api/auth/me` | Authenticated | 200; current user profile. |

Registration and login accept `{ "email": "name@example.com", "password": "at least twelve characters" }`. Passwords are bcrypt-hashed. Registration always sets the role to `viewer`; a supplied role is ignored. Refresh/logout accept `{ "refresh_token": "..." }`. Access tokens last 15 minutes and refresh tokens last 7 days by default; configure the durations with `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` and `JWT_REFRESH_TOKEN_EXPIRE_DAYS`.

## Scans and history

| Method and path | Access | Behavior |
| --- | --- | --- |
| `POST /api/scans` | Public; token optional | 201; performs a scan synchronously. The body is `{ "url": "https://example.com/path" }`. Optional bearer auth associates the scan with the account. |
| `GET /api/scans` | Authenticated | 200; paginated scan history. Viewers see their own scans; analysts/admins see all. |
| `GET /api/scans/{scan_id}` | Authenticated | 200 for a visible scan; 404 for missing or out-of-scope scans. |
| `DELETE /api/scans/{scan_id}` | Authenticated | 204 for a visible scan; 404 for missing or out-of-scope scans. |

`GET /api/scans` supports `limit` (1–100, default 50), `offset`, `risk_level`, `domain`, `brand`, `date_from`, and `date_to`. Scans return a `COMPLETED` record with normalized/redacted URL, score, score calculation, findings, domain intelligence, brand analysis, threat-intelligence, redirect analysis, and AI explanation where available.

Scan request validation errors return 422. The hourly rate limiter returns 429 and a `Retry-After` header after the configured quota; it returns 503 if Redis is unavailable because the limit cannot be safely enforced.

## Dashboard and brands

| Method and path | Access | Behavior |
| --- | --- | --- |
| `GET /api/dashboard/stats` | Authenticated | Account-scoped scan totals, risk counts, 30-day activity, brands, categories, and recent scans. |
| `GET /api/brands` | Public | Lists configured brand names, domains, aliases, and keywords. |
| `POST /api/brands` | Admin | Creates a brand. Body fields: `name`, `official_domains` (1–10), optional `aliases`, and optional `keywords`. |
| `PUT /api/brands/{brand_id}` | Admin | Replaces editable brand fields using the same body shape. |
| `DELETE /api/brands/{brand_id}` | Admin | Deletes a brand; 204 on success. |

Brand input domains are normalized and validated. Duplicate brand names return 409. There are no current user-administration, detection-rule, audit-log, or dedicated domain endpoints.

## Threat intelligence

| Method and path | Access | Behavior |
| --- | --- | --- |
| `GET /api/threat-intelligence/{indicator}` | Analyst or admin | Looks up the path value as a URL indicator and returns provider statuses. |

Because the URL is embedded in a path, percent-encode reserved characters. In the frontend, scan reports are the simpler way to submit a URL for threat lookup.

## Common errors and response protections

- 401: missing/invalid/expired access token for protected endpoints, or invalid credentials/token.
- 403: authenticated role is insufficient.
- 404: resource is absent or outside the caller’s scope.
- 409: duplicate account or brand.
- 422: invalid request body, path, or query.
- 429: scan quota exceeded.
- 503: readiness or Redis-backed scan limiting unavailable.

API responses set `Cache-Control: no-store`. CORS origins are configured with `CORS_ORIGINS`; credentials are disabled. FastAPI validation errors use the standard FastAPI error envelope.
