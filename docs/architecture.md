# LinkShield architecture

## Runtime components

Docker Compose defines five services:

| Service | Responsibility |
| --- | --- |
| `frontend` | React and TypeScript single-page application, served by Vite on port 5173. |
| `backend` | FastAPI HTTP API on port 8000; performs URL analysis and persists completed scans. |
| `postgres` | Durable storage for users, refresh sessions, brands, scans, and findings. |
| `redis` | Broker/cache dependency and atomic hourly scan counters. |
| `celery-worker` | Celery worker process connected to Redis and PostgreSQL. The current scan endpoint runs synchronously; it does not enqueue scan jobs. |

PostgreSQL and Redis health checks gate backend and worker startup. The backend readiness route pings both dependencies. The API container runs Alembic migrations before starting Uvicorn. PostgreSQL data persists in the `postgres_data` named volume.

## Request flow

1. The frontend sends a URL to `POST /api/scans`; a bearer access token is optional for submitting a scan.
2. FastAPI validates request shape. The scan dependency applies a Redis-backed per-hour limit, keyed to the direct client IP for anonymous callers or account ID for signed-in callers.
3. The URL analyzer normalizes the URL, removes user information and fragments from the stored representation, redacts common secret query values, and creates structural findings.
4. Enrichment performs bounded DNS/TLS metadata checks, brand matching, configured threat-provider lookups, and bounded redirect inspection. Special-use hostnames and non-public redirect targets are blocked from network inspection.
5. The deterministic risk engine attaches score impacts, clamps the result to 0–100, and returns the component formula. The optional AI layer receives only the score and bounded finding labels; it cannot change the score.
6. The scan and findings are stored in PostgreSQL and returned as a completed report.

Dashboard and history queries require authentication. Viewer queries are scoped to the viewer’s own scans; analyst and admin queries are account-wide.

## Data model

Alembic migrations create `users`, `refresh_sessions`, `brands`, `scans`, and `findings`. Scan enrichment results and the score breakdown are stored as JSON fields on `scans`; findings are separate rows. Deleting a scan cascades to its findings. Deleting a user cascades to refresh sessions and that user’s scans.

The current implementation does not include dedicated domain, threat-indicator, scan-source, or audit-log tables. It also does not expose user administration, detection-rule administration, or an audit-log endpoint. These are not implied by the current UI/API.

## Module boundaries

- `backend/app/api/`: HTTP routes and request/response wiring.
- `backend/app/core/`: environment configuration, JWT/password helpers, and rate limiting.
- `backend/app/database/`: SQLAlchemy setup and readiness checks.
- `backend/app/detection/`: URL, domain, brand, threat, redirect, risk, network-safety, and explanation logic.
- `backend/app/models/`, `schemas/`: persistence entities and typed API schemas.
- `backend/alembic/`: sequential database migrations.
- `frontend/src/`: React UI, API access, and dashboard/report components.

## Operational boundaries

The API is currently synchronous: provider timeouts and bounded DNS/TLS/HEAD checks contribute to request latency. Celery is present in Compose, but scan work is not yet delegated to it. Provider caches are process-local, so they are not shared between multiple backend replicas. See [deployment](deployment.md), [API](api.md), and [security](security.md) for operating constraints.
