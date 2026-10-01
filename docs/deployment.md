# Development deployment

This guide describes the local Docker Compose setup. It is not a production deployment recipe.

## Prerequisites

- Docker Desktop installed and running with the Linux container engine.
- Docker Compose v2 available through `docker compose`.
- Network access to fetch the configured base images and, if not cached, package dependencies.

On Windows, Docker Desktop must finish starting before Compose commands can reach its engine. `docker info` should show both Client and Server sections.

## Configure

From the repository root, make a local environment file:

```powershell
Copy-Item .env.example .env
```

Change `POSTGRES_PASSWORD` and `JWT_SECRET_KEY`. The password in `DATABASE_URL` must match `POSTGRES_PASSWORD`. A random JWT secret can be generated in PowerShell with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Do not commit `.env`. Optional provider keys are blank by default; scans remain available without them. Set `CORS_ORIGINS` to the exact frontend origin used by the browser. The local default is `http://localhost:5173`.

Important settings:

| Variable | Local default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Compose PostgreSQL URL | Backend database connection. |
| `REDIS_URL` | `redis://redis:6379/0` | Redis broker and scan limit counters. |
| `JWT_SECRET_KEY` | Placeholder in sample | Signing secret; replace before use. |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | 15 | Access token lifetime. |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | 7 | Refresh token lifetime. |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed browser origins. |
| `SCAN_LIMIT_ANONYMOUS_PER_HOUR` | 5 | Anonymous scan requests per direct IP/hour. |
| `SCAN_LIMIT_AUTHENTICATED_PER_HOUR` | 30 | Viewer/analyst scan requests per account/hour. |
| `SCAN_LIMIT_ADMIN_PER_HOUR` | 300 | Admin scan requests per account/hour. |
| `VIRUSTOTAL_API_KEY` | blank | Enables VirusTotal lookups. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | blank | Enables Google Safe Browsing v5 URL lookups (non-commercial use). |
| `OPENAI_API_KEY` | blank | Enables the optional explanation layer. |
| `OPENAI_EXPLANATION_MODEL` | `gpt-4o-mini` | Model used for optional explanations. |

## Start and verify

From the repository root:

```powershell
docker compose up --build
```

Open <http://localhost:5173>. API liveness is <http://localhost:8000/health>; dependency readiness is <http://localhost:8000/health/ready>; interactive API docs are at <http://localhost:8000/docs>.

Useful checks in a second PowerShell window:

```powershell
docker compose ps
docker compose logs --tail 100 backend
docker compose logs --tail 100 celery-worker
```

Rebuild selected services after code changes:

```powershell
docker compose up --build --force-recreate backend frontend celery-worker
```

The database is stored in the `postgres_data` volume. `docker compose down` stops the stack but keeps that volume. Treat `docker compose down -v` as a destructive database reset; it deletes persisted scan/account data.

## Tests and dependency checks

The backend regression suite uses an in-memory SQLite fixture and does not need live PostgreSQL/Redis:

```powershell
cd backend
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests -q
```

Run a Python dependency advisory scan after installing `pip-audit`:

```powershell
python -m pip install pip-audit
python -m pip_audit -r requirements.txt
```

Frontend build uses the committed lockfile:

```powershell
cd frontend
npm ci
npm run build
npm audit
```

## Operational limits

Compose exposes the frontend and API on all host interfaces by default. Keep this local or put a properly configured TLS reverse proxy and access controls in front before sharing it. Change development credentials, restrict network access, protect database backups, and configure provider keys deliberately. Scan enrichment is synchronous even though a Celery worker is started; the worker is not currently part of the scan request path. See [security](security.md) for other known gaps.

## Hosted demo: Netlify frontend + Render API

Netlify hosts the React/Vite frontend using the root `netlify.toml`. FastAPI, PostgreSQL, and Redis run on Render because the backend is a long-running Python API. The root `render.yaml` and `Dockerfile.api` define the Render API and its datastores. URL scans run synchronously in the API; a Celery worker is not required for the current scan flow.

### Deploy

1. Put the project files in a **private** GitHub repository. Do not include `.env`, API keys, or local `node_modules` folders. `.gitignore` excludes `.env` from Git and `.dockerignore` excludes local files from the Render image build.
2. In Render, choose **New → Blueprint**, connect the private repository, and approve the services described by `render.yaml`. Enter the VirusTotal key in Render's secret prompt (or leave it empty). Do not put keys in the repository.
3. Once `linkshield-api` is live, copy its HTTPS URL and check `<api-url>/health/ready` for `{"status":"ready"}`.
4. In Netlify, choose **Add new site → Import an existing project**, select the same repository, and deploy. Netlify reads build settings from `netlify.toml`.
5. In Netlify's site environment variables, set `VITE_API_URL` to the Render API URL (for example, `https://linkshield-api.onrender.com`, with no trailing slash), then trigger a new deploy.
6. Copy the Netlify site's production URL. In Render's `linkshield-api` Environment settings, set `CORS_ORIGINS` to that exact origin (for example, `https://your-site.netlify.app`, with no trailing slash), save, and redeploy the API. The frontend can then sign in and call the API.

This free configuration is for a demo. A free Render web service sleeps after 15 minutes without visits and can take about a minute to wake. Free Postgres expires after 30 days and has no backups; free Key Value data is erased when that service restarts. Do not use it for real accounts or data you need to keep. For persistent use, switch Postgres and Key Value to paid plans and review current [Render pricing](https://render.com/pricing). See Render's [free instance limits](https://render.com/docs/free).

The Netlify build variable `VITE_API_URL` is public because it is compiled into browser code; it must contain only the API address, never a secret. Add provider API keys only to Render's private Environment settings. Blueprint values marked `sync: false` are prompted only during initial creation; later secret changes are made in Render's service settings.
