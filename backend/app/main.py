from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.brands import router as brands_router
from app.api.threat_intelligence import router as threat_intelligence_router
from app.api.dashboard import router as dashboard_router
from app.core.config import settings
from app.database.session import database_is_ready

app = FastAPI(title="LinkShield API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Authorization", "Content-Type"])
app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(brands_router)
app.include_router(threat_intelligence_router)
app.include_router(dashboard_router)

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith(("/api/", "/health")):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "linkshield-api"}

@app.get("/api/health")
def api_health() -> dict[str, str]:
    return health()

@app.get("/health/ready")
def readiness(response: Response) -> dict[str, str]:
    try:
        database_is_ready()
        Redis.from_url(settings.redis_url, socket_connect_timeout=2).ping()
    except (SQLAlchemyError, RedisError, OSError, ValueError) as exc:
        response.status_code = 503
        return {"status": "not_ready", "detail": type(exc).__name__}
    return {"status": "ready", "database": "ok", "redis": "ok"}


# Production image includes the compiled Vite app. Keeping it on the API's
# origin means browser requests do not need a separately configured CORS host.
static_dir = Path(__file__).parent / "static"
assets_dir = static_dir / "assets"
if assets_dir.is_dir():
    app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")

if (static_dir / "index.html").is_file():
    @app.get("/", include_in_schema=False)
    def frontend_index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @app.get("/{frontend_path:path}", include_in_schema=False)
    def frontend_fallback(frontend_path: str) -> FileResponse:
        if frontend_path == "api" or frontend_path.startswith("api/") or frontend_path.startswith("health"):
            raise HTTPException(status_code=404, detail="Not Found")
        requested_file = (static_dir / frontend_path).resolve()
        if requested_file.is_relative_to(static_dir.resolve()) and requested_file.is_file():
            return FileResponse(requested_file)
        return FileResponse(static_dir / "index.html")
