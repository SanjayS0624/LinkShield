from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import require_roles
from app.detection.threat_intelligence import lookup_url
from app.detection.url_analyzer import URLValidationError, analyze_url

router = APIRouter(prefix="/api/threat-intelligence", tags=["threat intelligence"])


@router.get("/{indicator:path}")
def inspect_indicator(indicator: str, _analyst=Depends(require_roles("analyst", "admin"))) -> dict:
    try:
        parsed = analyze_url(indicator)
    except URLValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return lookup_url(parsed.storage_url)
