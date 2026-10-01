from uuid import UUID
from ipaddress import ip_address

from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from app.api.dependencies import current_user, optional_current_user
from app.database.session import get_db
from app.detection.url_analyzer import URLValidationError, analyze_url
from app.detection.risk_engine import assess_risk
from app.detection.domain_intelligence import inspect_domain
from app.detection.brand_detector import detect_brands
from app.detection.threat_intelligence import lookup_url
from app.detection.redirect_analyzer import inspect_redirects
from app.detection.ai_explanation import explain_assessment
from app.core.rate_limit import scan_rate_limit
from app.models.scan import Finding, Scan
from app.models.user import User
from app.models.brand import Brand
from app.schemas.scans import FindingView, ScanRequest, ScanView

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _summary(scan: Scan) -> str:
    if scan.risk_calculation is None or scan.risk_score is None or scan.risk_level is None:
        return "Risk assessment is unavailable for this older scan. Submit the URL again to calculate a current score."
    if scan.risk_calculation and scan.risk_calculation.get("raw_total", 0) <= 0:
        return "No positive weighted risk indicators were found. This assessment does not prove that the URL is safe."
    return f"Assessed {scan.risk_level.lower()} risk ({scan.risk_score}/100) from the weighted indicators listed below; this is not a verdict."


def _view(scan: Scan) -> ScanView:
    return ScanView(
        scan_id=scan.id,
        original_url=scan.original_url,
        normalized_url=scan.normalized_url,
        domain=scan.domain,
        risk_score=scan.risk_score,
        risk_level=scan.risk_level,
        risk_calculation=scan.risk_calculation,
        domain_intelligence=scan.domain_intelligence,
        brand_analysis=scan.brand_analysis,
        threat_intelligence=scan.threat_intelligence,
        redirect_analysis=scan.redirect_analysis,
        ai_explanation=scan.ai_explanation,
        status=scan.status,
        summary=_summary(scan),
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        findings=[FindingView.model_validate(finding) for finding in scan.findings],
    )


@router.post("", response_model=ScanView, status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanRequest, db: Session = Depends(get_db),
                user: User | None = Depends(optional_current_user),
                _rate_limit: None = Depends(scan_rate_limit)) -> ScanView:
    try:
        analysis = analyze_url(payload.url)
    except URLValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from None
    try:
        is_ip = False
        try:
            ip_address(analysis.domain)
            is_ip = True
        except ValueError:
            pass
        domain_intelligence = inspect_domain(analysis.domain, is_ip=is_ip)
    except Exception:
        # Enrichment must never prevent the structural scan from completing.
        domain_intelligence = {
            "dns": {"status": "unavailable", "addresses": [], "reason": "Domain lookup failed."},
            "certificate": {"status": "unavailable", "reason": "Domain lookup failed."},
            "registration": {"status": "unavailable", "reason": "Domain lookup failed; age was not inferred."},
        }
    configured_brands = db.scalars(select(Brand).order_by(Brand.name)).all()
    brand_analysis = detect_brands(analysis.domain, [
        {"name": item.name, "official_domains": item.official_domains,
         "aliases": item.aliases, "keywords": item.keywords}
        for item in configured_brands
    ])
    # The strongest configured brand match contributes once; multiple brand names must not stack risk.
    for match in brand_analysis["matches"][:1]:
        assessment_finding = {
            "category": "BRAND_IMPERSONATION", "severity": "MEDIUM",
            "title": f"Possible {match['brand']} lookalike domain",
            "description": match["reason"] + " This similarity is a review signal, not proof of impersonation.",
            "evidence": f"Matched hostname text: {match['matched_text']}; matched-label similarity: {match['matched_label_similarity']:.2f}; configured official domains: {', '.join(match['official_domains'])}",
        }
        analysis.findings.append(assessment_finding)
    threat_intelligence = lookup_url(analysis.storage_url)
    malicious_sources = [provider["provider"] for provider in threat_intelligence["providers"]
                         if provider["status"] == "malicious"]
    if malicious_sources:
        analysis.findings.append({
            "category": "THREAT_INTELLIGENCE", "severity": "HIGH",
            "title": "Known threat intelligence match",
            "description": "At least one configured threat-intelligence provider reported a match for this URL. Check the provider details and timestamp.",
            "evidence": "Matching providers: " + ", ".join(malicious_sources),
        })
    redirect_analysis = inspect_redirects(analysis.storage_url)
    if redirect_analysis.get("redirect_count", 0) >= 2:
        analysis.findings.append({
            "category": "REDIRECT", "severity": "MEDIUM",
            "title": "Multiple redirects detected",
            "description": "The public destination returned multiple HTTP redirects. Redirects can obscure where a link leads; this is not proof of malicious activity.",
            "evidence": f"Redirect count: {redirect_analysis['redirect_count']}; domains: {', '.join(redirect_analysis.get('domains', [])) or 'destination not fully resolved'}",
        })
    elif redirect_analysis.get("redirect_count", 0) and redirect_analysis.get("domain_changed"):
        analysis.findings.append({
            "category": "REDIRECT", "severity": "LOW",
            "title": "Cross-domain redirect observed",
            "description": "The destination redirected to a different hostname. This can be normal; review the destination domain.",
            "evidence": "Domains: " + ", ".join(redirect_analysis.get("domains", [])),
        })
    assessment = assess_risk(analysis.findings, scheme=analysis.normalized_url.split(":", 1)[0])
    ai_explanation = explain_assessment(
        risk_score=assessment["risk_score"], risk_level=assessment["risk_level"],
        findings=assessment["findings"],
    )
    scan = Scan(user_id=user.id if user else None, original_url=analysis.storage_url,
                normalized_url=analysis.storage_url, domain=analysis.domain, status="COMPLETED",
                risk_score=assessment["risk_score"], risk_level=assessment["risk_level"],
                risk_calculation=assessment["risk_calculation"], domain_intelligence=domain_intelligence,
                brand_analysis=brand_analysis, threat_intelligence=threat_intelligence,
                redirect_analysis=redirect_analysis, ai_explanation=ai_explanation)
    scan.findings = [Finding(**finding) for finding in assessment["findings"]]
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return _view(scan)


@router.get("", response_model=list[ScanView])
def list_scans(limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0),
               risk_level: str | None = Query(default=None, pattern="^(?i:low|medium|high|critical)$"),
               domain: str | None = Query(default=None, min_length=1, max_length=253),
               brand: str | None = Query(default=None, min_length=1, max_length=80),
               date_from: date | None = None, date_to: date | None = None,
               db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[ScanView]:
    query = select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(limit)
    if user.role not in {"admin", "analyst"}:
        query = query.where(Scan.user_id == user.id)
    if risk_level:
        query = query.where(Scan.risk_level == risk_level.upper())
    if domain:
        query = query.where(Scan.domain.ilike(f"%{domain.strip()}%"))
    if date_from:
        query = query.where(Scan.created_at >= datetime.combine(date_from, time.min, tzinfo=timezone.utc))
    if date_to:
        query = query.where(Scan.created_at < datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=timezone.utc))
    if brand:
        escaped = brand.replace("%", "\\%").replace("_", "\\_")
        query = query.where(Scan.findings.any(and_(Finding.category == "BRAND_IMPERSONATION",
                                                   Finding.title.ilike(f"%{escaped}%", escape="\\"))))
    return [_view(scan) for scan in db.scalars(query).all()]


@router.get("/{scan_id}", response_model=ScanView)
def get_scan(scan_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)) -> ScanView:
    scan = db.get(Scan, scan_id)
    if scan is None or (user.role not in {"admin", "analyst"} and scan.user_id != user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _view(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None or (user.role not in {"admin", "analyst"} and scan.user_id != user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    db.delete(scan)
    db.commit()
