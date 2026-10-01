from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import current_user
from app.database.session import get_db
from app.models.scan import Finding, Scan
from app.models.user import User
from app.schemas.dashboard import DashboardRecentScan, DashboardStats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _scope(statement, user: User):
    if user.role not in {"admin", "analyst"}:
        return statement.where(Scan.user_id == user.id)
    return statement


@router.get("/stats", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db), user: User = Depends(current_user)) -> DashboardStats:
    total = db.scalar(_scope(select(func.count()).select_from(Scan), user)) or 0
    risk_rows = db.execute(_scope(
        select(Scan.risk_level, func.count()).group_by(Scan.risk_level), user)).all()
    risk_counts = {level: 0 for level in RISK_LEVELS}
    risk_counts.update({level: count for level, count in risk_rows if level in risk_counts})

    high_risk = risk_counts["HIGH"] + risk_counts["CRITICAL"]
    since = datetime.now(timezone.utc) - timedelta(days=29)
    timeline_rows = db.execute(_scope(
        select(func.date(Scan.created_at), func.count())
        .where(Scan.created_at >= since).group_by(func.date(Scan.created_at))
        .order_by(func.date(Scan.created_at)), user)).all()
    scans_over_time = [{"date": day, "count": count} for day, count in timeline_rows]

    brand_query = select(Finding.title, func.count()).join(Scan, Finding.scan_id == Scan.id).where(
        Finding.category == "BRAND_IMPERSONATION")
    if user.role not in {"admin", "analyst"}:
        brand_query = brand_query.where(Scan.user_id == user.id)
    brand_rows = db.execute(brand_query.group_by(Finding.title).order_by(func.count().desc()).limit(8)).all()
    top_brands = [(title.removeprefix("Possible ").removesuffix(" lookalike domain"), count)
                  for title, count in brand_rows]

    category_rows = db.execute(
        select(Finding.category, func.count()).join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.category != "URL_STRUCTURE")
        .group_by(Finding.category).order_by(func.count().desc())
    ).all() if user.role in {"admin", "analyst"} else db.execute(
        select(Finding.category, func.count()).join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == user.id, Finding.category != "URL_STRUCTURE")
        .group_by(Finding.category).order_by(func.count().desc())
    ).all()
    threat_categories = [{"label": label, "count": count} for label, count in category_rows[:8]]

    recent_rows = db.scalars(_scope(select(Scan).order_by(Scan.created_at.desc()).limit(8), user)).all()
    recent_scans = [DashboardRecentScan(
        scan_id=scan.id, domain=scan.domain, risk_score=scan.risk_score,
        risk_level=scan.risk_level, status=scan.status, created_at=scan.created_at,
    ) for scan in recent_rows]
    return DashboardStats(
        total_scans=total, high_risk_links=high_risk, risk_counts=risk_counts,
        scans_over_time=scans_over_time,
        top_detected_brands=[{"label": label, "count": count} for label, count in top_brands],
        threat_categories=threat_categories, recent_scans=recent_scans,
    )
