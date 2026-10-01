from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel


class DashboardPoint(BaseModel):
    date: date
    count: int


class DashboardLabelCount(BaseModel):
    label: str
    count: int


class DashboardRecentScan(BaseModel):
    scan_id: UUID
    domain: str
    risk_score: int | None
    risk_level: str | None
    status: str
    created_at: datetime


class DashboardStats(BaseModel):
    total_scans: int
    high_risk_links: int
    risk_counts: dict[str, int]
    scans_over_time: list[DashboardPoint]
    top_detected_brands: list[DashboardLabelCount]
    threat_categories: list[DashboardLabelCount]
    recent_scans: list[DashboardRecentScan]
