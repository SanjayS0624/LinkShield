from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class FindingView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    category: str
    severity: str
    title: str
    description: str
    evidence: str
    score_impact: int | None = None
    created_at: datetime


class RiskComponentView(BaseModel):
    title: str
    category: str
    severity: str
    evidence: str
    impact: int


class RiskCalculationView(BaseModel):
    method: str
    formula: str
    components: list[RiskComponentView]
    raw_total: int
    final_score: int


class ScanView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    scan_id: UUID
    original_url: str
    normalized_url: str
    domain: str
    risk_score: int | None
    risk_level: str | None
    risk_calculation: RiskCalculationView | None
    domain_intelligence: dict | None = None
    brand_analysis: dict | None = None
    threat_intelligence: dict | None = None
    redirect_analysis: dict | None = None
    ai_explanation: dict | None = None
    status: Literal["COMPLETED"]
    summary: str
    created_at: datetime
    completed_at: datetime | None
    findings: list[FindingView]


class ScanAccepted(BaseModel):
    scan_id: UUID
    status: Literal["COMPLETED"]
