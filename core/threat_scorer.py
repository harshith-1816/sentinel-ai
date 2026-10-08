"""
Sentinel AI - Threat Scorer and Risk Assessment Data Models
"""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    category: str
    severity: RiskLevel
    title: str
    description: str
    indicator: Optional[str] = None
    remediation: Optional[str] = None


class ThreatReport(BaseModel):
    target: str
    target_type: str  # "email", "url", "mobile_app", "mobile_device"
    overall_risk: RiskLevel
    risk_score: int = Field(ge=0, le=100, description="0 is harmless, 100 is confirmed critical threat")
    summary: str
    findings: List[Finding] = []
    metadata: Dict[str, Any] = {}
    recommended_actions: List[str] = []


def calculate_risk(score: int) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    elif score >= 50:
        return RiskLevel.HIGH
    elif score >= 25:
        return RiskLevel.MEDIUM
    elif score >= 10:
        return RiskLevel.LOW
    return RiskLevel.SAFE
