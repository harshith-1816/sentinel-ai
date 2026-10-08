"""
Sentinel AI - REST API Service & Full-Stack Security Hub
Exposes threat analysis endpoints, web dashboard, and automated screen alerts.
"""
import os
from typing import List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core.threat_scorer import ThreatReport, RiskLevel
from core.url_analyzer import URLAnalyzer
from core.email_analyzer import EmailAnalyzer
from core.mobile_auditor import MobileAuditor, AppInfo, DeviceAuditReport
from automation.screen_notifier import trigger_screen_alert
from automation.background_watchdog import start_automation_guard, clipboard_guard

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "web", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "web", "templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start automated clipboard watchdog on server startup
    start_automation_guard()
    yield
    clipboard_guard.stop()


app = FastAPI(
    title="Sentinel AI - Cyber Threat & Mobile Security Engine",
    description="Automated AI engine for identifying fake emails, unauthorized websites/apps, and rogue mobile authorizations.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontends and mobile apps
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for dashboard
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

url_analyzer = URLAnalyzer()
live_url_analyzer = URLAnalyzer(check_live_status=True)
email_analyzer = EmailAnalyzer()
mobile_auditor = MobileAuditor()


# --- Request Models ---
class URLScanRequest(BaseModel):
    url: str = Field(..., example="http://paypa1-security-verification.xyz/login")
    check_live: bool = Field(False, description="Whether to probe live SSL and redirects")
    notify_screen: bool = Field(True, description="Whether to show an on-screen desktop popup if harmful")


class EmailScanRequest(BaseModel):
    raw_email: Optional[str] = Field(None, description="RFC 822 format or full raw email message")
    sender: Optional[str] = Field(None, example="PayPal Support <alert-service@gmail.com>")
    reply_to: Optional[str] = Field(None, example="hacker-inbox@evilmail.xyz")
    subject: Optional[str] = Field(None, example="URGENT: Your account has been suspended within 24 hours")
    body: Optional[str] = Field(None, example="Dear Customer, click here to verify: http://paypa1-update.com/login")
    attachments: Optional[List[str]] = Field(default=[], example=["invoice.pdf.exe"])
    notify_screen: bool = Field(True, description="Whether to show an on-screen desktop popup if harmful")


class DeviceAuditRequest(BaseModel):
    device_id: Optional[str] = "Android Device"
    apps: List[AppInfo]
    notify_screen: bool = Field(True, description="Whether to trigger desktop alert if trojans found")


# --- Web Dashboard Home ---
@app.get("/")
def serve_dashboard():
    index_file = os.path.join(TEMPLATES_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Sentinel AI API is active. Open /docs for API documentation."}


from datetime import datetime

recent_incidents: List[dict] = []


def record_incident(target: str, target_type: str, risk: RiskLevel, score: int, summary: str):
    incident = {
        "id": len(recent_incidents) + 1,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "target": target,
        "type": target_type,
        "risk": risk.value,
        "score": score,
        "summary": summary
    }
    recent_incidents.insert(0, incident)
    if len(recent_incidents) > 50:
        recent_incidents.pop()


# --- API Endpoints ---
@app.get("/api/status")
def get_status():
    return {
        "status": "online",
        "service": "Sentinel AI Security Engine",
        "version": "1.0.0",
        "modules": {
            "email_analyzer": "active",
            "url_analyzer": "active",
            "mobile_auditor": "active",
            "screen_alert_automation": "active"
        },
        "stats": {
            "total_incidents_recorded": len(recent_incidents),
            "threats_blocked": sum(1 for i in recent_incidents if i["risk"] in ("CRITICAL", "HIGH"))
        }
    }


@app.get("/api/incidents")
def get_incidents():
    return {"incidents": recent_incidents}


@app.post("/api/scan/url", response_model=ThreatReport)
def scan_url(req: URLScanRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    analyzer = live_url_analyzer if req.check_live else url_analyzer
    report = analyzer.analyze(req.url)

    record_incident(
        target=req.url,
        target_type="URL / Web App",
        risk=report.overall_risk,
        score=report.risk_score,
        summary=report.summary
    )

    if req.notify_screen and report.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        trigger_screen_alert(
            title="HARMFUL WEBSITE DETECTED",
            threat_type="Phishing Website",
            target=req.url,
            risk_level=report.overall_risk.value,
            summary=report.summary,
            indicators=[f.title for f in report.findings[:3]],
            async_mode=True
        )

    return report


@app.post("/api/scan/email", response_model=ThreatReport)
def scan_email(req: EmailScanRequest):
    if req.raw_email:
        report = email_analyzer.analyze_raw(req.raw_email, attachments=req.attachments)
    else:
        if not req.sender and not req.body and not req.subject:
            raise HTTPException(status_code=400, detail="Provide either raw_email or at least sender/subject/body.")
        report = email_analyzer.analyze_structured(
            sender=req.sender or "",
            reply_to=req.reply_to or "",
            subject=req.subject or "",
            body=req.body or "",
            attachments=req.attachments or []
        )

    record_incident(
        target=req.sender or req.subject or "Email Message",
        target_type="Phishing Email",
        risk=report.overall_risk,
        score=report.risk_score,
        summary=report.summary
    )

    if req.notify_screen and report.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        trigger_screen_alert(
            title="HARMFUL PHISHING EMAIL DETECTED",
            threat_type="Phishing Email",
            target=req.sender or req.subject or "Email Message",
            risk_level=report.overall_risk.value,
            summary=report.summary,
            indicators=[f.title for f in report.findings[:3]],
            async_mode=True
        )

    return report


@app.post("/api/audit/mobile-app", response_model=ThreatReport)
def audit_mobile_app(app_info: AppInfo):
    return mobile_auditor.audit_app(app_info)


@app.post("/api/audit/mobile-device", response_model=DeviceAuditReport)
def audit_mobile_device(req: DeviceAuditRequest):
    report = mobile_auditor.audit_device(apps=req.apps, device_id=req.device_id or "Android Device")

    record_incident(
        target=f"{req.device_id} ({len(req.apps)} apps)",
        target_type="Mobile Device Audit",
        risk=report.overall_device_posture,
        score=100 if report.critical_threats else (75 if report.high_threats else (30 if report.medium_threats else 0)),
        summary=report.summary
    )

    if req.notify_screen and (report.critical_threats or report.high_threats):
        top_threat = (report.critical_threats + report.high_threats)[0]
        trigger_screen_alert(
            title="ROGUE MOBILE APP DETECTED",
            threat_type="Mobile Trojan / Spyware",
            target=top_threat.target,
            risk_level=top_threat.overall_risk.value,
            summary=f"Found {len(report.critical_threats)} trojans and {len(report.high_threats)} hazardous permissions on phone.",
            indicators=[f.title for f in top_threat.findings[:3]],
            async_mode=True
        )

    return report


@app.post("/api/automation/test-alert")
def test_alert():
    trigger_screen_alert(
        title="HARMFUL PHISHING SIMULATION",
        threat_type="Phishing & Credential Theft",
        target="http://paypa1-security-verification.xyz/login",
        risk_level="CRITICAL",
        summary="This website mimics PayPal login to steal account passwords and 2FA credentials.",
        indicators=["Homoglyph / Typosquatting", "High-Risk TLD (.xyz)", "Unencrypted Credentials"],
        async_mode=True
    )
    return {"status": "success", "message": "On-screen warning alert launched on your Windows screen!"}
