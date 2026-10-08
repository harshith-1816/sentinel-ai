"""
Sentinel AI - Mobile App & Permission Threat Auditor
Identifies unassessed authorizations, dangerous permissions, banking trojan combos,
spyware vectors, and unauthorized device-level surveillance on mobile (Android).
"""
import re
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field

from core.threat_scorer import ThreatReport, Finding, RiskLevel, calculate_risk

# Dangerous Permission Definitions & Severity Weights
PERMISSION_WEIGHTS: Dict[str, Dict[str, Any]] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "weight": 50,
        "name": "Accessibility Service (God Mode)",
        "threat": "Can read screen text, intercept 2FA codes, log keystrokes, and automatically tap buttons without user consent."
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "weight": 35,
        "name": "Draw Over Other Apps (Overlay)",
        "threat": "Can inject deceptive fake login overlays over banking, crypto, and social apps to harvest credentials."
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "weight": 45,
        "name": "Device Administrator Privileges",
        "threat": "Can lock the device, alter lockscreen passcodes, block uninstallation, and remotely wipe storage."
    },
    "android.permission.RECEIVE_SMS": {
        "weight": 30,
        "name": "Receive SMS Messages",
        "threat": "Allows silent interception of incoming one-time SMS verification passwords (OTPs)."
    },
    "android.permission.READ_SMS": {
        "weight": 30,
        "name": "Read SMS Storage",
        "threat": "Allows reading private text messages and archived banking authentication codes."
    },
    "android.permission.SEND_SMS": {
        "weight": 30,
        "name": "Send SMS Messages",
        "threat": "Can silently send premium-rate SMS messages incurring unexpected billing charges."
    },
    "android.permission.RECORD_AUDIO": {
        "weight": 25,
        "name": "Microphone Audio Recording",
        "threat": "Can record ambient room audio and telephone conversations secretly in the background."
    },
    "android.permission.CAMERA": {
        "weight": 25,
        "name": "Camera Access",
        "threat": "Can snap photos and video streams without clear user intent."
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "weight": 30,
        "name": "24/7 Background Location Tracking",
        "threat": "Monitors the user's precise physical movements continuously even when the app is closed."
    },
    "android.permission.READ_CONTACTS": {
        "weight": 20,
        "name": "Address Book Harvesting",
        "threat": "Exfiltrates entire family and colleague contact lists for phishing and extortion."
    },
    "android.permission.READ_CALL_LOG": {
        "weight": 25,
        "name": "Read Call Logs",
        "threat": "Inspects who you speak with, call frequency, and timestamps."
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "weight": 35,
        "name": "Install Unknown Apps (Dropper)",
        "threat": "Can act as a dropper trojan by silently downloading and triggering installations of auxiliary malware."
    },
    "android.permission.PACKAGE_USAGE_STATS": {
        "weight": 25,
        "name": "Package Usage Statistics",
        "threat": "Tracks which app is active on screen to precisely time overlay attacks on banking apps."
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "weight": 20,
        "name": "Reconnaissance of Installed Apps",
        "threat": "Scans all installed applications on the device to discover which cryptocurrency and banking apps exist."
    }
}

# Categories where dangerous permissions are completely unjustified
UNJUSTIFIED_CATEGORIES: Dict[str, Set[str]] = {
    "calculator": {"android.permission.READ_SMS", "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.CAMERA", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.ACCESS_BACKGROUND_LOCATION"},
    "flashlight": {"android.permission.READ_SMS", "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.ACCESS_BACKGROUND_LOCATION"},
    "wallpaper": {"android.permission.READ_SMS", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
    "cleaner": {"android.permission.READ_SMS", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
    "game": {"android.permission.READ_SMS", "android.permission.READ_CALL_LOG", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"}
}


class AppInfo(BaseModel):
    package_name: str
    app_name: Optional[str] = None
    category: Optional[str] = "utility"
    is_system_app: bool = False
    permissions: List[str] = []


class DeviceAuditReport(BaseModel):
    device_id: Optional[str] = "Mobile Device"
    total_apps_scanned: int = 0
    apps_at_risk_count: int = 0
    critical_threats: List[ThreatReport] = []
    high_threats: List[ThreatReport] = []
    medium_threats: List[ThreatReport] = []
    low_or_safe: List[ThreatReport] = []
    overall_device_posture: RiskLevel = RiskLevel.SAFE
    summary: str = ""
    remedial_steps: List[str] = []


class MobileAuditor:
    def __init__(self):
        pass

    def audit_app(self, app: AppInfo) -> ThreatReport:
        findings: List[Finding] = []
        score = 0
        perms = set(app.permissions)
        app_label = app.app_name or app.package_name

        # System apps normally have higher privileges; apply baseline damping unless severely malicious
        is_sys = app.is_system_app

        # 1. Check Specific Dangerous Permissions
        for perm, meta in PERMISSION_WEIGHTS.items():
            if perm in perms:
                weight = meta["weight"]
                if is_sys:
                    weight = int(weight * 0.3)  # System app tolerance factor

                score += weight
                findings.append(Finding(
                    category="Dangerous Permission",
                    severity=RiskLevel.CRITICAL if weight >= 45 else (RiskLevel.HIGH if weight >= 30 else RiskLevel.MEDIUM),
                    title=f"Authorization: {meta['name']}",
                    description=meta["threat"],
                    indicator=perm,
                    remediation=f"Revoke this authorization in Settings > Apps > {app_label} > Permissions."
                ))

        # 2. MALICIOUS COMBINATION 1: Banking Overlay Trojan
        # Accessibility + System Alert Window (+/- SMS)
        has_acc = "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms
        has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perms
        has_sms = any(p in perms for p in ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS"])

        if has_acc and has_overlay:
            extra = 40 if not is_sys else 15
            score += extra
            findings.append(Finding(
                category="Malware Profile",
                severity=RiskLevel.CRITICAL,
                title="Banking Trojan Overlay Architecture Detected",
                description="This app pairs Accessibility Service with Draw-Over-Apps (Overlay). This exact combination is standard for banking trojans (e.g., Anatsa, SharkBot) to siphon credentials and auto-authorize unauthorized fund transfers.",
                indicator="BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW",
                remediation="UNINSTALL THIS APP IMMEDIATELY unless it is an official screen reader like Google TalkBack."
            ))

        # 3. MALICIOUS COMBINATION 2: Complete Spyware / Stalkerware Vector
        # Audio + Camera + Background Location + Contacts
        has_audio = "android.permission.RECORD_AUDIO" in perms
        has_cam = "android.permission.CAMERA" in perms
        has_bg_loc = "android.permission.ACCESS_BACKGROUND_LOCATION" in perms
        has_contacts = "android.permission.READ_CONTACTS" in perms

        if has_audio and has_cam and (has_bg_loc or has_contacts):
            extra = 35 if not is_sys else 10
            score += extra
            findings.append(Finding(
                category="Malware Profile",
                severity=RiskLevel.CRITICAL,
                title="Full-Surveillance Spyware Profile Detected",
                description="App holds concurrent microphone recording, camera capture, and location/contact access. Can act as stealth stalkerware/spyware.",
                indicator="AUDIO + CAMERA + LOCATION/CONTACTS",
                remediation="Inspect whether this application genuinely requires background surveillance capabilities."
            ))

        # 4. MALICIOUS COMBINATION 3: Stealth Dropper
        has_install = "android.permission.REQUEST_INSTALL_PACKAGES" in perms
        if has_install and (has_overlay or has_acc):
            score += 30
            findings.append(Finding(
                category="Malware Profile",
                severity=RiskLevel.HIGH,
                title="Dropper / Secondary Payload Installer",
                description="App has permission to install unvetted APK packages while holding overlay or accessibility rights.",
                indicator="REQUEST_INSTALL_PACKAGES + OVERLAY/ACCESSIBILITY",
                remediation="Disable 'Install unknown apps' permission for this application."
            ))

        # 5. Unassessed / Unjustified Authorization Check (Category Mismatch)
        cat = (app.category or "").lower()
        if cat in UNJUSTIFIED_CATEGORIES:
            unjustified_for_cat = UNJUSTIFIED_CATEGORIES[cat]
            abusive_perms = perms.intersection(unjustified_for_cat)
            if abusive_perms:
                score += 30
                findings.append(Finding(
                    category="Authorization Anomaly",
                    severity=RiskLevel.HIGH,
                    title=f"Unjustified Authorizations for Category '{cat.capitalize()}'",
                    description=f"App is categorized as '{cat}' but requests intrusive permissions ({', '.join(abusive_perms)}) that serve no legitimate functional purpose.",
                    indicator=", ".join(abusive_perms),
                    remediation=f"There is no reason for a {cat} to access these services. Revoke permissions or uninstall."
                ))

        score = min(score, 100)
        overall_risk = calculate_risk(score)

        summary_map = {
            RiskLevel.SAFE: f"'{app_label}' holds benign permissions standard for normal mobile applications.",
            RiskLevel.LOW: f"'{app_label}' holds minor permissions. No concerning authorization anomalies found.",
            RiskLevel.MEDIUM: f"'{app_label}' has sensitive permissions that warrant user review.",
            RiskLevel.HIGH: f"WARNING: '{app_label}' has dangerous permission authorizations capable of privacy compromise.",
            RiskLevel.CRITICAL: f"CRITICAL SECURITY HAZARD: '{app_label}' exhibits clear spyware or banking trojan permission signatures!"
        }

        recs = []
        if overall_risk == RiskLevel.CRITICAL:
            recs.extend([
                f"Immediately uninstall '{app_label}' from your phone.",
                "Check recent banking and cryptocurrency transactions for unauthorized activity.",
                "Review device Accessibility Services in Android Settings and disable unvetted entries."
            ])
        elif overall_risk == RiskLevel.HIGH:
            recs.extend([
                f"Revoke dangerous permissions for '{app_label}' in Android Settings > Apps.",
                "Verify if you downloaded this app from the official Google Play Store or an unverified APK."
            ])
        elif overall_risk == RiskLevel.MEDIUM:
            recs.append("Ensure permissions are set to 'Only while using the app' rather than 'Always allow'.")
        else:
            recs.append("App is within acceptable permission parameters.")

        return ThreatReport(
            target=app_label,
            target_type="mobile_app",
            overall_risk=overall_risk,
            risk_score=score,
            summary=summary_map[overall_risk],
            findings=findings,
            metadata={
                "package_name": app.package_name,
                "app_name": app.app_name,
                "category": app.category,
                "is_system_app": app.is_system_app,
                "permissions_count": len(app.permissions)
            },
            recommended_actions=recs
        )

    def audit_device(self, apps: List[AppInfo], device_id: str = "Android Device") -> DeviceAuditReport:
        critical_list = []
        high_list = []
        medium_list = []
        low_list = []

        for app in apps:
            report = self.audit_app(app)
            if report.overall_risk == RiskLevel.CRITICAL:
                critical_list.append(report)
            elif report.overall_risk == RiskLevel.HIGH:
                high_list.append(report)
            elif report.overall_risk == RiskLevel.MEDIUM:
                medium_list.append(report)
            else:
                low_list.append(report)

        at_risk = len(critical_list) + len(high_list) + len(medium_list)
        if len(critical_list) > 0:
            posture = RiskLevel.CRITICAL
            summary = f"DEVICE COMPROMISED: {len(critical_list)} apps with Trojan/Spyware permission signatures found!"
        elif len(high_list) > 0:
            posture = RiskLevel.HIGH
            summary = f"HIGH RISK: {len(high_list)} apps with dangerous intrusive permissions detected."
        elif len(medium_list) > 0:
            posture = RiskLevel.MEDIUM
            summary = f"MODERATE RISK: {len(medium_list)} apps hold authorizations that need scrutiny."
        else:
            posture = RiskLevel.SAFE
            summary = "Mobile device posture is healthy. No hazardous authorizations detected."

        device_remedy = []
        if critical_list:
            device_remedy.append(f"CRITICAL: Uninstall flagged apps ({', '.join([r.target for r in critical_list])}).")
            device_remedy.append("Perform a full malware scan and inspect Accessibility Services settings.")
        if high_list:
            device_remedy.append("Revoke background SMS, Location, and Draw-Over-Apps authorizations from high-risk apps.")
        if not device_remedy:
            device_remedy.append("Keep Android OS and security patches updated.")

        return DeviceAuditReport(
            device_id=device_id,
            total_apps_scanned=len(apps),
            apps_at_risk_count=at_risk,
            critical_threats=critical_list,
            high_threats=high_list,
            medium_threats=medium_list,
            low_or_safe=low_list,
            overall_device_posture=posture,
            summary=summary,
            remedial_steps=device_remedy
        )
