"""
Sentinel AI - Email Threat Analyzer
Analyzes email headers, display name spoofing, reply-to traps, urgency psychology,
dangerous attachments, and embedded deceptive links.
"""
import re
from urllib.parse import urlparse
from email import message_from_string
from typing import List, Optional, Dict, Any

from core.threat_scorer import ThreatReport, Finding, RiskLevel, calculate_risk
from core.url_analyzer import URLAnalyzer, HIGH_VALUE_BRANDS

DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "scr", "vbs", "js", "hta", "iso", "img", "jar",
    "pif", "docm", "xlsm", "pptm", "ps1", "wsf"
}

FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "icloud.com", "zoho.com", "mail.com", "yandex.com"
}

URGENCY_PATTERNS = [
    (r"(suspended|disabled|restricted|deactivated)\s+(immediately|within|in\s+\d+\s+hours)", 25, "Account suspension threat"),
    (r"(unauthorized|suspicious)\s+(activity|sign-in|login|access)", 20, "Fake security alert trigger"),
    (r"(urgent|immediate|action\s+required|critical\s+notice)", 15, "High urgency manipulation"),
    (r"(wire\s+transfer|gift\s+card|payroll|direct\s+deposit\s+update)", 25, "BEC financial fraud pattern"),
    (r"(verify\s+your\s+identity|confirm\s+your\s+(wallet|account|ssn|pin))", 25, "Credential harvesting prompt"),
    (r"(tax\s+penalty|irs|lawsuit|legal\s+action|arrest\s+warrant)", 30, "Authority intimidation tactic"),
    (r"(crypto|bitcoin|ethereum)\s+(giveaway|recovery|deposit)", 20, "Cryptocurrency lure")
]

GENERIC_GREETINGS = [
    r"dear\s+customer", r"dear\s+user", r"dear\s+client", r"dear\s+member",
    r"attention\s+valued\s+customer", r"dear\s+account\s+holder"
]


class EmailAnalyzer:
    def __init__(self):
        self.url_analyzer = URLAnalyzer(check_live_status=False)

    def analyze_raw(
        self,
        raw_email: str,
        attachments: Optional[List[str]] = None
    ) -> ThreatReport:
        """Parses an RFC 822 format or formatted text email."""
        try:
            msg = message_from_string(raw_email)
            subject = msg.get("Subject", "")
            sender = msg.get("From", "")
            reply_to = msg.get("Reply-To", "")
            auth_results = msg.get("Authentication-Results", "")
            received_spf = msg.get("Received-SPF", "")

            # Extract body
            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() in ("text/plain", "text/html"):
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body_parts.append(payload.decode(errors="ignore"))
                        except Exception:
                            pass
            else:
                body_parts.append(msg.get_payload() or "")

            body = "\n".join(body_parts) if body_parts else raw_email

        except Exception:
            sender = ""
            reply_to = ""
            subject = ""
            auth_results = ""
            received_spf = ""
            body = raw_email

        return self.analyze_structured(
            sender=sender,
            reply_to=reply_to,
            subject=subject,
            body=body,
            auth_results=auth_results,
            received_spf=received_spf,
            attachments=attachments or []
        )

    def analyze_structured(
        self,
        sender: str,
        reply_to: str = "",
        subject: str = "",
        body: str = "",
        auth_results: str = "",
        received_spf: str = "",
        attachments: Optional[List[str]] = None
    ) -> ThreatReport:
        findings: List[Finding] = []
        score = 0
        attachments = attachments or []

        # Parse sender details
        sender_match = re.search(r'(.*?)(?:<([^>]+)>)?$', sender.strip())
        display_name = sender_match.group(1).strip(' "\'') if sender_match else ""
        sender_email = (sender_match.group(2) or sender_match.group(1)).strip('<> ').lower() if sender_match else ""

        sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ""
        reply_to_email = re.search(r'<([^>]+)>|([^\s<>]+@[^\s<>]+)', reply_to)
        reply_to_email = (reply_to_email.group(1) or reply_to_email.group(2)).lower() if reply_to_email else ""
        reply_domain = reply_to_email.split('@')[-1] if '@' in reply_to_email else ""

        # 1. Display Name Impersonation
        if display_name:
            for brand in HIGH_VALUE_BRANDS:
                if brand in display_name.lower() and brand not in sender_domain:
                    score += 45
                    findings.append(Finding(
                        category="Display Name Spoofing",
                        severity=RiskLevel.HIGH,
                        title=f"Brand Impersonation in Sender Name ({brand.capitalize()})",
                        description=f"Display name claims to be '{display_name}', but actual sending address is '{sender_email}'.",
                        indicator=f"Name: {display_name} vs Email: {sender_email}",
                        remediation="Do not trust sender names without verifying the true email domain."
                    ))
                    break

        # 2. Free Mailbox pretending to be Corporate/Banking
        if sender_domain in FREE_MAIL_PROVIDERS:
            for brand in HIGH_VALUE_BRANDS:
                if brand in subject.lower() or brand in display_name.lower():
                    score += 40
                    findings.append(Finding(
                        category="Sender Spoofing",
                        severity=RiskLevel.HIGH,
                        title=f"Official Brand using Public Webmail",
                        description=f"Email relates to {brand.capitalize()} but was sent from a free mailbox ({sender_domain}). Real organizations send from corporate domains.",
                        indicator=sender_email,
                        remediation="Legitimate organizations will never contact you from free email providers like Gmail, Yahoo, or Outlook."
                    ))
                    break

        # 3. From vs Reply-To Mismatch (Trap)
        if reply_to_email and sender_email and reply_domain != sender_domain:
            score += 40
            findings.append(Finding(
                category="Reply-To Mismatch",
                severity=RiskLevel.HIGH,
                title="Suspicious Reply-To Redirect",
                description=f"Sender address is '{sender_email}', but replies are redirected to a different domain '{reply_to_email}'.",
                indicator=f"From: {sender_email} -> Reply-To: {reply_to_email}",
                remediation="Do not reply. Your response would go directly to the attacker."
            ))

        # 4. SPF / DKIM / DMARC Failures
        auth_blob = (auth_results + " " + received_spf).lower()
        if "spf=fail" in auth_blob or "spf=softfail" in auth_blob:
            score += 30
            findings.append(Finding(
                category="Email Authentication",
                severity=RiskLevel.HIGH,
                title="SPF Authentication Failure",
                description="The sending server is not authorized by the domain's SPF policy, indicating sender address spoofing.",
                indicator="SPF fail/softfail",
                remediation="High likelihood of unauthorized email spoofing."
            ))

        if "dkim=fail" in auth_blob:
            score += 30
            findings.append(Finding(
                category="Email Authentication",
                severity=RiskLevel.HIGH,
                title="DKIM Signature Verification Failed",
                description="The cryptographic signature on this email is invalid or has been modified in transit.",
                indicator="DKIM fail",
                remediation="The message integrity could not be verified."
            ))

        # 5. Urgency & Psychological Coercion in Subject/Body
        content_to_check = f"{subject} \n {body}".lower()
        for pattern, weight, title in URGENCY_PATTERNS:
            match = re.search(pattern, content_to_check, re.IGNORECASE)
            if match:
                score += weight
                findings.append(Finding(
                    category="Social Engineering",
                    severity=RiskLevel.MEDIUM if weight < 25 else RiskLevel.HIGH,
                    title=title,
                    description=f"Detected high-pressure social engineering phrase: '{match.group(0)}'.",
                    indicator=match.group(0),
                    remediation="Scammers create artificial urgency to prevent you from calmly evaluating requests."
                ))

        # 6. Generic Greeting on Account Notice
        for greeting_pat in GENERIC_GREETINGS:
            if re.search(greeting_pat, content_to_check):
                for brand in HIGH_VALUE_BRANDS:
                    if brand in content_to_check:
                        score += 15
                        findings.append(Finding(
                            category="Social Engineering",
                            severity=RiskLevel.LOW,
                            title="Impersonal Generic Greeting",
                            description="Real financial/service platforms address account holders by their real name, not generic greetings.",
                            indicator=greeting_pat,
                            remediation="Verify if the sender knows your account profile name."
                        ))
                        break
                break

        # 7. Dangerous Attachments
        for att in attachments:
            clean_att = att.strip().lower()
            ext = clean_att.split('.')[-1] if '.' in clean_att else ""

            # Double extension trick e.g. statement.pdf.exe
            if clean_att.count('.') >= 2:
                parts = clean_att.split('.')
                if parts[-1] in DANGEROUS_EXTENSIONS:
                    score += 55
                    findings.append(Finding(
                        category="Malware Attachment",
                        severity=RiskLevel.CRITICAL,
                        title=f"Disguised Double-Extension Attachment: {att}",
                        description=f"Attachment '{att}' uses double extension to masquerade malware as a document.",
                        indicator=att,
                        remediation="DO NOT OPEN OR DOWNLOAD THIS FILE."
                    ))
                    continue

            if ext in DANGEROUS_EXTENSIONS:
                score += 45
                findings.append(Finding(
                    category="Malware Attachment",
                    severity=RiskLevel.HIGH,
                    title=f"High-Risk Executable/Script Attachment ({ext.upper()})",
                    description=f"Email contains file '{att}' with dangerous file extension .{ext}.",
                    indicator=att,
                    remediation="Never run executable files received via email."
                ))

        # 8. Embedded Links & Anchor Text Spoofing
        # Check HTML anchors: <a href="REAL_URL">DISPLAY_URL</a>
        html_anchors = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', body, re.IGNORECASE)
        for href, anchor_text in html_anchors:
            # Check if anchor text looks like a URL but points elsewhere
            anchor_clean = re.sub(r'<[^>]+>', '', anchor_text).strip()
            if re.match(r'https?://', anchor_clean, re.IGNORECASE):
                href_domain = urlparse(href).netloc.lower()
                anchor_domain = urlparse(anchor_clean).netloc.lower()
                if href_domain and anchor_domain and href_domain != anchor_domain:
                    score += 60
                    findings.append(Finding(
                        category="Deceptive Link",
                        severity=RiskLevel.CRITICAL,
                        title="Deceptive Anchor Link Mismatch (Phishing Trap)",
                        description=f"Text displays trusted destination '{anchor_clean}' but actual click navigates to '{href}'.",
                        indicator=f"Displayed: {anchor_clean} -> Destination: {href}",
                        remediation="This is a confirmed phishing technique. Do not click."
                    ))

        # Extract all URLs and run through URLAnalyzer
        extracted_urls = set(re.findall(r'https?://[^\s<>"\'\)]+', body))
        for url in list(extracted_urls)[:5]:  # Analyze up to top 5 URLs to keep analysis fast
            url_rep = self.url_analyzer.analyze(url)
            if url_rep.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                score += (35 if url_rep.overall_risk == RiskLevel.HIGH else 50)
                findings.append(Finding(
                    category="Phishing Link",
                    severity=url_rep.overall_risk,
                    title=f"Embedded Dangerous Link ({url_rep.overall_risk.value})",
                    description=f"Email links to suspicious website '{url}': {url_rep.summary}",
                    indicator=url,
                    remediation="Do not open links inside this email."
                ))

        score = min(score, 100)
        overall_risk = calculate_risk(score)

        summary_map = {
            RiskLevel.SAFE: "Email headers and content appear normal. No signs of spoofing or phishing detected.",
            RiskLevel.LOW: "Low threat. Contains mild urgency or generic phrasing, but no explicit malicious payload.",
            RiskLevel.MEDIUM: "Suspicious indicators found. Exercise caution before replying or clicking links.",
            RiskLevel.HIGH: "HIGH PHISHING RISK: Strong evidence of sender deception, social engineering, or risky links.",
            RiskLevel.CRITICAL: "CRITICAL THREAT: Confirmed phishing attack, credential theft attempt, or malware attachment."
        }

        recommended_actions = []
        if overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            recommended_actions.extend([
                "Mark email as phishing/junk in your email client.",
                "Do NOT click any links, open attachments, or reply.",
                "Report this email to your organization's IT security team or abuse reporting address."
            ])
        elif overall_risk == RiskLevel.MEDIUM:
            recommended_actions.append("Contact the sender through an independent, verified phone number or website.")
        else:
            recommended_actions.append("Safe to review, keep security hygiene active.")

        return ThreatReport(
            target=sender or subject or "Raw Email",
            target_type="email",
            overall_risk=overall_risk,
            risk_score=score,
            summary=summary_map[overall_risk],
            findings=findings,
            metadata={
                "sender": sender,
                "sender_domain": sender_domain,
                "reply_to": reply_to,
                "subject": subject,
                "attachment_count": len(attachments),
                "embedded_urls_found": len(extracted_urls)
            },
            recommended_actions=recommended_actions
        )
