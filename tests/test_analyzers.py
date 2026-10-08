"""
Sentinel AI - Automated Test Suite
Validates detection accuracy across Email, URL, and Mobile Permission threat vectors.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.threat_scorer import RiskLevel
from core.url_analyzer import URLAnalyzer
from core.email_analyzer import EmailAnalyzer
from core.mobile_auditor import MobileAuditor, AppInfo


class TestSentinelAI(unittest.TestCase):
    def setUp(self):
        self.url_analyzer = URLAnalyzer(check_live_status=False)
        self.email_analyzer = EmailAnalyzer()
        self.mobile_auditor = MobileAuditor()

    # --- URL TESTS ---
    def test_benign_url(self):
        rep = self.url_analyzer.analyze("https://www.google.com/search?q=cybersecurity")
        self.assertEqual(rep.overall_risk, RiskLevel.SAFE)
        self.assertLess(rep.risk_score, 20)

    def test_typosquatting_url(self):
        rep = self.url_analyzer.analyze("http://paypa1-security.xyz/login")
        self.assertIn(rep.overall_risk, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        categories = [f.category for f in rep.findings]
        self.assertTrue(any("Typosquatting" in c or "Brand Spoofing" in c for c in categories))

    def test_ip_host_url(self):
        rep = self.url_analyzer.analyze("http://192.168.1.100/admin-login")
        self.assertIn(rep.overall_risk, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        self.assertTrue(any(f.category == "IP Host" for f in rep.findings))

    # --- EMAIL TESTS ---
    def test_benign_email(self):
        rep = self.email_analyzer.analyze_structured(
            sender="Alice <alice@mycompany.com>",
            subject="Project status sync",
            body="Hey team, let's meet at 3 PM to review the quarterly milestones."
        )
        self.assertIn(rep.overall_risk, [RiskLevel.SAFE, RiskLevel.LOW])

    def test_phishing_email(self):
        rep = self.email_analyzer.analyze_structured(
            sender="PayPal Support <service@gmail.com>",
            reply_to="stealer@shadowmail.xyz",
            subject="URGENT: Your account has been suspended within 24 hours",
            body='Click here to confirm: <a href="http://paypa1-fake.xyz">https://www.paypal.com/signin</a>',
            attachments=["invoice.pdf.exe"]
        )
        self.assertEqual(rep.overall_risk, RiskLevel.CRITICAL)
        self.assertGreaterEqual(rep.risk_score, 80)
        categories = [f.category for f in rep.findings]
        self.assertIn("Malware Attachment", categories)
        self.assertIn("Deceptive Link", categories)
        self.assertIn("Reply-To Mismatch", categories)

    # --- MOBILE AUDITOR TESTS ---
    def test_benign_mobile_app(self):
        app = AppInfo(
            package_name="com.android.calculator2",
            app_name="Calculator",
            category="calculator",
            is_system_app=True,
            permissions=["android.permission.VIBRATE"]
        )
        rep = self.mobile_auditor.audit_app(app)
        self.assertEqual(rep.overall_risk, RiskLevel.SAFE)

    def test_unassessed_authorization_anomaly(self):
        # A flashlight app requesting contacts and SMS
        app = AppInfo(
            package_name="com.simple.flashlight",
            app_name="Bright Flashlight",
            category="flashlight",
            is_system_app=False,
            permissions=[
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_SMS"
            ]
        )
        rep = self.mobile_auditor.audit_app(app)
        self.assertIn(rep.overall_risk, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        self.assertTrue(any(f.category == "Authorization Anomaly" for f in rep.findings))

    def test_banking_trojan_overlay_combo(self):
        # App with accessibility + overlay + SMS theft
        app = AppInfo(
            package_name="com.battery.booster.fast",
            app_name="Battery Super Booster",
            category="utility",
            is_system_app=False,
            permissions=[
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_SMS",
                "android.permission.QUERY_ALL_PACKAGES"
            ]
        )
        rep = self.mobile_auditor.audit_app(app)
        self.assertEqual(rep.overall_risk, RiskLevel.CRITICAL)
        self.assertGreaterEqual(rep.risk_score, 90)
        self.assertTrue(any("Banking Trojan" in f.title for f in rep.findings))


if __name__ == "__main__":
    unittest.main()
