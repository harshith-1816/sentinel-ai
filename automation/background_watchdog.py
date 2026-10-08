"""
Sentinel AI - Automated Background Watchdog
Continuously monitors clipboard and system events for harmful URLs, fake emails,
and dangerous payloads, immediately popping up on-screen warnings.
"""
import time
import threading
import re
from typing import Optional

from core.threat_scorer import RiskLevel
from core.url_analyzer import URLAnalyzer
from core.email_analyzer import EmailAnalyzer
from automation.screen_notifier import trigger_screen_alert

url_analyzer = URLAnalyzer(check_live_status=False)
email_analyzer = EmailAnalyzer()


class ClipboardGuard:
    def __init__(self, check_interval: float = 1.0):
        self.check_interval = check_interval
        self._running = False
        self._last_content = ""
        self._thread: Optional[threading.Thread] = None

    def _get_clipboard_text(self) -> str:
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            text = root.clipboard_get()
            root.destroy()
            return text.strip()
        except Exception:
            return ""

    def _process_content(self, text: str):
        if not text or text == self._last_content:
            return
        self._last_content = text

        # Check if text is a URL
        url_match = re.search(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
        if url_match:
            candidate_url = url_match.group(0)
            rep = url_analyzer.analyze(candidate_url)
            if rep.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                indicators = [f.title for f in rep.findings[:3]]
                trigger_screen_alert(
                    title="HARMFUL LINK COPIED",
                    threat_type="Phishing URL",
                    target=candidate_url,
                    risk_level=rep.overall_risk.value,
                    summary=f"You just copied a harmful link! {rep.summary}",
                    indicators=indicators,
                    async_mode=True
                )
            return

        # Check if text resembles an email message or security alert
        lower = text.lower()
        if any(term in lower for term in ["urgent", "account suspended", "verify your account", "wire transfer", "unauthorized activity"]):
            rep = email_analyzer.analyze_structured(body=text)
            if rep.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                indicators = [f.title for f in rep.findings[:3]]
                trigger_screen_alert(
                    title="HARMFUL PHISHING TEXT COPIED",
                    threat_type="Phishing / Scam Email",
                    target=text[:60] + "...",
                    risk_level=rep.overall_risk.value,
                    summary=f"Suspicious fraudulent message detected in clipboard! {rep.summary}",
                    indicators=indicators,
                    async_mode=True
                )

    def start(self):
        if self._running:
            return
        self._running = True

        def loop():
            while self._running:
                try:
                    text = self._get_clipboard_text()
                    if text:
                        self._process_content(text)
                except Exception:
                    pass
                time.sleep(self.check_interval)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False


# Global singleton instance
clipboard_guard = ClipboardGuard()


def start_automation_guard():
    clipboard_guard.start()
    print("[+] Sentinel AI Real-Time Screen Alert Automation is ACTIVE.")


if __name__ == "__main__":
    start_automation_guard()
    print("[*] Running clipboard protection loop. Copy a fake URL like 'http://paypa1-security.xyz' to test on-screen alert.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        clipboard_guard.stop()
        print("\n[-] Automation stopped.")
