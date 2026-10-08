"""
Sentinel AI - Automation & Screen Alert Package
"""
from automation.screen_notifier import trigger_screen_alert, show_onscreen_alert_window
from automation.background_watchdog import start_automation_guard, clipboard_guard

__all__ = [
    "trigger_screen_alert",
    "show_onscreen_alert_window",
    "start_automation_guard",
    "clipboard_guard"
]
