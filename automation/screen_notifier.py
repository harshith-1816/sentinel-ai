"""
Sentinel AI - Windows On-Screen Threat Alert Notifier
Pops up an unmissable, on-top-of-all-windows warning overlay on the user's laptop screen
whenever harmful websites, fake emails, or phone trojans are detected.
"""
import sys
import threading
import tkinter as tk
from tkinter import ttk
from typing import Optional

try:
    import winsound
except ImportError:
    winsound = None


def play_threat_alert_sound():
    if winsound:
        try:
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:
            pass


def show_onscreen_alert_window(
    title: str,
    threat_type: str,
    target: str,
    risk_level: str,
    summary: str,
    indicators: Optional[list] = None
):
    """
    Spawns an attention-grabbing topmost window on the user's laptop screen.
    """
    root = tk.Tk()
    root.title(f"SENTINEL AI: {title}")
    root.geometry("520x360")
    root.resizable(False, False)
    root.configure(bg="#0F172A")

    # Keep on top of all other windows (browsers, apps, games)
    root.attributes("-topmost", True)

    # Header Frame
    header_frame = tk.Frame(root, bg="#EF4444", height=50)
    header_frame.pack(fill=tk.X)

    header_lbl = tk.Label(
        header_frame,
        text="⚠️ HARMFUL THREAT DETECTED!",
        font=("Segoe UI", 14, "bold"),
        fg="#FFFFFF",
        bg="#EF4444",
        pady=10
    )
    header_lbl.pack()

    # Content Frame
    content_frame = tk.Frame(root, bg="#0F172A", padx=20, pady=15)
    content_frame.pack(fill=tk.BOTH, expand=True)

    # Risk Badge Line
    badge_lbl = tk.Label(
        content_frame,
        text=f"STATUS: {risk_level} • TYPE: {threat_type.upper()}",
        font=("Segoe UI", 10, "bold"),
        fg="#EF4444",
        bg="#0F172A"
    )
    badge_lbl.pack(anchor="w")

    # Target Label
    target_lbl = tk.Label(
        content_frame,
        text=f"Target: {target}",
        font=("Segoe UI", 11, "bold"),
        fg="#F8FAFC",
        bg="#0F172A",
        wraplength=480,
        justify="left"
    )
    target_lbl.pack(anchor="w", pady=(8, 4))

    # Summary Text Box
    summary_txt = tk.Text(
        content_frame,
        height=5,
        wrap="word",
        font=("Segoe UI", 9),
        fg="#CBD5E1",
        bg="#1E293B",
        bd=0,
        padx=10,
        pady=8
    )
    summary_txt.insert(
        tk.END,
        f"{summary}\n\n"
        f"Key Indicators: {', '.join(indicators) if indicators else 'Deceptive patterns detected.'}\n\n"
        f"Recommendation: DO NOT ENTER CREDENTIALS OR OPEN ATTACHMENTS."
    )
    summary_txt.config(state="disabled")
    summary_txt.pack(fill=tk.BOTH, expand=True, pady=8)

    # Button Frame
    btn_frame = tk.Frame(content_frame, bg="#0F172A")
    btn_frame.pack(fill=tk.X, pady=(6, 0))

    dismiss_btn = tk.Button(
        btn_frame,
        text="🛡️ Block & Dismiss Alert",
        font=("Segoe UI", 10, "bold"),
        bg="#06B6D4",
        fg="#FFFFFF",
        activebackground="#0891B2",
        activeforeground="#FFFFFF",
        bd=0,
        padx=16,
        pady=8,
        cursor="hand2",
        command=root.destroy
    )
    dismiss_btn.pack(side=tk.RIGHT)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"+{x}+{y}")

    play_threat_alert_sound()
    root.mainloop()


def trigger_screen_alert(
    title: str = "HARMFUL THREAT DETECTED",
    threat_type: str = "security",
    target: str = "Unknown",
    risk_level: str = "CRITICAL",
    summary: str = "Dangerous deception or authorization anomaly detected.",
    indicators: Optional[list] = None,
    async_mode: bool = True
):
    """
    Triggers an on-screen alert. If async_mode is True, runs in a daemon thread so it doesn't block.
    """
    if async_mode:
        t = threading.Thread(
            target=show_onscreen_alert_window,
            args=(title, threat_type, target, risk_level, summary, indicators),
            daemon=True
        )
        t.start()
        return t
    else:
        show_onscreen_alert_window(title, threat_type, target, risk_level, summary, indicators)


if __name__ == "__main__":
    # Test alert popup directly
    trigger_screen_alert(
        title="MALICIOUS PHISHING SITE",
        threat_type="Phishing URL",
        target="http://paypa1-security-verification.xyz/login",
        risk_level="CRITICAL",
        summary="This website closely mimics PayPal to steal passwords and financial credentials.",
        indicators=["Typosquatting", "High-Risk TLD (.xyz)", "Deceptive Login Path"],
        async_mode=False
    )
