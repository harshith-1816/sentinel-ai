"""
Sentinel AI - Interactive Security CLI
Command-line interface with rich visuals for threat detection on emails, URLs, and mobile apps.
"""
import sys
import os
import json
import argparse
import subprocess
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.threat_scorer import ThreatReport, RiskLevel
from core.url_analyzer import URLAnalyzer
from core.email_analyzer import EmailAnalyzer
from core.mobile_auditor import MobileAuditor, AppInfo, DeviceAuditReport

console = Console()


def get_risk_style(risk: RiskLevel) -> str:
    if risk == RiskLevel.CRITICAL:
        return "bold red"
    elif risk == RiskLevel.HIGH:
        return "bold dark_orange"
    elif risk == RiskLevel.MEDIUM:
        return "bold yellow"
    elif risk == RiskLevel.LOW:
        return "bold blue"
    return "bold green"


def print_report(report: ThreatReport):
    style = get_risk_style(report.overall_risk)

    # Header Panel
    header_text = Text()
    header_text.append(f"TARGET: ", style="bold")
    header_text.append(f"{report.target}\n", style="white")
    header_text.append(f"TYPE: ", style="bold")
    header_text.append(f"{report.target_type.upper()}\n", style="cyan")
    header_text.append(f"RISK LEVEL: ", style="bold")
    header_text.append(f"[{report.overall_risk.value}] (Score: {report.risk_score}/100)\n\n", style=style)
    header_text.append(f"SUMMARY:\n", style="bold")
    header_text.append(f"{report.summary}\n", style="italic")

    console.print(Panel(header_text, title="[bold cyan]SENTINEL AI THREAT EVALUATION[/bold cyan]", border_style=style))

    # Findings Table
    if report.findings:
        table = Table(title="[bold yellow]DETECTED THREAT INDICATORS[/bold yellow]", border_style="dim")
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Category", style="cyan", width=18)
        table.add_column("Indicator / Flag", style="white", width=25)
        table.add_column("Technical Details & Remediation", style="dim", width=45)

        for f in report.findings:
            f_style = get_risk_style(f.severity)
            remedy_text = f"{f.description}\n[bold]Fix:[/bold] {f.remediation or 'N/A'}"
            table.add_row(
                Text(f.severity.value, style=f_style),
                f.category,
                f.indicator or f.title,
                remedy_text
            )
        console.print(table)
    else:
        console.print("[bold green][+][/bold green] No threat indicators detected.")

    # Recommended Actions
    if report.recommended_actions:
        console.print("\n[bold cyan]RECOMMENDED ACTIONS:[/bold cyan]")
        for action in report.recommended_actions:
            console.print(f"  • {action}")
    console.print("")


def print_device_report(report: DeviceAuditReport):
    style = get_risk_style(report.overall_device_posture)
    console.print(Panel(
        f"[bold]DEVICE:[/bold] {report.device_id}\n"
        f"[bold]TOTAL APPS SCANNED:[/bold] {report.total_apps_scanned}\n"
        f"[bold]AT-RISK APPS:[/bold] {report.apps_at_risk_count}\n"
        f"[bold]OVERALL POSTURE:[/bold] [{report.overall_device_posture.value}]\n\n"
        f"[italic]{report.summary}[/italic]",
        title="[bold cyan]MOBILE DEVICE AUDIT REPORT[/bold cyan]",
        border_style=style
    ))

    if report.critical_threats:
        console.print("\n[bold red]CRITICAL THREAT APPS (TROJANS / SPYWARE):[/bold red]")
        for rep in report.critical_threats:
            print_report(rep)

    if report.high_threats:
        console.print("\n[bold dark_orange]HIGH RISK APPS (UNASSESSED DANGEROUS PERMISSIONS):[/bold dark_orange]")
        for rep in report.high_threats:
            print_report(rep)

    if report.medium_threats:
        console.print(f"\n[yellow]MODERATE RISK APPS ({len(report.medium_threats)} apps flagged):[/yellow]")
        for rep in report.medium_threats:
            console.print(f"  - [yellow]{rep.target}[/yellow] (Score: {rep.risk_score}): {rep.summary}")

    console.print("\n[bold cyan]ACTIONABLE REMEDIATION FOR PHONE:[/bold cyan]")
    for r in report.remedial_steps:
        console.print(f"  • {r}")


def run_adb_audit():
    console.print("[cyan][*] Attempting to connect to attached Android device via ADB...[/cyan]")
    try:
        devices_out = subprocess.check_output(["adb", "devices"], stderr=subprocess.STDOUT, text=True)
        if "device\n" not in devices_out and "\tdevice" not in devices_out:
            console.print("[yellow][!] No Android device found via ADB. Ensure USB debugging is enabled on phone.[/yellow]")
            return

        console.print("[green][+] Android device detected! Querying package permissions...[/green]")
        pkg_out = subprocess.check_output(["adb", "shell", "pm", "list", "packages", "-3"], text=True)
        packages = [p.replace("package:", "").strip() for p in pkg_out.splitlines() if p.strip()]

        apps_to_audit = []
        for pkg in packages[:20]:  # Audit up to first 20 third-party packages for responsiveness
            dumpsys = subprocess.check_output(["adb", "shell", "dumpsys", "package", pkg], text=True)
            perms = []
            for line in dumpsys.splitlines():
                if "android.permission." in line:
                    perm_name = line.strip().split(":")[0].split(" ")[0].strip()
                    perms.append(perm_name)
            apps_to_audit.append(AppInfo(package_name=pkg, app_name=pkg, permissions=list(set(perms))))

        auditor = MobileAuditor()
        report = auditor.audit_device(apps_to_audit, device_id="Connected Android Device")
        print_device_report(report)

    except FileNotFoundError:
        console.print("[red][X] 'adb' command not found in PATH. Install Android Platform Tools to enable live USB audit.[/red]")
    except Exception as e:
        console.print(f"[red][X] Error during ADB execution: {e}[/red]")


def run_demo():
    console.print(Panel.fit(
        "[bold cyan]SENTINEL AI: THREAT DETECTION SIMULATION & AUDIT DEMO[/bold cyan]\n"
        "[dim]Demonstrating real-world Phishing Emails, Spoofed Domains, and Trojan Permissions[/dim]",
        border_style="cyan"
    ))

    # 1. URL Analysis Demo
    console.print("\n[bold yellow]=== 1. SCANNING SUSPICIOUS URLS ===[/bold yellow]")
    url_analyzer = URLAnalyzer()
    demo_urls = [
        "https://www.paypal.com/signin",
        "http://paypa1-security-verification.xyz/login/verify-identity",
        "http://185.220.101.5/banking-update/suspended-account"
    ]
    for url in demo_urls:
        report = url_analyzer.analyze(url)
        print_report(report)

    # 2. Email Analysis Demo
    console.print("\n[bold yellow]=== 2. SCANNING SUSPICIOUS EMAIL ===[/bold yellow]")
    email_analyzer = EmailAnalyzer()
    suspicious_email = {
        "sender": "PayPal Support Team <account-alert891@gmail.com>",
        "reply_to": "attacker-collector@shadowmail.xyz",
        "subject": "CRITICAL NOTICE: Your account has been suspended within 24 hours",
        "body": """Dear Customer,
We detected unauthorized activity on your account.
Immediate action required: You must confirm your wallet and verify your identity within 24 hours or your balance will be permanently locked.

Click below to verify:
<a href="http://paypa1-security-update.xyz/login">https://www.paypal.com/verify</a>

Regards,
Security Department
""",
        "attachments": ["account_statement.pdf.exe"]
    }
    email_report = email_analyzer.analyze_structured(
        sender=suspicious_email["sender"],
        reply_to=suspicious_email["reply_to"],
        subject=suspicious_email["subject"],
        body=suspicious_email["body"],
        attachments=suspicious_email["attachments"]
    )
    print_report(email_report)

    # 3. Mobile Device Audit Demo
    console.print("\n[bold yellow]=== 3. AUDITING MOBILE APP AUTHORIZATIONS ===[/bold yellow]")
    auditor = MobileAuditor()
    sample_apps = [
        AppInfo(
            package_name="com.google.android.calculator",
            app_name="Google Calculator",
            category="calculator",
            is_system_app=True,
            permissions=["android.permission.VIBRATE"]
        ),
        AppInfo(
            package_name="com.bright.superflashlight.pro",
            app_name="Super Flashlight Ultra",
            category="flashlight",
            is_system_app=False,
            permissions=[
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_SMS",
                "android.permission.ACCESS_BACKGROUND_LOCATION"
            ]
        ),
        AppInfo(
            package_name="com.fastupdate.systemservice",
            app_name="System Update Helper",
            category="utility",
            is_system_app=False,
            permissions=[
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.QUERY_ALL_PACKAGES"
            ]
        )
    ]
    device_report = auditor.audit_device(sample_apps, device_id="Demo Pixel Phone")
    print_device_report(device_report)


def main():
    parser = argparse.ArgumentParser(description="Sentinel AI - Cyber Threat & Mobile Security Engine")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan-url
    url_p = subparsers.add_parser("scan-url", help="Analyze URL or web application for threats")
    url_p.add_argument("url", help="URL to scan")
    url_p.add_argument("--live", action="store_true", help="Probe live SSL and redirect chains")

    # scan-email
    email_p = subparsers.add_parser("scan-email", help="Analyze email headers and content for phishing")
    email_p.add_argument("--file", help="Path to raw email (.eml or text file)")
    email_p.add_argument("--sender", help="Sender email address")
    email_p.add_argument("--subject", help="Email subject line")
    email_p.add_argument("--body", help="Email body text")

    # audit-mobile
    mobile_p = subparsers.add_parser("audit-mobile", help="Audit mobile application permissions")
    mobile_p.add_argument("--file", help="Path to JSON file containing app list")
    mobile_p.add_argument("--adb", action="store_true", help="Audit connected Android device via ADB")

    # serve
    serve_p = subparsers.add_parser("serve", help="Run the FastAPI REST API server")
    serve_p.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    serve_p.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")

    # demo
    subparsers.add_parser("demo", help="Run demonstration across all threat vectors")

    args = parser.parse_args()

    if args.command == "scan-url":
        analyzer = URLAnalyzer(check_live_status=args.live)
        rep = analyzer.analyze(args.url)
        print_report(rep)

    elif args.command == "scan-email":
        analyzer = EmailAnalyzer()
        if args.file:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            rep = analyzer.analyze_raw(content)
        else:
            rep = analyzer.analyze_structured(
                sender=args.sender or "",
                subject=args.subject or "",
                body=args.body or ""
            )
        print_report(rep)

    elif args.command == "audit-mobile":
        if args.adb:
            run_adb_audit()
        elif args.file:
            with open(args.file, "r", encoding="utf-8") as f:
                data = json.load(f)
            apps = [AppInfo(**item) for item in data]
            auditor = MobileAuditor()
            rep = auditor.audit_device(apps)
            print_device_report(rep)
        else:
            console.print("[yellow]Specify --file <manifest.json> or --adb to audit a connected phone.[/yellow]")

    elif args.command == "serve":
        import uvicorn
        console.print(f"[bold green]Starting Sentinel AI REST API at http://{args.host}:{args.port}[/bold green]")
        uvicorn.run("api.app:app", host=args.host, port=args.port, reload=True)

    elif args.command == "demo":
        run_demo()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
