"""
Sentinel AI - Mobile Device Live ADB Auditor
Connects to an Android phone over USB or WiFi (via ADB) and audits all installed apps.
"""
import sys
import os
import subprocess
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rich.console import Console
from core.mobile_auditor import MobileAuditor, AppInfo
from cli.main import print_device_report

console = Console()


def scan_connected_device():
    console.print("[bold cyan][*] Connecting to Android device via ADB...[/bold cyan]")
    try:
        # Check connected devices
        devices_out = subprocess.check_output(["adb", "devices"], stderr=subprocess.STDOUT, text=True)
        lines = [line.strip() for line in devices_out.splitlines() if line.strip()]
        connected = [l for l in lines[1:] if "\tdevice" in l]

        if not connected:
            console.print("[bold yellow][!] No active Android device detected.[/bold yellow]")
            console.print("    To audit your phone live:")
            console.print("    1. Enable 'Developer Options' on your phone (tap 'Build Number' 7 times).")
            console.print("    2. Turn ON 'USB Debugging'.")
            console.print("    3. Connect your phone via USB cable and allow debugging when prompted.")
            return

        device_serial = connected[0].split("\t")[0]
        console.print(f"[bold green][+] Connected to device: {device_serial}[/bold green]")

        # Get list of installed non-system apps
        console.print("[dim]Querying third-party installed packages...[/dim]")
        pkg_output = subprocess.check_output(
            ["adb", "-s", device_serial, "shell", "pm", "list", "packages", "-3"],
            text=True
        )
        package_names = [
            line.replace("package:", "").strip()
            for line in pkg_output.splitlines()
            if line.startswith("package:")
        ]

        console.print(f"[cyan][*] Found {len(package_names)} third-party apps. Auditing permissions...[/cyan]")

        audited_apps = []
        for pkg in package_names:
            try:
                dump = subprocess.check_output(
                    ["adb", "-s", device_serial, "shell", "dumpsys", "package", pkg],
                    text=True,
                    stderr=subprocess.DEVNULL
                )
                permissions = []
                for line in dump.splitlines():
                    clean_line = line.strip()
                    if "android.permission." in clean_line:
                        # Extract permission token
                        parts = clean_line.split(":")
                        perm_token = parts[0].strip().split()[0].replace(",", "")
                        if perm_token.startswith("android.permission."):
                            permissions.append(perm_token)

                audited_apps.append(AppInfo(
                    package_name=pkg,
                    app_name=pkg.split(".")[-1].capitalize(),
                    category="utility",
                    is_system_app=False,
                    permissions=list(set(permissions))
                ))
            except Exception:
                continue

        auditor = MobileAuditor()
        report = auditor.audit_device(audited_apps, device_id=f"Android Device ({device_serial})")
        print_device_report(report)

    except FileNotFoundError:
        console.print("[bold red][X] ADB tool is not installed or not in PATH.[/bold red]")
        console.print("    Download Android Platform Tools or run Sentinel CLI with --file to scan offline manifests.")
    except Exception as e:
        console.print(f"[bold red][X] An error occurred while auditing mobile device: {e}[/bold red]")


if __name__ == "__main__":
    scan_connected_device()
