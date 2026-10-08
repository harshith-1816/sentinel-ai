# Sentinel Mobile Shield (Android Native App)

The native Android companion app for Sentinel AI, built with **Kotlin** and **Jetpack Compose**.

## Features

1. **Automated On-Device App & Authorization Audit**:
   - Inspects all third-party apps installed on the phone.
   - Detects dangerous authorizations: Accessibility God-Mode, Draw Over Apps (Overlay), Background Location, Silent SMS, Audio recording, Dropper APK installers.
2. **Trojan & Spyware Combination Detection**:
   - Banking Trojan Combo: `ACCESSIBILITY + OVERLAY + SMS`
   - Stalkerware / Spyware Combo: `MICROPHONE + CAMERA + LOCATION + CONTACTS`
   - Dropper Combo: `REQUEST_INSTALL_PACKAGES + OVERLAY/ACCESSIBILITY`
   - Unassessed Authorizations: Utility apps (flashlight, calculator, wallpaper) requesting private SMS/Contacts.
3. **One-Tap Fix & Remediation**:
   - Deep links directly into Android system settings to revoke permissions or trigger uninstallation dialog.
4. **Phishing & Web App Shield**:
   - Fast URL scanner to verify links received in SMS or WhatsApp before tapping them.

---

## How to Open and Run in Android Studio

1. Open **Android Studio**.
2. Click **Open** and select:
   `C:\Users\DELL\.gemini\antigravity\scratch\sentinel-ai\android-app`
3. Wait for Gradle sync to complete.
4. Connect an Android phone via USB (with **USB Debugging** enabled) or launch an Android Virtual Device (AVD).
5. Click the green **Run** button (or press `Shift + F10`).
