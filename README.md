# Sentinel AI: Cyber Threat & Mobile Security Engine

Sentinel AI is an automated AI and heuristic cyber defense system designed to protect against:
1. **Phishing & Fraudulent Emails**: Sender spoofing, display name tricks, reply-to traps, urgency manipulation, malicious double extensions (`.pdf.exe`), and deceptive links.
2. **Deceptive & Unauthorized Websites/Web Apps**: Typosquatting against major brands (`paypa1`, `g00gle`, `chase-security`), homoglyphs, numeric IP hosts, excessive subdomains, and malicious TLDs.
3. **Mobile Malware & Unassessed Permissions**: Detects rogue mobile app authorizations, banking overlay trojans (`Accessibility` + `Draw Over Apps`), background stalkerware/spyware, and permission anomalies.

---

## Architecture Roadmap

- **Phase 1 (Completed)**: Core AI Detection Engine, Python REST API (FastAPI), Rich Interactive CLI, and automated test suite.
- **Phase 2 (Ready for Mobile)**: Android On-Device Permission Scanner (`AndroidPermissionScanner.kt`) and live USB ADB auditor (`adb_quick_scan.py`).
- **Phase 3**: Unified Full-Stack Security Hub & Real-Time Dashboard.

---

## Directory Structure

```
sentinel-ai/
├── core/
│   ├── threat_scorer.py       # Risk scoring models (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
│   ├── url_analyzer.py        # Typosquatting, homoglyph & web deception detection
│   ├── email_analyzer.py      # Phishing, spoofing & social engineering heuristics
│   └── mobile_auditor.py      # Android banking trojans, stalkerware & permission auditing
├── api/
│   └── app.py                 # FastAPI REST Service
├── cli/
│   └── main.py                # Rich CLI tool
├── mobile/
│   ├── adb_quick_scan.py      # Live USB Android permission auditor via ADB
│   └── AndroidPermissionScanner.kt # Native Android Kotlin scanner
├── tests/
│   ├── test_analyzers.py      # Unit test suite
│   └── sample_device_dump.json# Sample exported mobile app manifest
├── requirements.txt
└── README.md
```

---

## Quick Start & Usage

### 1. Run the Interactive Simulation Demo
```bash
python -m cli.main demo
```

### 2. Scan a Suspicious Website / Web App
```bash
python -m cli.main scan-url "http://paypa1-security-verification.xyz/login"
```

### 3. Scan a Suspicious Email
```bash
python -m cli.main scan-email --sender "security@fake-support.com" --subject "Urgent: Account locked" --body "Verify your account at http://fake.com"
```
Or scan raw `.eml` files:
```bash
python -m cli.main scan-email --file /path/to/email.eml
```

### 4. Audit Mobile Apps & Permissions
Audit an exported JSON manifest:
```bash
python -m cli.main audit-mobile --file tests/sample_device_dump.json
```
Or audit a live connected phone via ADB:
```bash
python -m cli.main audit-mobile --adb
# or
python mobile/adb_quick_scan.py
```

### 5. Launch the Full-Stack Security Hub (Web Dashboard & Automated Screen Alerts)
```bash
python -m cli.main serve --port 8000
```
Open your browser to:
👉 **`http://127.0.0.1:8000`** (Interactive Web Dashboard with Mobile Simulator & Live Scanners)
👉 **`http://127.0.0.1:8000/docs`** (Interactive OpenAPI Docs)

### 6. Run the Standalone Background Clipboard & Screen Alert Watchdog
Whenever you copy a malicious URL or phishing email, a topmost red alert window pops up on your Windows screen!
```bash
python -m automation.background_watchdog
```

### 7. Run Automated Tests
```bash
python -m unittest tests/test_analyzers.py
```
