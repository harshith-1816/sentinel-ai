// Sentinel AI - Full-Stack Hub Controller
document.addEventListener("DOMContentLoaded", () => {
  // Tab switching
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      tab.classList.add("active");
      const target = document.getElementById(tab.dataset.target);
      if (target) target.classList.add("active");
    });
  });

  // URL Scanner
  const scanUrlBtn = document.getElementById("scan-url-btn");
  if (scanUrlBtn) {
    scanUrlBtn.addEventListener("click", async () => {
      const url = document.getElementById("target-url").value.trim();
      const live = document.getElementById("check-live-ssl").checked;
      if (!url) return alert("Please enter a URL to scan.");

      scanUrlBtn.disabled = true;
      scanUrlBtn.innerText = "Analyzing...";

      try {
        const res = await fetch("/api/scan/url", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url, check_live: live, notify_screen: true })
        });
        const data = await res.json();
        renderThreatReport("url-result-box", data);
        loadIncidents();
      } catch (err) {
        alert("Scan failed: " + err);
      } finally {
        scanUrlBtn.disabled = false;
        scanUrlBtn.innerText = "Analyze URL";
      }
    });
  }

  // Email Scanner
  const scanEmailBtn = document.getElementById("scan-email-btn");
  if (scanEmailBtn) {
    scanEmailBtn.addEventListener("click", async () => {
      const sender = document.getElementById("email-sender").value.trim();
      const replyTo = document.getElementById("email-replyto").value.trim();
      const subject = document.getElementById("email-subject").value.trim();
      const body = document.getElementById("email-body").value.trim();
      const attRaw = document.getElementById("email-attachments").value.trim();
      const attachments = attRaw ? attRaw.split(",").map(s => s.trim()) : [];

      scanEmailBtn.disabled = true;
      scanEmailBtn.innerText = "Analyzing Phishing Vectors...";

      try {
        const res = await fetch("/api/scan/email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sender, reply_to: replyTo, subject, body, attachments, notify_screen: true })
        });
        const data = await res.json();
        renderThreatReport("email-result-box", data);
        loadIncidents();
      } catch (err) {
        alert("Analysis failed: " + err);
      } finally {
        scanEmailBtn.disabled = false;
        scanEmailBtn.innerText = "Analyze Email";
      }
    });
  }

  // Mobile Phone Simulator Scanner
  const scanPhoneBtn = document.getElementById("scan-phone-btn");
  if (scanPhoneBtn) {
    scanPhoneBtn.addEventListener("click", async () => {
      scanPhoneBtn.disabled = true;
      scanPhoneBtn.innerText = "Auditing Mobile Apps...";

      const demoApps = [
        {
          package_name: "com.google.android.calculator",
          app_name: "Calculator",
          category: "calculator",
          is_system_app: true,
          permissions: ["android.permission.VIBRATE"]
        },
        {
          package_name: "org.flashlight.superbright",
          app_name: "Flashlight Ultra",
          category: "flashlight",
          is_system_app: false,
          permissions: [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS"
          ]
        },
        {
          package_name: "com.bankupdate.trojanservice",
          app_name: "Security Update",
          category: "utility",
          is_system_app: false,
          permissions: [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_SMS",
            "android.permission.REQUEST_INSTALL_PACKAGES"
          ]
        }
      ];

      try {
        const res = await fetch("/api/audit/mobile-device", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ device_id: "Simulated Pixel Phone", apps: demoApps, notify_screen: true })
        });
        const data = await res.json();
        renderDeviceReport(data);
        loadIncidents();
      } catch (err) {
        alert("Phone audit failed: " + err);
      } finally {
        scanPhoneBtn.disabled = false;
        scanPhoneBtn.innerText = "Re-Audit Phone";
      }
    });
  }

  // Trigger On-Screen Alert Test Button
  const testAlertBtn = document.getElementById("test-onscreen-alert-btn");
  if (testAlertBtn) {
    testAlertBtn.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/automation/test-alert", { method: "POST" });
        const data = await res.json();
        console.log(data.message);
      } catch (err) {
        alert("Could not trigger screen alert: " + err);
      }
    });
  }

  // Initial load
  loadIncidents();
  setInterval(loadIncidents, 4000);
});

// Load Live Incidents
async function loadIncidents() {
  try {
    const res = await fetch("/api/incidents");
    const data = await res.json();
    const tableBody = document.getElementById("incidents-table-body");
    const statTotal = document.getElementById("stat-total");
    const statThreats = document.getElementById("stat-threats");

    if (!data.incidents || data.incidents.length === 0) {
      if (statTotal) statTotal.innerText = "0";
      if (statThreats) statThreats.innerText = "0";
      return;
    }

    if (statTotal) statTotal.innerText = data.incidents.length;
    const threatsCount = data.incidents.filter(i => i.risk === "CRITICAL" || i.risk === "HIGH").length;
    if (statThreats) statThreats.innerText = threatsCount;

    if (tableBody) {
      tableBody.innerHTML = data.incidents.map(inc => `
        <tr style="border-bottom: 1px solid rgba(51, 65, 85, 0.4);">
          <td style="padding: 0.75rem; color: #94A3B8;">${inc.timestamp}</td>
          <td style="padding: 0.75rem; font-weight: 600; color: #F8FAFC;">${inc.type}</td>
          <td style="padding: 0.75rem; font-family: monospace; color: #06B6D4;">${escapeHtml(inc.target)}</td>
          <td style="padding: 0.75rem;">
            <span style="background: ${getRiskColor(inc.risk)}; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold;">
              ${inc.risk}
            </span>
          </td>
          <td style="padding: 0.75rem; color: #CBD5E1; font-size: 0.8rem;">${escapeHtml(inc.summary)}</td>
        </tr>
      `).join("");
    }
  } catch (err) {
    console.error("Incident fetch error:", err);
  }
}

// Attack Simulators
async function simulateAttack(type) {
  if (type === "phishing_url") {
    // Jump to URL tab and scan
    document.querySelector('[data-target="tab-url"]').click();
    document.getElementById("target-url").value = "http://paypa1-security-verification.xyz/login/verify-identity";
    document.getElementById("scan-url-btn").click();
  } else if (type === "phishing_email") {
    // Jump to Email tab and scan
    document.querySelector('[data-target="tab-email"]').click();
    loadSampleEmail("phishing");
    document.getElementById("scan-email-btn").click();
  } else if (type === "mobile_trojan") {
    // Jump to Mobile tab and audit
    document.querySelector('[data-target="tab-mobile"]').click();
    document.getElementById("scan-phone-btn").click();
  }
}

// Render Threat Report
function renderThreatReport(containerId, report) {
  const box = document.getElementById(containerId);
  if (!box) return;

  const riskClass = report.overall_risk.toLowerCase();
  box.className = `result-box ${riskClass}`;

  const findingsHtml = report.findings.map(f => `
    <li class="finding-item">
      <div class="finding-title" style="color: ${getRiskColor(f.severity)}">
        [${f.severity}] ${escapeHtml(f.title)} (${escapeHtml(f.category)})
      </div>
      <div style="font-size: 0.82rem; color: #94A3B8; margin-bottom: 4px;">${escapeHtml(f.description)}</div>
      <div style="font-size: 0.8rem; color: #06B6D4;"><strong>Action:</strong> ${escapeHtml(f.remediation || "N/A")}</div>
    </li>
  `).join("");

  const actionsHtml = report.recommended_actions.map(a => `<li>• ${escapeHtml(a)}</li>`).join("");

  box.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <span class="score-badge" style="background: ${getRiskColor(report.overall_risk)}; color: #fff;">
        ${report.overall_risk} (Score: ${report.risk_score}/100)
      </span>
      <span style="font-size: 0.85rem; color: #94A3B8;">Target: <strong>${escapeHtml(report.target)}</strong></span>
    </div>
    <p style="font-weight: 600; font-size: 0.95rem; margin-bottom: 0.75rem;">${escapeHtml(report.summary)}</p>
    
    <div style="margin-top: 1rem;">
      <strong style="font-size: 0.85rem; color: #CBD5E1;">Key Threat Indicators (${report.findings.length}):</strong>
      <ul class="findings-list">${findingsHtml || "<li>No major threat indicators detected.</li>"}</ul>
    </div>

    ${report.recommended_actions.length ? `
      <div style="margin-top: 1rem; font-size: 0.85rem; color: #06B6D4;">
        <strong>Recommended Defense Actions:</strong>
        <ul style="list-style: none; margin-top: 4px;">${actionsHtml}</ul>
      </div>
    ` : ""}
  `;
}

// Render Phone Device Report into the simulator
function renderDeviceReport(report) {
  const phoneScreen = document.getElementById("phone-screen-content");
  if (!phoneScreen) return;

  const isDanger = report.critical_threats.length > 0 || report.high_threats.length > 0;
  const statusColor = isDanger ? "#EF4444" : "#10B981";

  let appsHtml = "";
  const allApps = [...report.critical_threats, ...report.high_threats, ...report.medium_threats, ...report.low_or_safe];

  allApps.forEach(app => {
    const isCritical = app.overall_risk === "CRITICAL";
    appsHtml += `
      <div style="background: #1E293B; border-radius: 8px; padding: 10px; margin-bottom: 8px; border-left: 4px solid ${getRiskColor(app.overall_risk)}">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="color: #F8FAFC;">${escapeHtml(app.target)}</strong>
          <span style="font-size: 0.75rem; color: ${getRiskColor(app.overall_risk)}; font-weight: bold;">${app.overall_risk}</span>
        </div>
        <p style="font-size: 0.75rem; color: #94A3B8; margin: 4px 0;">${escapeHtml(app.summary)}</p>
        ${isCritical ? `
          <button onclick="alert('Sent uninstall signal for ${escapeHtml(app.target)}')" style="background: #EF4444; border:none; color:white; border-radius: 4px; padding: 4px 8px; font-size: 0.75rem; font-weight: bold; cursor: pointer; margin-top: 4px;">
            Uninstall Now
          </button>
        ` : ""}
      </div>
    `;
  });

  phoneScreen.innerHTML = `
    <div style="text-align: center; margin-bottom: 12px; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 8px;">
      <div style="font-size: 1.1rem; font-weight: bold; color: ${statusColor};">
        ${isDanger ? "🚨 DEVICE COMPROMISED" : "🛡️ DEVICE PROTECTED"}
      </div>
      <div style="font-size: 0.75rem; color: #CBD5E1; margin-top: 4px;">
        ${report.critical_threats.length} Critical Trojans • ${report.high_threats.length} Dangerous Apps
      </div>
    </div>
    <div>${appsHtml}</div>
  `;
}

function getRiskColor(risk) {
  switch (risk) {
    case "CRITICAL": return "#EF4444";
    case "HIGH": return "#F97316";
    case "MEDIUM": return "#F59E0B";
    case "LOW": return "#3B82F6";
    default: return "#10B981";
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Preset Loaders
function loadSampleUrl(type) {
  const input = document.getElementById("target-url");
  if (type === "paypal") input.value = "http://paypa1-security-verification.xyz/login";
  else if (type === "ip") input.value = "http://185.220.101.5/banking-login";
  else if (type === "safe") input.value = "https://www.google.com";
}

function loadSampleEmail(type) {
  if (type === "phishing") {
    document.getElementById("email-sender").value = "PayPal Security <alert-desk992@gmail.com>";
    document.getElementById("email-replyto").value = "stealer@shadowmail.xyz";
    document.getElementById("email-subject").value = "URGENT: Your account has been suspended within 24 hours";
    document.getElementById("email-body").value = "Dear Customer,\nWe detected unauthorized logins. Verify your identity immediately or funds will be seized: http://paypa1-security-verification.xyz/login";
    document.getElementById("email-attachments").value = "invoice.pdf.exe";
  } else {
    document.getElementById("email-sender").value = "Alex Johnson <alex@techcorp.io>";
    document.getElementById("email-replyto").value = "";
    document.getElementById("email-subject").value = "Weekly sprint review notes";
    document.getElementById("email-body").value = "Hey team, here are the action items from our Monday standup.";
    document.getElementById("email-attachments").value = "sprint_notes.pdf";
  }
}
