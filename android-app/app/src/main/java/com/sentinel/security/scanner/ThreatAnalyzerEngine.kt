package com.sentinel.security.scanner

import com.sentinel.security.model.AppThreatInfo
import com.sentinel.security.model.RiskLevel
import com.sentinel.security.model.ThreatFinding

class ThreatAnalyzerEngine {

    companion object {
        private val PERMISSION_WEIGHTS = mapOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE" to Pair(50, "Accessibility Service (God Mode) - Can read screen, keystrokes, and auto-tap."),
            "android.permission.SYSTEM_ALERT_WINDOW" to Pair(35, "Draw Over Apps (Overlay) - Can inject fake credential login screens."),
            "android.permission.BIND_DEVICE_ADMIN" to Pair(45, "Device Admin Rights - Can block uninstall, wipe data, or lock phone."),
            "android.permission.RECEIVE_SMS" to Pair(30, "Intercept Incoming SMS - Intercepts one-time banking passcodes (OTPs)."),
            "android.permission.READ_SMS" to Pair(30, "Read SMS History - Can extract past 2FA codes and private messages."),
            "android.permission.SEND_SMS" to Pair(30, "Send Premium SMS - Can silently trigger unwanted toll billing."),
            "android.permission.RECORD_AUDIO" to Pair(25, "Microphone Recording - Secret room and call audio surveillance."),
            "android.permission.CAMERA" to Pair(25, "Camera Capture - Secret background photo/video recording."),
            "android.permission.ACCESS_BACKGROUND_LOCATION" to Pair(30, "24/7 Background Location - Continuous physical movement tracking."),
            "android.permission.READ_CONTACTS" to Pair(20, "Harvest Contacts - Extracts address book for extortion/phishing."),
            "android.permission.READ_CALL_LOG" to Pair(25, "Read Call Log - Monitors call history and relationships."),
            "android.permission.REQUEST_INSTALL_PACKAGES" to Pair(35, "Install Unknown Apps - Dropper functionality to load extra malware.")
        )
    }

    fun analyzeApp(
        packageName: String,
        appName: String,
        isSystemApp: Boolean,
        permissions: List<String>,
        hasActiveAccessibility: Boolean,
        hasOverlayPermission: Boolean
    ): AppThreatInfo {
        val findings = mutableListOf<ThreatFinding>()
        var score = 0
        val permSet = permissions.toSet()

        // 1. Evaluate Individual Dangerous Permissions
        for ((perm, data) in PERMISSION_WEIGHTS) {
            val (baseWeight, threatDesc) = data
            if (permSet.contains(perm)) {
                val weight = if (isSystemApp) (baseWeight * 0.3).toInt() else baseWeight
                score += weight

                val sev = when {
                    weight >= 45 -> RiskLevel.CRITICAL
                    weight >= 30 -> RiskLevel.HIGH
                    else -> RiskLevel.MEDIUM
                }

                findings.add(
                    ThreatFinding(
                        category = "Dangerous Permission",
                        title = perm.substringAfterLast("."),
                        description = threatDesc,
                        indicator = perm,
                        severity = sev,
                        remediation = "Revoke in Phone Settings > Apps > $appName > Permissions."
                    )
                )
            }
        }

        // 2. MALICIOUS COMBINATION 1: Banking Trojan Overlay Architecture
        val hasAcc = permSet.contains("android.permission.BIND_ACCESSIBILITY_SERVICE") || hasActiveAccessibility
        val hasOverlay = permSet.contains("android.permission.SYSTEM_ALERT_WINDOW") || hasOverlayPermission
        val hasSms = permSet.contains("android.permission.RECEIVE_SMS") || permSet.contains("android.permission.READ_SMS")

        if (hasAcc && hasOverlay) {
            val comboExtra = if (isSystemApp) 15 else 40
            score += comboExtra
            findings.add(
                ThreatFinding(
                    category = "Malware Combo",
                    title = "Banking Trojan Overlay Signature",
                    description = "Pairs Accessibility Service with Draw-Over-Apps. Known attack vector used by trojans (Anatsa, SharkBot) to siphon banking credentials and OTPs.",
                    indicator = "ACCESSIBILITY + OVERLAY",
                    severity = RiskLevel.CRITICAL,
                    remediation = "UNINSTALL THIS APP IMMEDIATELY unless it is an official screen reader like Google TalkBack."
                )
            )
        }

        // 3. MALICIOUS COMBINATION 2: Covert Spyware / Stalkerware
        val hasAudio = permSet.contains("android.permission.RECORD_AUDIO")
        val hasCam = permSet.contains("android.permission.CAMERA")
        val hasLoc = permSet.contains("android.permission.ACCESS_BACKGROUND_LOCATION")
        val hasContacts = permSet.contains("android.permission.READ_CONTACTS")

        if (hasAudio && hasCam && (hasLoc || hasContacts)) {
            val comboExtra = if (isSystemApp) 10 else 35
            score += comboExtra
            findings.add(
                ThreatFinding(
                    category = "Malware Combo",
                    title = "Full Surveillance Spyware Vector",
                    description = "Holds concurrent microphone eavesdropping, camera access, and location/contact harvesting.",
                    indicator = "AUDIO + CAMERA + LOCATION/CONTACTS",
                    severity = RiskLevel.CRITICAL,
                    remediation = "Verify if you trust this application with continuous physical surveillance."
                )
            )
        }

        // 4. MALICIOUS COMBINATION 3: Dropper / Stealth Loader
        val hasInstall = permSet.contains("android.permission.REQUEST_INSTALL_PACKAGES")
        if (hasInstall && (hasOverlay || hasAcc)) {
            score += 30
            findings.add(
                ThreatFinding(
                    category = "Malware Combo",
                    title = "Dropper / Malicious Loader Vector",
                    description = "Has permission to install unvetted APK packages while holding overlay or accessibility control.",
                    indicator = "INSTALL_PACKAGES + OVERLAY/ACCESSIBILITY",
                    severity = RiskLevel.HIGH,
                    remediation = "Disable 'Install unknown apps' permission in Android Settings."
                )
            )
        }

        // 5. Unassessed / Unjustified Utility Anomaly
        val lowerName = appName.lowercase()
        val isUtility = lowerName.contains("flash") || lowerName.contains("torch") ||
                lowerName.contains("calculator") || lowerName.contains("wallpaper") ||
                lowerName.contains("cleaner") || lowerName.contains("battery")

        if (isUtility && (hasSms || hasContacts || hasAudio || hasLoc)) {
            score += 30
            findings.add(
                ThreatFinding(
                    category = "Authorization Anomaly",
                    title = "Unassessed & Unjustified Permission Request",
                    description = "Simple utility app '$appName' requests intrusive permissions (SMS, Contacts, or Microphone) completely unrelated to its function.",
                    indicator = "Unjustified Utility Authorizations",
                    severity = RiskLevel.HIGH,
                    remediation = "There is no valid functional reason for this utility to access personal data. Revoke access."
                )
            )
        }

        val finalScore = score.coerceIn(0, 100)
        val riskLevel = when {
            finalScore >= 75 -> RiskLevel.CRITICAL
            finalScore >= 50 -> RiskLevel.HIGH
            finalScore >= 25 -> RiskLevel.MEDIUM
            finalScore >= 10 -> RiskLevel.LOW
            else -> RiskLevel.SAFE
        }

        val recs = mutableListOf<String>()
        if (riskLevel == RiskLevel.CRITICAL) {
            recs.add("Uninstall '$appName' immediately.")
            recs.add("Check recent bank/crypto accounts for unauthorized logins.")
            recs.add("Disable unvetted Accessibility Services in Android Settings.")
        } else if (riskLevel == RiskLevel.HIGH) {
            recs.add("Revoke background permissions in Settings > Apps > $appName.")
            recs.add("Verify whether you downloaded this from the official Google Play Store.")
        } else if (riskLevel == RiskLevel.MEDIUM) {
            recs.add("Limit permissions to 'Only while using the app'.")
        } else {
            recs.add("App is within safe authorization limits.")
        }

        val summary = when (riskLevel) {
            RiskLevel.CRITICAL -> "CRITICAL THREAT: App exhibits active banking trojan or spyware permission signatures!"
            RiskLevel.HIGH -> "HIGH RISK: Excessive and dangerous authorizations detected that could compromise privacy."
            RiskLevel.MEDIUM -> "MODERATE RISK: Sensitive authorizations present. Review access."
            RiskLevel.LOW -> "LOW RISK: Standard benign mobile authorizations."
            RiskLevel.SAFE -> "SAFE: Clean authorization posture."
        }

        return AppThreatInfo(
            packageName = packageName,
            appName = appName,
            isSystemApp = isSystemApp,
            riskLevel = riskLevel,
            riskScore = finalScore,
            summary = summary,
            permissions = permissions,
            findings = findings,
            recommendations = recs
        )
    }
}
