package com.sentinel.security.model

enum class RiskLevel(val label: String) {
    SAFE("SAFE"),
    LOW("LOW"),
    MEDIUM("MEDIUM"),
    HIGH("HIGH"),
    CRITICAL("CRITICAL")
}

data class ThreatFinding(
    val category: String,
    val title: String,
    val description: String,
    val indicator: String,
    val severity: RiskLevel,
    val remediation: String
)

data class AppThreatInfo(
    val packageName: String,
    val appName: String,
    val isSystemApp: Boolean,
    val riskLevel: RiskLevel,
    val riskScore: Int,
    val summary: String,
    val permissions: List<String>,
    val findings: List<ThreatFinding>,
    val recommendations: List<String>
)

data class DevicePostureReport(
    val overallRisk: RiskLevel,
    val totalScanned: Int,
    val atRiskCount: Int,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val apps: List<AppThreatInfo>
)
