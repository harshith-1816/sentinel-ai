package com.sentinel.security.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.sentinel.security.model.AppThreatInfo
import com.sentinel.security.model.DevicePostureReport
import com.sentinel.security.model.RiskLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class PermissionAuditor(private val context: Context) {

    private val engine = ThreatAnalyzerEngine()

    suspend fun auditAllApps(): DevicePostureReport = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val installed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        val activeAccessibility = getActiveAccessibilityServices()
        val auditedApps = mutableListOf<AppThreatInfo>()

        for (pkg in installed) {
            val appInfo = pkg.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            // Focus on non-system third party apps, but include system apps if they have third-party updates
            val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            if (isSystem && !isUpdatedSystem) {
                continue
            }

            val appLabel = pm.getApplicationLabel(appInfo).toString()
            val perms = pkg.requestedPermissions?.toList() ?: emptyList()
            val hasActiveAcc = activeAccessibility.any { it.contains(pkg.packageName) }

            val appReport = engine.analyzeApp(
                packageName = pkg.packageName,
                appName = appLabel,
                isSystemApp = isSystem,
                permissions = perms,
                hasActiveAccessibility = hasActiveAcc,
                hasOverlayPermission = false
            )

            auditedApps.add(appReport)
        }

        // Sort: Critical first, then High, then Medium, then Low/Safe
        auditedApps.sortByDescending { it.riskScore }

        val criticalCount = auditedApps.count { it.riskLevel == RiskLevel.CRITICAL }
        val highCount = auditedApps.count { it.riskLevel == RiskLevel.HIGH }
        val mediumCount = auditedApps.count { it.riskLevel == RiskLevel.MEDIUM }
        val atRisk = criticalCount + highCount + mediumCount

        val overallRisk = when {
            criticalCount > 0 -> RiskLevel.CRITICAL
            highCount > 0 -> RiskLevel.HIGH
            mediumCount > 0 -> RiskLevel.MEDIUM
            else -> RiskLevel.SAFE
        }

        DevicePostureReport(
            overallRisk = overallRisk,
            totalScanned = auditedApps.size,
            atRiskCount = atRisk,
            criticalCount = criticalCount,
            highCount = highCount,
            mediumCount = mediumCount,
            apps = auditedApps
        )
    }

    private fun getActiveAccessibilityServices(): List<String> {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return emptyList()

        return enabled.split(":").map { it.trim() }
    }
}
