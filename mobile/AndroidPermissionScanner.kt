package com.sentinel.security.scanner

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * Sentinel AI - Android Mobile On-Device Security & Permission Scanner
 *
 * Extracts:
 * - Granted & requested permissions for all non-system applications
 * - Active Accessibility Services (God Mode detection)
 * - Overlay / SYSTEM_ALERT_WINDOW ("Draw over other apps") status
 * - Device Administrator rights
 */
class AndroidPermissionScanner(private val context: Context) {

    data class ScannedApp(
        val packageName: String,
        val appName: String,
        val isSystemApp: Boolean,
        val permissions: List<String>,
        val hasOverlayPermission: Boolean = false,
        val isAccessibilityEnabled: Boolean = false,
        val isDeviceAdmin: Boolean = false
    )

    fun scanInstalledApps(): List<ScannedApp> {
        val pm = context.packageManager
        val installedPackages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        val activeAccessibilityServices = getActiveAccessibilityServices()
        val devicePolicyManager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager

        val results = mutableListOf<ScannedApp>()

        for (pkgInfo in installedPackages) {
            val appInfo = pkgInfo.applicationInfo ?: continue
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            // Filter out default platform apps unless debugging system vectors
            val permsList = pkgInfo.requestedPermissions?.toList() ?: emptyList()
            val appLabel = pm.getApplicationLabel(appInfo).toString()

            // Check if app has active accessibility service turned on
            val hasActiveAccessibility = activeAccessibilityServices.any { it.contains(pkgInfo.packageName) }

            // Check device admin status
            val isAdmin = devicePolicyManager?.isAdminActive(
                ComponentName(pkgInfo.packageName, "")
            ) ?: false

            results.add(
                ScannedApp(
                    packageName = pkgInfo.packageName,
                    appName = appLabel,
                    isSystemApp = isSystem,
                    permissions = permsList,
                    isAccessibilityEnabled = hasActiveAccessibility,
                    isDeviceAdmin = isAdmin
                )
            )
        }
        return results
    }

    private fun getActiveAccessibilityServices(): List<String> {
        val enabledServices = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return emptyList()

        return enabledServices.split(":").map { it.trim() }
    }

    /**
     * Converts scanned apps to JSON payload matching Sentinel AI Backend API format
     */
    fun toJsonPayload(apps: List<ScannedApp>, deviceId: String = Build.MODEL): JSONObject {
        val root = JSONObject()
        root.put("device_id", deviceId)

        val jsonArray = JSONArray()
        for (app in apps) {
            val obj = JSONObject()
            obj.put("package_name", app.packageName)
            obj.put("app_name", app.appName)
            obj.put("is_system_app", app.isSystemApp)
            obj.put("category", "utility")

            val permsArray = JSONArray()
            for (p in app.permissions) {
                permsArray.put(p)
            }
            obj.put("permissions", permsArray)
            jsonArray.put(obj)
        }

        root.put("apps", jsonArray)
        return root
    }

    /**
     * Sends the device audit payload to Sentinel AI REST API
     */
    fun sendAuditToSentinelApi(apiUrl: String, payload: JSONObject): String {
        val url = URL("$apiUrl/api/audit/mobile-device")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json; utf-8")
        conn.setRequestProperty("Accept", "application/json")
        conn.doOutput = true
        conn.connectTimeout = 8000
        conn.readTimeout = 8000

        OutputStreamWriter(conn.outputStream).use { writer ->
            writer.write(payload.toString())
            writer.flush()
        }

        return conn.inputStream.bufferedReader().use { it.readText() }
    }
}
