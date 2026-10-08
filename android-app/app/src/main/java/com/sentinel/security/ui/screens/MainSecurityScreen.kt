package com.sentinel.security.ui.screens

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentinel.security.model.AppThreatInfo
import com.sentinel.security.model.DevicePostureReport
import com.sentinel.security.model.RiskLevel
import com.sentinel.security.scanner.PermissionAuditor
import com.sentinel.security.ui.components.ThreatCard
import com.sentinel.security.ui.theme.*
import com.sentinel.security.utils.IntentUtils
import kotlinx.coroutines.launch

@Composable
fun MainSecurityScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val auditor = remember { PermissionAuditor(context) }

    var selectedTab by remember { mutableIntStateOf(0) }
    var isScanning by remember { mutableStateOf(false) }
    var report by remember { mutableStateOf<DevicePostureReport?>(null) }
    var selectedAppForDetail by remember { mutableStateOf<AppThreatInfo?>(null) }

    fun triggerScan() {
        coroutineScope.launch {
            isScanning = true
            report = auditor.auditAllApps()
            isScanning = false
        }
    }

    // Auto-scan on initial launch
    LaunchedEffect(Unit) {
        triggerScan()
    }

    Scaffold(
        bottomBar = {
            NavigationBar(containerColor = CardDark) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    label = { Text("App Auditor") },
                    icon = { Text("🛡️") }
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    label = { Text("Phishing Shield") },
                    icon = { Text("🌐") }
                )
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(BgDark)
        ) {
            if (selectedTab == 1) {
                PhishingShieldScreen()
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                ) {
                    // Header Status Card
                    report?.let { rep ->
                        val isDanger = rep.overallRisk in listOf(RiskLevel.CRITICAL, RiskLevel.HIGH)
                        val shieldBg = if (isDanger) ThreatCritical.copy(alpha = 0.15f) else ThreatSafe.copy(alpha = 0.15f)
                        val shieldColor = if (isDanger) ThreatCritical else ThreatSafe

                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = shieldBg)
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(
                                    text = if (isDanger) "🚨 SECURITY ALERT" else "🛡️ DEVICE PROTECTED",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = shieldColor
                                )

                                Spacer(modifier = Modifier.height(4.dp))

                                Text(
                                    text = if (isDanger)
                                        "${rep.criticalCount} Critical Trojans & ${rep.highCount} Rogue Permissions Detected"
                                    else
                                        "Scanned ${rep.totalScanned} Apps. No unassessed authorizations found.",
                                    fontSize = 13.sp,
                                    color = TextPrimary
                                )

                                Spacer(modifier = Modifier.height(12.dp))

                                Button(
                                    onClick = { triggerScan() },
                                    enabled = !isScanning,
                                    colors = ButtonDefaults.buttonColors(containerColor = AccentCyan),
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    if (isScanning) {
                                        CircularProgressIndicator(
                                            modifier = Modifier.size(16.dp),
                                            color = Color.White,
                                            strokeWidth = 2.dp
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text("Auditing Phone…", color = Color.White)
                                    } else {
                                        Text("Re-Scan Phone", color = Color.White, fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                        }

                        // App Threat List
                        LazyColumn(modifier = Modifier.fillMaxSize()) {
                            items(rep.apps) { app ->
                                ThreatCard(
                                    app = app,
                                    onClickDetails = { selectedAppForDetail = app },
                                    onFixPermissions = {
                                        if (app.riskLevel == RiskLevel.CRITICAL) {
                                            IntentUtils.promptUninstall(context, app.packageName)
                                        } else {
                                            IntentUtils.openAppDetails(context, app.packageName)
                                        }
                                    }
                                )
                            }
                        }
                    } ?: run {
                        // Initial Loading State
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                CircularProgressIndicator(color = AccentCyan)
                                Spacer(modifier = Modifier.height(16.dp))
                                Text("Auditing device packages and permissions…", color = TextSecondary)
                            }
                        }
                    }
                }
            }

            // Detail Dialog
            selectedAppForDetail?.let { app ->
                AppDetailDialog(
                    app = app,
                    onDismiss = { selectedAppForDetail = null },
                    onOpenSettings = {
                        IntentUtils.openAppDetails(context, app.packageName)
                        selectedAppForDetail = null
                    },
                    onUninstall = {
                        IntentUtils.promptUninstall(context, app.packageName)
                        selectedAppForDetail = null
                    }
                )
            }
        }
    }
}
