package com.sentinel.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sentinel.security.model.AppThreatInfo
import com.sentinel.security.model.RiskLevel
import com.sentinel.security.ui.theme.*

@Composable
fun AppDetailDialog(
    app: AppThreatInfo,
    onDismiss: () -> Unit,
    onOpenSettings: () -> Unit,
    onUninstall: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = CardDark,
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.85f)
        ) {
            Column(
                modifier = Modifier
                    .padding(20.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    text = app.appName,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary
                )
                Text(
                    text = app.packageName,
                    fontSize = 12.sp,
                    color = TextSecondary
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "Risk Score: ${app.riskScore}/100 [${app.riskLevel.label}]",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (app.riskLevel == RiskLevel.CRITICAL) ThreatCritical else ThreatHigh
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Detected Threat Indicators:",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AccentCyan
                )

                Spacer(modifier = Modifier.height(8.dp))

                app.findings.forEach { finding ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp)
                            .background(BgDark, RoundedCornerShape(8.dp))
                            .padding(10.dp)
                    ) {
                        Text(
                            text = finding.title,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = if (finding.severity == RiskLevel.CRITICAL) ThreatCritical else ThreatHigh
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = finding.description,
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Fix: ${finding.remediation}",
                            fontSize = 11.sp,
                            color = AccentCyan
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Recommended Remediation:",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )

                app.recommendations.forEach { rec ->
                    Text(
                        text = "• $rec",
                        fontSize = 12.sp,
                        color = TextSecondary,
                        modifier = Modifier.padding(vertical = 2.dp)
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = onOpenSettings,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = AccentBlue),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("App Settings", color = Color.White, fontSize = 12.sp)
                    }

                    Button(
                        onClick = onUninstall,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = ThreatCritical),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("Uninstall", color = Color.White, fontSize = 12.sp)
                    }
                }

                TextButton(
                    onClick = onDismiss,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp)
                ) {
                    Text("Close", color = TextSecondary)
                }
            }
        }
    }
}
