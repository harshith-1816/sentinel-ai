package com.sentinel.security.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentinel.security.model.AppThreatInfo
import com.sentinel.security.model.RiskLevel
import com.sentinel.security.ui.theme.*

@Composable
fun ThreatCard(
    app: AppThreatInfo,
    onClickDetails: () -> Unit,
    onFixPermissions: () -> Unit
) {
    val (badgeColor, badgeText) = when (app.riskLevel) {
        RiskLevel.CRITICAL -> Pair(ThreatCritical, "CRITICAL")
        RiskLevel.HIGH -> Pair(ThreatHigh, "HIGH RISK")
        RiskLevel.MEDIUM -> Pair(ThreatMedium, "MODERATE")
        RiskLevel.LOW -> Pair(ThreatLow, "LOW")
        RiskLevel.SAFE -> Pair(ThreatSafe, "SAFE")
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .clickable { onClickDetails() },
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CardDark),
        border = BorderStroke(
            width = if (app.riskLevel == RiskLevel.CRITICAL) 1.5.dp else 1.dp,
            color = if (app.riskLevel == RiskLevel.CRITICAL) ThreatCritical else CardBorder
        )
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = app.appName,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Text(
                        text = app.packageName,
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                }

                // Risk Badge
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = badgeColor.copy(alpha = 0.2f),
                    border = BorderStroke(1.dp, badgeColor)
                ) {
                    Text(
                        text = "$badgeText (${app.riskScore})",
                        color = badgeColor,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = app.summary,
                fontSize = 13.sp,
                color = TextSecondary,
                lineHeight = 18.sp
            )

            if (app.findings.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "⚠️ ${app.findings.size} Security Flags Found",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = badgeColor
                    )

                    Button(
                        onClick = onFixPermissions,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (app.riskLevel == RiskLevel.CRITICAL) ThreatCritical else AccentCyan
                        ),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                        shape = RoundedCornerShape(6.dp),
                        modifier = Modifier.height(34.dp)
                    ) {
                        Text(
                            text = if (app.riskLevel == RiskLevel.CRITICAL) "Uninstall" else "Revoke Access",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }
            }
        }
    }
}
