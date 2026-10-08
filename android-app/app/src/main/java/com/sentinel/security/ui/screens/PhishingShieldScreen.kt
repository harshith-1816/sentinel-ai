package com.sentinel.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentinel.security.ui.theme.*

@Composable
fun PhishingShieldScreen() {
    var urlInput by remember { mutableStateOf("") }
    var scanResult by remember { mutableStateOf<String?>(null) }
    var isDangerous by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDark)
            .padding(16.dp)
    ) {
        Text(
            text = "Phishing & Web App Shield",
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary
        )

        Text(
            text = "Paste any link received via SMS, WhatsApp, or email before tapping it.",
            fontSize = 13.sp,
            color = TextSecondary,
            modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
        )

        OutlinedTextField(
            value = urlInput,
            onValueChange = { urlInput = it },
            label = { Text("Enter or paste URL", color = TextSecondary) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = TextPrimary,
                unfocusedTextColor = TextPrimary,
                focusedBorderColor = AccentCyan,
                unfocusedBorderColor = CardBorder,
                cursorColor = AccentCyan
            )
        )

        Spacer(modifier = Modifier.height(12.dp))

        Button(
            onClick = {
                val input = urlInput.trim().lowercase()
                if (input.isEmpty()) return@Button

                // Fast on-device heuristic evaluation
                val isFakeBrand = input.contains("paypa1") || input.contains("g00gle") ||
                        input.contains("micros0ft") || input.contains("app1e") ||
                        (input.contains("paypal") && !input.contains("paypal.com"))

                val isRawIp = Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""").containsMatchIn(input)
                val isBadTld = input.endsWith(".xyz") || input.endsWith(".top") || input.endsWith(".click")
                val isObfuscatedAt = input.contains("@")

                if (isFakeBrand || isRawIp || isBadTld || isObfuscatedAt) {
                    isDangerous = true
                    scanResult = "CRITICAL PHISHING THREAT DETECTED!\n\n" +
                            "• Brand Impersonation / Typosquatting\n" +
                            "• Suspicious domain structure\n\n" +
                            "Action: DO NOT OPEN. Delete this link immediately."
                } else {
                    isDangerous = false
                    scanResult = "SAFE: No known deception markers found on this URL."
                }
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = AccentCyan),
            shape = RoundedCornerShape(8.dp)
        ) {
            Text("Analyze Link", color = Color.White, fontWeight = FontWeight.Bold)
        }

        scanResult?.let { result ->
            Spacer(modifier = Modifier.height(20.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (isDangerous) ThreatCritical.copy(alpha = 0.15f) else ThreatSafe.copy(alpha = 0.15f)
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = if (isDangerous) "⚠️ DANGER DETECTED" else "✅ URL APPEARS SAFE",
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                        color = if (isDangerous) ThreatCritical else ThreatSafe
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = result,
                        fontSize = 13.sp,
                        color = TextPrimary,
                        lineHeight = 18.sp
                    )
                }
            }
        }
    }
}
