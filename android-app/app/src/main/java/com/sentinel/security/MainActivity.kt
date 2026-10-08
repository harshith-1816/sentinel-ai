package com.sentinel.security

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.sentinel.security.ui.screens.MainSecurityScreen
import com.sentinel.security.ui.theme.SentinelTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SentinelTheme {
                MainSecurityScreen()
            }
        }
    }
}
