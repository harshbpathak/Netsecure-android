package com.example.netsecure.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val NetSecureDarkScheme = darkColorScheme(
    primary = CyberCyan,
    onPrimary = DarkNavy,
    primaryContainer = CyberCyanDark,
    onPrimaryContainer = CyberCyanLight,
    secondary = ElectricPurple,
    onSecondary = DarkNavy,
    secondaryContainer = ElectricPurpleDark,
    onSecondaryContainer = ElectricPurple,
    tertiary = NeonGreen,
    onTertiary = DarkNavy,
    error = AlertRed,
    onError = Color.White,
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = DarkNavy,
    onBackground = TextWhite,
    surface = DarkSurface,
    onSurface = TextWhite,
    surfaceVariant = CardSurface,
    onSurfaceVariant = TextGray,
    outline = TextDimmed,
    outlineVariant = CardSurfaceLight,
)

@Composable
fun NetSecureTheme(
    content: @Composable () -> Unit
) {
    val colorScheme = NetSecureDarkScheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = DarkNavy.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = false
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}