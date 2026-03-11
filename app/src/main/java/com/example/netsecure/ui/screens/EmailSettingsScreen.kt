package com.example.netsecure.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.netsecure.notification.EmailAlertSender
import com.example.netsecure.notification.EmailConfig
import com.example.netsecure.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EmailSettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHost = remember { SnackbarHostState() }

    // Local UI state (init from EmailConfig)
    var enabled by remember { mutableStateOf(EmailConfig.enabled) }
    var senderEmail by remember { mutableStateOf(EmailConfig.senderEmail) }
    var senderPassword by remember { mutableStateOf(EmailConfig.senderPassword) }
    var passwordVisible by remember { mutableStateOf(false) }
    var recipientsText by remember { mutableStateOf(EmailConfig.recipients.joinToString(", ")) }
    var cooldown by remember { mutableStateOf(EmailConfig.cooldownMinutes.toFloat()) }
    var enableHighCritical by remember { mutableStateOf(EmailConfig.enableForHighCritical) }
    var enableIds by remember { mutableStateOf(EmailConfig.enableForIds) }
    var testStatus by remember { mutableStateOf<EmailTestStatus?>(null) }
    var showSetupGuide by remember { mutableStateOf(false) }

    fun parseRecipients(): List<String> =
        recipientsText.split(",", ";", "\n")
            .map { it.trim() }
            .filter { it.contains("@") }

    fun saveAndBack() {
        EmailConfig.save(
            context = context,
            enabled = enabled,
            smtpHost = "smtp.gmail.com",
            smtpPort = 587,
            senderEmail = senderEmail.trim(),
            senderPassword = senderPassword,
            recipients = parseRecipients(),
            cooldownMinutes = cooldown.toInt(),
            enableForHighCritical = enableHighCritical,
            enableForIds = enableIds
        )
        onBack()
    }

    Scaffold(
        containerColor = DarkNavy,
        snackbarHost = { SnackbarHost(snackbarHost) },
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Email, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(22.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Email Alerts", fontWeight = FontWeight.Bold, color = TextWhite)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { saveAndBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = CyberCyan)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DarkNavy)
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            contentPadding = PaddingValues(bottom = 32.dp)
        ) {

            // ── Enable / Disable ──
            item {
                EmailSettingsCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Enable Email Alerts", color = TextWhite, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                            Text("Send threat alerts via SMTP email", color = TextDimmed, fontSize = 12.sp)
                        }
                        Switch(
                            checked = enabled,
                            onCheckedChange = { enabled = it },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = DarkNavy,
                                checkedTrackColor = CyberCyan
                            )
                        )
                    }
                }
            }

            // ── Gmail Setup Guide ──
            item {
                EmailSettingsCard {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Info, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Gmail App Password Setup", color = CyberCyan, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                        }
                        IconButton(onClick = { showSetupGuide = !showSetupGuide }, modifier = Modifier.size(24.dp)) {
                            Icon(
                                if (showSetupGuide) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                                contentDescription = "Toggle guide",
                                tint = CyberCyan
                            )
                        }
                    }
                    AnimatedVisibility(visible = showSetupGuide) {
                        Column(modifier = Modifier.padding(top = 12.dp)) {
                            val steps = listOf(
                                "1. Go to myaccount.google.com/security",
                                "2. Enable 2-Step Verification (required)",
                                "3. Go to myaccount.google.com/apppasswords",
                                "4. Select \"Mail\" and your device",
                                "5. Generate a 16-character App Password",
                                "6. Paste it in the \"App Password\" field below"
                            )
                            steps.forEach { step ->
                                Text(
                                    step,
                                    color = TextGray,
                                    fontSize = 12.sp,
                                    modifier = Modifier.padding(vertical = 2.dp)
                                )
                            }
                            Spacer(Modifier.height(6.dp))
                            Text(
                                "Do NOT use your regular Gmail password. App Passwords require 2FA enabled.",
                                color = AlertOrange,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }
            }

            // ── Sender Email ──
            item {
                EmailSettingsCard {
                    Text("Gmail Account", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = senderEmail,
                        onValueChange = { senderEmail = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("you@gmail.com", color = TextDimmed, fontSize = 13.sp) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextWhite,
                            unfocusedTextColor = TextGray,
                            focusedBorderColor = CyberCyan,
                            unfocusedBorderColor = TextDimmed.copy(alpha = 0.4f),
                            cursorColor = CyberCyan
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )
                }
            }

            // ── App Password ──
            item {
                EmailSettingsCard {
                    Text("App Password", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = senderPassword,
                        onValueChange = { senderPassword = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("16-character App Password", color = TextDimmed, fontSize = 13.sp) },
                        singleLine = true,
                        visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { passwordVisible = !passwordVisible }) {
                                Icon(
                                    if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                    contentDescription = "Toggle visibility",
                                    tint = TextGray
                                )
                            }
                        },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextWhite,
                            unfocusedTextColor = TextGray,
                            focusedBorderColor = CyberCyan,
                            unfocusedBorderColor = TextDimmed.copy(alpha = 0.4f),
                            cursorColor = CyberCyan
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )
                    Text(
                        "Stored encrypted via AndroidKeyStore",
                        color = TextDimmed,
                        fontSize = 11.sp,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }

            // ── Recipients ──
            item {
                EmailSettingsCard {
                    Text("Recipients", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Comma-separated email addresses",
                        color = TextDimmed, fontSize = 11.sp,
                        modifier = Modifier.padding(top = 2.dp, bottom = 6.dp)
                    )
                    OutlinedTextField(
                        value = recipientsText,
                        onValueChange = { recipientsText = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("admin@company.com, security@team.org", color = TextDimmed, fontSize = 13.sp) },
                        minLines = 2,
                        maxLines = 4,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextWhite,
                            unfocusedTextColor = TextGray,
                            focusedBorderColor = CyberCyan,
                            unfocusedBorderColor = TextDimmed.copy(alpha = 0.4f),
                            cursorColor = CyberCyan
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )
                    val parsed = parseRecipients()
                    if (parsed.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text(
                            "${parsed.size} recipient${if (parsed.size > 1) "s" else ""} configured",
                            color = NeonGreen,
                            fontSize = 11.sp
                        )
                    }
                }
            }

            // ── Test Email ──
            item {
                EmailSettingsCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("Test Email", color = TextWhite, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                            when (val s = testStatus) {
                                is EmailTestStatus.Loading -> Text("Sending…", color = CyberCyan, fontSize = 12.sp)
                                is EmailTestStatus.Success -> Text(s.message, color = NeonGreen, fontSize = 12.sp)
                                is EmailTestStatus.Failure -> Text(s.reason, color = AlertRed, fontSize = 11.sp)
                                null -> Text("Verify SMTP configuration works", color = TextDimmed, fontSize = 12.sp)
                            }
                        }
                        Spacer(Modifier.width(12.dp))
                        OutlinedButton(
                            onClick = {
                                // Save current values first for the test
                                EmailConfig.save(
                                    context = context,
                                    enabled = true, // force-enable for test
                                    smtpHost = "smtp.gmail.com",
                                    smtpPort = 587,
                                    senderEmail = senderEmail.trim(),
                                    senderPassword = senderPassword,
                                    recipients = parseRecipients(),
                                    cooldownMinutes = cooldown.toInt(),
                                    enableForHighCritical = enableHighCritical,
                                    enableForIds = enableIds
                                )
                                testStatus = EmailTestStatus.Loading
                                scope.launch {
                                    val result = withContext(Dispatchers.IO) {
                                        EmailAlertSender.sendTestEmail()
                                    }
                                    testStatus = if (result.contains("success", ignoreCase = true)) {
                                        EmailTestStatus.Success(result)
                                    } else {
                                        EmailTestStatus.Failure(result)
                                    }
                                }
                            },
                            enabled = senderEmail.isNotBlank() && senderPassword.isNotBlank() && parseRecipients().isNotEmpty(),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
                            border = BorderStroke(1.dp, CyberCyan.copy(alpha = 0.5f)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Icon(
                                when (testStatus) {
                                    is EmailTestStatus.Success -> Icons.Default.CheckCircle
                                    is EmailTestStatus.Failure -> Icons.Default.Error
                                    else -> Icons.Default.Send
                                },
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(Modifier.width(6.dp))
                            Text("Test", fontSize = 13.sp)
                        }
                    }
                }
            }

            // ── Trigger Toggles ──
            item {
                EmailSettingsCard {
                    Text("Trigger Conditions", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(8.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("Email on HIGH/CRITICAL threats", color = TextWhite, fontSize = 14.sp)
                            Text("IntelOwl findings with high severity", color = TextDimmed, fontSize = 11.sp)
                        }
                        Switch(
                            checked = enableHighCritical,
                            onCheckedChange = { enableHighCritical = it },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = DarkNavy,
                                checkedTrackColor = CyberCyan
                            )
                        )
                    }

                    Spacer(Modifier.height(8.dp))
                    HorizontalDivider(color = TextDimmed.copy(alpha = 0.2f))
                    Spacer(Modifier.height(8.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("Email on IDS signature matches", color = TextWhite, fontSize = 14.sp)
                            Text("Local payload signature detections", color = TextDimmed, fontSize = 11.sp)
                        }
                        Switch(
                            checked = enableIds,
                            onCheckedChange = { enableIds = it },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = DarkNavy,
                                checkedTrackColor = CyberCyan
                            )
                        )
                    }
                }
            }

            // ── Cooldown Slider ──
            item {
                EmailSettingsCard {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Cooldown Period", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        Text("${cooldown.toInt()} min", color = CyberCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                    Text(
                        "Minimum time between emails for the same observable",
                        color = TextDimmed, fontSize = 11.sp
                    )
                    Slider(
                        value = cooldown,
                        onValueChange = { cooldown = it },
                        valueRange = 5f..120f,
                        steps = 22,
                        colors = SliderDefaults.colors(
                            thumbColor = CyberCyan,
                            activeTrackColor = CyberCyan,
                            inactiveTrackColor = CardSurfaceLight
                        )
                    )
                }
            }

            // ── Save Button ──
            item {
                Button(
                    onClick = { saveAndBack() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text("Save", color = DarkNavy, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
            }
        }
    }
}

private sealed class EmailTestStatus {
    object Loading : EmailTestStatus()
    data class Success(val message: String) : EmailTestStatus()
    data class Failure(val reason: String) : EmailTestStatus()
}

@Composable
private fun EmailSettingsCard(content: @Composable ColumnScope.() -> Unit) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            content = content
        )
    }
}
