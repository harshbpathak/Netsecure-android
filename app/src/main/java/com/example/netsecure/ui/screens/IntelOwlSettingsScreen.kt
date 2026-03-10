package com.example.netsecure.ui.screens

import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.netsecure.data.ThreatIntelRepository
import com.example.netsecure.network.IntelOwlConfig
import com.example.netsecure.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IntelOwlSettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHost = remember { SnackbarHostState() }

    // Local UI state (init from IntelOwlConfig)
    var serverUrl by remember { mutableStateOf(IntelOwlConfig.serverUrl) }
    var apiToken by remember { mutableStateOf(IntelOwlConfig.apiToken) }
    var enabled by remember { mutableStateOf(IntelOwlConfig.enabled) }
    var tlp by remember { mutableStateOf(IntelOwlConfig.tlp) }
    var cacheTtl by remember { mutableStateOf(IntelOwlConfig.cacheTtlMinutes.toFloat()) }
    var maxJobs by remember { mutableStateOf(IntelOwlConfig.maxConcurrentJobs.toFloat()) }
    var selectedAnalyzers by remember { mutableStateOf(IntelOwlConfig.selectedAnalyzers.toSet()) }
    var tokenVisible by remember { mutableStateOf(false) }
    var testStatus by remember { mutableStateOf<TestStatus?>(null) }

    // Save on back
    fun saveAndBack() {
        IntelOwlConfig.save(
            context = context,
            serverUrl = serverUrl.trim(),
            apiToken = apiToken.trim(),
            enabled = enabled,
            tlp = tlp,
            selectedAnalyzers = selectedAnalyzers.toList(),
            maxConcurrentJobs = maxJobs.toInt(),
            cacheTtlMinutes = cacheTtl.toInt()
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
                        Icon(Icons.Default.Security, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(22.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("IntelOwl Settings", fontWeight = FontWeight.Bold, color = TextWhite)
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
                SettingsCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Enable IntelOwl", color = TextWhite, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                            Text("Scan IPs/domains against your IntelOwl instance", color = TextDimmed, fontSize = 12.sp)
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

            // ── Server URL ──
            item {
                SettingsCard {
                    Text("Server URL", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = serverUrl,
                        onValueChange = { serverUrl = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("https://intelowl.yourdomain.com", color = TextDimmed, fontSize = 13.sp) },
                        singleLine = true,
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

            // ── API Token ──
            item {
                SettingsCard {
                    Text("API Token", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = apiToken,
                        onValueChange = { apiToken = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Paste your IntelOwl API token", color = TextDimmed, fontSize = 13.sp) },
                        singleLine = true,
                        visualTransformation = if (tokenVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { tokenVisible = !tokenVisible }) {
                                Icon(
                                    if (tokenVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
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

            // ── Test Connection ──
            item {
                SettingsCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text("Test Connection", color = TextWhite, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                            when (val s = testStatus) {
                                is TestStatus.Loading  -> Text("Connecting…", color = CyberCyan, fontSize = 12.sp)
                                is TestStatus.Success  -> Text("Connected! ✓ IntelOwl is reachable", color = NeonGreen, fontSize = 12.sp)
                                is TestStatus.Failure  -> Text(s.reason, color = AlertRed, fontSize = 11.sp)
                                null -> Text("Verify connectivity to IntelOwl", color = TextDimmed, fontSize = 12.sp)
                            }
                        }
                        Spacer(Modifier.width(12.dp))
                        // Test button
                        OutlinedButton(
                            onClick = {
                                testStatus = TestStatus.Loading
                                scope.launch {
                                    testStatus = testConnection(serverUrl.trim(), apiToken.trim())
                                }
                            },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberCyan),
                            border = BorderStroke(1.dp, CyberCyan.copy(alpha = 0.5f)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Icon(
                                when (testStatus) {
                                    is TestStatus.Success -> Icons.Default.CheckCircle
                                    is TestStatus.Failure -> Icons.Default.Error
                                    else -> Icons.Default.Refresh
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

            // ── TLP Selection ──
            item {
                SettingsCard {
                    Text("TLP Level", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Controls how IntelOwl shares analysis data externally. AMBER = private.",
                        color = TextDimmed, fontSize = 11.sp, modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        IntelOwlConfig.TLP_OPTIONS.forEach { option ->
                            val selected = tlp == option
                            val tlpColor = when (option) {
                                "CLEAR" -> TextWhite
                                "GREEN" -> NeonGreen
                                "AMBER" -> AlertOrange
                                "RED"   -> AlertRed
                                else    -> TextGray
                            }
                            FilterChip(
                                selected = selected,
                                onClick = { tlp = option },
                                label = { Text(option, fontSize = 11.sp) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = tlpColor.copy(alpha = 0.15f),
                                    selectedLabelColor = tlpColor,
                                    containerColor = CardSurfaceLight,
                                    labelColor = TextGray
                                ),
                                border = if (selected) BorderStroke(1.dp, tlpColor.copy(alpha = 0.5f)) else null,
                                shape = RoundedCornerShape(8.dp)
                            )
                        }
                    }
                }
            }

            // ── Analyzer Selection ──
            item {
                SettingsCard {
                    Text("Analyzers", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Select which analyzers run during scans",
                        color = TextDimmed, fontSize = 11.sp, modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
                    )
                    IntelOwlConfig.DEFAULT_ANALYZERS.forEach { analyzer ->
                        val isSelected = selectedAnalyzers.contains(analyzer)
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = isSelected,
                                onCheckedChange = { checked ->
                                    selectedAnalyzers = if (checked)
                                        selectedAnalyzers + analyzer
                                    else
                                        selectedAnalyzers - analyzer
                                },
                                colors = CheckboxDefaults.colors(
                                    checkedColor = CyberCyan,
                                    uncheckedColor = TextDimmed
                                )
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(analyzer, color = if (isSelected) TextWhite else TextGray, fontSize = 13.sp)
                        }
                    }
                }
            }

            // ── Cache TTL ──
            item {
                SettingsCard {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Cache TTL", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        Text("${cacheTtl.toInt()} min", color = CyberCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                    Text("How long scan results are kept before re-scanning", color = TextDimmed, fontSize = 11.sp)
                    Slider(
                        value = cacheTtl,
                        onValueChange = { cacheTtl = it },
                        valueRange = 10f..1440f,
                        steps = 13,
                        colors = SliderDefaults.colors(
                            thumbColor = CyberCyan,
                            activeTrackColor = CyberCyan,
                            inactiveTrackColor = CardSurfaceLight
                        )
                    )
                }
            }

            // ── Max Jobs ──
            item {
                SettingsCard {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Max Concurrent Jobs", color = TextGray, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        Text("${maxJobs.toInt()}", color = CyberCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                    Text("Limit IntelOwl API concurrency", color = TextDimmed, fontSize = 11.sp)
                    Slider(
                        value = maxJobs,
                        onValueChange = { maxJobs = it },
                        valueRange = 1f..10f,
                        steps = 8,
                        colors = SliderDefaults.colors(
                            thumbColor = CyberCyan,
                            activeTrackColor = CyberCyan,
                            inactiveTrackColor = CardSurfaceLight
                        )
                    )
                }
            }

            // ── Scan Now + Clear Cache ──
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Button(
                        onClick = {
                            // Force re-scan by clearing the cache (new observables will be queued immediately)
                            ThreatIntelRepository.clearAll()
                            scope.launch {
                                snackbarHost.showSnackbar("Cache cleared — re-scanning on next traffic update")
                            }
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = CardSurface),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Clear Cache", color = TextGray, fontSize = 13.sp)
                    }

                    Button(
                        onClick = { saveAndBack() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Save", color = DarkNavy, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    }
                }
            }
        }
    }
}

private sealed class TestStatus {
    object Loading : TestStatus()
    object Success : TestStatus()
    data class Failure(val reason: String) : TestStatus()
}

private suspend fun testConnection(serverUrl: String, apiToken: String): TestStatus {
    val url = serverUrl.trim()
    val token = apiToken.trim()
    if (url.isBlank()) return TestStatus.Failure("Server URL is blank")
    if (token.isBlank()) return TestStatus.Failure("API token is blank")
    return try {
        withContext(Dispatchers.IO) {
            android.util.Log.d("IntelOwlTest", "Testing connection to: $url")
            val service = IntelOwlConfig.buildServiceForCredentials(url, token)
                ?: return@withContext TestStatus.Failure("Failed to build HTTP client — check URL format")
            val resp = try {
                service.analyzerHealthcheck()
            } catch (e: Exception) {
                android.util.Log.e("IntelOwlTest", "HTTP call failed", e)
                return@withContext TestStatus.Failure("${e.javaClass.simpleName}: ${e.message?.take(80)}")
            }
            android.util.Log.d("IntelOwlTest", "Response code: ${resp.code()}")
            when {
                resp.isSuccessful -> TestStatus.Success
                resp.code() == 401 -> TestStatus.Failure("401 Unauthorized — API token is wrong")
                resp.code() == 403 -> TestStatus.Failure("403 Forbidden — token lacks permission")
                resp.code() == 404 -> TestStatus.Failure("404 Not Found — wrong URL or IntelOwl version")
                else -> TestStatus.Failure("HTTP ${resp.code()} — ${resp.message().take(60)}")
            }
        }
    } catch (e: Exception) {
        android.util.Log.e("IntelOwlTest", "Outer exception", e)
        TestStatus.Failure("${e.javaClass.simpleName}: ${e.message?.take(80)}")
    }
}

@Composable
private fun SettingsCard(content: @Composable ColumnScope.() -> Unit) {
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



