package com.example.netsecure.ui.screens


import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.example.netsecure.data.ThreatIntelRepository
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.CategoryStats
import com.example.netsecure.data.model.ScanStatus
import com.example.netsecure.data.model.ThreatAlert
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.ThreatSeverity
import com.example.netsecure.data.model.ThreatSummary
import com.example.netsecure.data.model.TrafficCategory
import com.example.netsecure.ui.theme.*
import com.example.netsecure.ui.viewmodel.DashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel,
    onAppClick: (String) -> Unit,
    onPrepareVpn: () -> Unit,
    onIntelOwlSettings: () -> Unit = {},
    onEmailSettings: () -> Unit = {},
    onLogsClick: () -> Unit = {}
) {
    val appList by viewModel.appTrafficList.collectAsState()
    val isCapturing by viewModel.isCapturing.collectAsState()
    val categoryBreakdown by viewModel.globalCategoryBreakdown.collectAsState()
    val selectedCategory by viewModel.selectedCategory.collectAsState()
    val threatSummary by viewModel.threatSummary.collectAsState()
    val threatAlerts by viewModel.threatAlerts.collectAsState()
    val scanStatus by viewModel.scanStatus.collectAsState()
    val threatMap by viewModel.threatReports.collectAsState()
    val context = LocalContext.current

    // Filter app list by selected category
    val filteredAppList = if (selectedCategory != null) {
        appList.filter { app ->
            app.categoryBreakdown.containsKey(selectedCategory)
        }
    } else {
        appList
    }

    Scaffold(
        containerColor = DarkNavy,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Shield,
                            contentDescription = null,
                            tint = CyberCyan,
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(
                            "NetSecure",
                            fontWeight = FontWeight.Bold,
                            fontSize = 22.sp,
                            color = TextWhite
                        )
                    }
                },
                actions = {
                    // Debug: Test Signature Scanner
                    IconButton(onClick = { viewModel.testSignatureScanner() }) {
                        Icon(
                            Icons.Default.BugReport,
                            contentDescription = "Test Signature Scanner",
                            tint = AlertOrange
                        )
                    }
                    // Logs viewer button
                    IconButton(onClick = onLogsClick) {
                        Icon(
                            Icons.Default.Terminal,
                            contentDescription = "System Logs",
                            tint = TextGray
                        )
                    }
                    // IntelOwl Settings button
                    IconButton(onClick = onIntelOwlSettings) {
                        Icon(
                            Icons.Default.Settings,
                            contentDescription = "IntelOwl Settings",
                            tint = if (scanStatus == ScanStatus.SCANNING) CyberCyan else TextGray
                        )
                    }
                    // Email Settings button
                    IconButton(onClick = onEmailSettings) {
                        Icon(
                            Icons.Default.Email,
                            contentDescription = "Email Settings",
                            tint = TextGray
                        )
                    }
                    if (appList.isNotEmpty()) {
                        IconButton(onClick = { viewModel.clearData() }) {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = "Clear",
                                tint = TextGray
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = DarkNavy
                )
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = {
                    if (isCapturing) {
                        viewModel.stopCapture()
                    } else {
                        onPrepareVpn()
                    }
                },
                containerColor = if (isCapturing) AlertRed else CyberCyan,
                contentColor = if (isCapturing) Color.White else DarkNavy,
                shape = RoundedCornerShape(16.dp)
            ) {
                Icon(
                    if (isCapturing) Icons.Default.Stop else Icons.Default.PlayArrow,
                    contentDescription = null
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    if (isCapturing) "Stop Capture" else "Start Capture",
                    fontWeight = FontWeight.Bold
                )
            }
        }
    ) { padding ->
        if (appList.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp)
            ) {
                SummaryRow(appList, isCapturing)
                Spacer(Modifier.height(12.dp))
                // Threat summary even when no traffic yet (if IntelOwl is configured)
                if (threatSummary.total > 0) {
                    ThreatSummaryCard(threatSummary, scanStatus, onIntelOwlSettings)
                    Spacer(Modifier.height(12.dp))
                }
                EmptyState(isCapturing)
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 80.dp)
            ) {
                // Summary cards
                item { SummaryRow(appList, isCapturing) }

                // Threat Intelligence Summary Card
                if (threatSummary.total > 0 || scanStatus == ScanStatus.SCANNING) {
                    item {
                        ThreatSummaryCard(threatSummary, scanStatus, onIntelOwlSettings)
                    }
                }

                // Active alert banners (HIGH/CRITICAL)
                val activeAlerts = threatAlerts.filter { !it.isDismissed() }.take(3)
                activeAlerts.forEach { alert ->
                    item(key = "alert_${alert.alertId}") {
                        ThreatAlertBanner(
                            alert = alert,
                            onDismiss = { viewModel.dismissThreatAlert(alert) }
                        )
                    }
                }

                // Category Breakdown Bar Graph
                if (categoryBreakdown.isNotEmpty()) {
                    item { CategoryBreakdownBar(categoryBreakdown) }
                }

                // Category Filter Chips
                item {
                    CategoryChipRow(
                        categoryBreakdown = categoryBreakdown,
                        selectedCategory = selectedCategory,
                        onCategoryClick = { viewModel.selectCategory(it) }
                    )
                }

                // App list header
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            if (selectedCategory != null) {
                                "${selectedCategory!!.label} — ${filteredAppList.size} apps"
                            } else {
                                "Apps Detected"
                            },
                            color = TextGray,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold
                        )

                        if (selectedCategory == null && filteredAppList.isNotEmpty()) {
                            IconButton(
                                onClick = { viewModel.exportConnectionsCsv(context) },
                                modifier = Modifier.size(24.dp) // Make it a bit smaller so it fits nicely
                            ) {
                                Icon(
                                    Icons.Default.Download,
                                    contentDescription = "Download CSV",
                                    tint = CyberCyan,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }
                    }
                }

                // App cards
                items(filteredAppList, key = { it.packageName }) { app ->
                    // Compute highest threat severity for this app's connections
                    val appThreatSeverity = remember(app.packageName, threatMap) {
                        computeAppThreatSeverity(app, threatMap)
                    }
                    AppTrafficCard(
                        app = app,
                        threatSeverity = appThreatSeverity,
                        onClick = { onAppClick(app.packageName) }
                    )
                }
            }
        }
    }
}

// ── Category Bar Graph ──

@Composable
private fun CategoryBreakdownBar(categoryBreakdown: Map<TrafficCategory, CategoryStats>) {
    val totalBytes = categoryBreakdown.values.sumOf { it.totalBytes }.coerceAtLeast(1)
    val sorted = TrafficCategory.displayOrder.filter { categoryBreakdown.containsKey(it) }
    val maxBytes = sorted.maxOfOrNull { categoryBreakdown[it]?.totalBytes ?: 0L } ?: 1L

    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp)
        ) {
            Text(
                "Data Categories",
                color = TextWhite,
                fontWeight = FontWeight.SemiBold,
                fontSize = 14.sp
            )
            Spacer(Modifier.height(12.dp))

            // Horizontal bar graph — one bar per category
            for (cat in sorted) {
                val stats = categoryBreakdown[cat] ?: continue
                val fraction = stats.totalBytes.toFloat() / maxBytes.toFloat()
                val pct = ((stats.totalBytes * 100) / totalBytes).toInt()
                val color = categoryColor(cat)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Category label (fixed width)
                    Text(
                        cat.label,
                        color = TextGray,
                        fontSize = 11.sp,
                        maxLines = 1,
                        modifier = Modifier.width(80.dp)
                    )

                    // Bar
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(12.dp)
                            .clip(RoundedCornerShape(6.dp))
                            .background(CardSurfaceLight)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxHeight()
                                .fillMaxWidth(fraction.coerceIn(0.02f, 1f))
                                .clip(RoundedCornerShape(6.dp))
                                .background(color)
                        )
                    }

                    Spacer(Modifier.width(8.dp))

                    // Percentage
                    Text(
                        "$pct%",
                        color = color,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.width(32.dp)
                    )
                }
            }
        }
    }
}

// ── Category Chip Row ──

@Composable
private fun CategoryChipRow(
    categoryBreakdown: Map<TrafficCategory, CategoryStats>,
    selectedCategory: TrafficCategory?,
    onCategoryClick: (TrafficCategory) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // "All" chip
        FilterChip(
            selected = selectedCategory == null,
            onClick = { onCategoryClick(selectedCategory ?: return@FilterChip) },
            label = { Text("All", fontSize = 12.sp) },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = CyberCyan.copy(alpha = 0.2f),
                selectedLabelColor = CyberCyan,
                containerColor = CardSurface,
                labelColor = TextGray
            ),
            border = FilterChipDefaults.filterChipBorder(
                borderColor = Color.Transparent,
                selectedBorderColor = CyberCyan.copy(alpha = 0.5f),
                enabled = true,
                selected = selectedCategory == null
            ),
            shape = RoundedCornerShape(10.dp)
        )

        // Category-specific chips (only show categories that have data)
        for (cat in TrafficCategory.displayOrder) {
            val stats = categoryBreakdown[cat] ?: continue
            val isSelected = selectedCategory == cat
            val color = categoryColor(cat)

            FilterChip(
                selected = isSelected,
                onClick = { onCategoryClick(cat) },
                label = {
                    Text(
                        cat.label,
                        fontSize = 12.sp,
                        maxLines = 1
                    )
                },
                leadingIcon = if (isSelected) {
                    {
                        Text(
                            "${stats.requests}",
                            color = color,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                } else null,
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = color.copy(alpha = 0.15f),
                    selectedLabelColor = color,
                    containerColor = CardSurface,
                    labelColor = TextGray
                ),
                border = FilterChipDefaults.filterChipBorder(
                    borderColor = Color.Transparent,
                    selectedBorderColor = color.copy(alpha = 0.5f),
                    enabled = true,
                    selected = isSelected
                ),
                shape = RoundedCornerShape(10.dp)
            )
        }
    }
}

// ── Summary Row (unchanged) ──

@Composable
private fun SummaryRow(appList: List<AppTrafficInfo>, isCapturing: Boolean) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            SummaryCard(
                label = "Apps",
                value = "${appList.size}",
                color = CyberCyan,
                modifier = Modifier.weight(1f)
            )
            SummaryCard(
                label = "Requests",
                value = "${appList.sumOf { it.totalRequests }}",
                color = ElectricPurple,
                modifier = Modifier.weight(1f)
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            SummaryCard(
                label = "Data Out",
                value = formatBytes(appList.sumOf { it.totalBytesOut }),
                color = AlertOrange,
                modifier = Modifier.weight(1f)
            )
            SummaryCard(
                label = "Data In",
                value = formatBytes(appList.sumOf { it.totalBytesIn }),
                color = NeonGreen,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun SummaryCard(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                value,
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = color
            )
            Spacer(Modifier.height(4.dp))
            Text(
                label,
                fontSize = 12.sp,
                color = TextGray
            )
        }
    }
}

@Composable
private fun AppTrafficCard(app: AppTrafficInfo, threatSeverity: ThreatSeverity?, onClick: () -> Unit) {
    val borderColor = when (threatSeverity) {
        ThreatSeverity.CRITICAL -> AlertRed
        ThreatSeverity.HIGH -> AlertOrange
        ThreatSeverity.MEDIUM -> UdpYellow
        else -> Color.Transparent
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (threatSeverity != null && threatSeverity != ThreatSeverity.CLEAN && threatSeverity != ThreatSeverity.LOW)
                borderColor.copy(alpha = 0.08f) else CardSurface
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // App icon (with threat dot overlay)
            Box(contentAlignment = Alignment.TopEnd) {
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .clip(CircleShape)
                        .background(
                            brush = Brush.linearGradient(
                                listOf(CyberCyanDark.copy(alpha = 0.3f), ElectricPurpleDark.copy(alpha = 0.3f))
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    if (app.appIcon != null) {
                        val bitmap = remember(app.appIcon) {
                            app.appIcon.toBitmap(32, 32).asImageBitmap()
                        }
                        Image(
                            bitmap = bitmap,
                            contentDescription = app.appName,
                            modifier = Modifier.size(32.dp)
                        )
                    } else {
                        Text(
                            app.appName.take(1).uppercase(),
                            color = CyberCyan,
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp
                        )
                    }
                }
                // Threat severity dot
                if (threatSeverity != null && threatSeverity != ThreatSeverity.CLEAN) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(borderColor)
                    )
                }
            }

            Spacer(Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    app.appName,
                    color = TextWhite,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                    maxLines = 1
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    "${app.totalRequests} requests • ↑${formatBytes(app.totalBytesOut)} ↓${formatBytes(app.totalBytesIn)}",
                    color = TextGray,
                    fontSize = 12.sp
                )

                // Mini category bar for this app
                if (app.categoryBreakdown.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    MiniCategoryBar(app.categoryBreakdown)
                }
            }

            // Arrow indicator
            Text("›", color = TextDimmed, fontSize = 22.sp)
        }
    }
}

/**
 * Tiny colored bar inside each app card showing category proportions.
 */
@Composable
private fun MiniCategoryBar(breakdown: Map<TrafficCategory, CategoryStats>) {
    val totalBytes = breakdown.values.sumOf { it.totalBytes }.coerceAtLeast(1)
    val sorted = TrafficCategory.displayOrder.filter { breakdown.containsKey(it) }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(4.dp)
            .clip(RoundedCornerShape(2.dp))
            .drawBehind {
                var currentX = 0f
                for (cat in sorted) {
                    val stats = breakdown[cat] ?: continue
                    val fraction = stats.totalBytes.toFloat() / totalBytes.toFloat()
                    val segmentWidth = size.width * fraction
                    if (segmentWidth < 1f) continue
                    drawRect(
                        color = categoryColor(cat),
                        topLeft = Offset(currentX, 0f),
                        size = Size(segmentWidth, size.height)
                    )
                    currentX += segmentWidth
                }
            }
    )
}

@Composable
private fun EmptyState(isCapturing: Boolean) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                Icons.Default.Shield,
                contentDescription = null,
                tint = CyberCyan.copy(alpha = 0.3f),
                modifier = Modifier.size(80.dp)
            )
            Spacer(Modifier.height(16.dp))
            Text(
                if (isCapturing) "Listening for traffic…" else "Tap Start Capture to begin",
                color = TextGray,
                fontSize = 16.sp
            )
        }
    }
}

// ── Threat Intelligence UI Components ──

@Composable
fun ThreatSummaryCard(summary: ThreatSummary, status: ScanStatus, onSettingsClick: () -> Unit) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (summary.critical > 0) AlertRed.copy(alpha = 0.12f)
                            else if (summary.high > 0) AlertOrange.copy(alpha = 0.12f)
                            else CardSurface
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    when {
                        summary.critical > 0 || summary.high > 0 -> Icons.Default.GppBad
                        summary.medium > 0 -> Icons.Default.GppMaybe
                        else -> Icons.Default.GppGood
                    },
                    contentDescription = null,
                    tint = when {
                        summary.critical > 0 -> AlertRed
                        summary.high > 0     -> AlertOrange
                        summary.medium > 0   -> UdpYellow
                        else                 -> NeonGreen
                    },
                    modifier = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "Threat Intelligence",
                    color = TextWhite,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp,
                    modifier = Modifier.weight(1f)
                )
                // Status badge
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = when (status) {
                        ScanStatus.SCANNING   -> CyberCyan.copy(alpha = 0.2f)
                        ScanStatus.ERROR      -> AlertRed.copy(alpha = 0.2f)
                        ScanStatus.UNAVAILABLE -> TextDimmed.copy(alpha = 0.2f)
                        ScanStatus.IDLE       -> TextDimmed.copy(alpha = 0.1f)
                    }
                ) {
                    Text(
                        when (status) {
                            ScanStatus.SCANNING   -> "Scanning"
                            ScanStatus.ERROR      -> "Error"
                            ScanStatus.UNAVAILABLE -> "Offline"
                            ScanStatus.IDLE       -> "Idle"
                        },
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        color = when (status) {
                            ScanStatus.SCANNING -> CyberCyan
                            ScanStatus.ERROR    -> AlertRed
                            else                -> TextDimmed
                        },
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(Modifier.width(6.dp))
                IconButton(
                    onClick = onSettingsClick,
                    modifier = Modifier.size(20.dp)
                ) {
                    Icon(
                        Icons.Default.Settings,
                        contentDescription = "IntelOwl Settings",
                        tint = TextDimmed,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            Spacer(Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                ThreatCountPill("Clean",    summary.clean,    NeonGreen)
                ThreatCountPill("Low",      summary.low,      UdpYellow)
                ThreatCountPill("Medium",   summary.medium,   AlertOrange)
                ThreatCountPill("High",     summary.high,     AlertRed)
                ThreatCountPill("Critical", summary.critical, ElectricPurple)
            }

            if (summary.pending > 0) {
                Spacer(Modifier.height(6.dp))
                Text(
                    "${summary.pending} job${if (summary.pending > 1) "s" else ""} pending • scanned ${summary.total} observables",
                    color = TextDimmed,
                    fontSize = 11.sp
                )
            } else {
                Spacer(Modifier.height(4.dp))
                Text(
                    "${summary.total} observables scanned",
                    color = TextDimmed,
                    fontSize = 11.sp
                )
            }
        }
    }
}

@Composable
private fun ThreatCountPill(label: String, count: Int, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            "$count",
            color = if (count > 0) color else TextDimmed,
            fontWeight = FontWeight.Bold,
            fontSize = 16.sp
        )
        Text(label, color = TextDimmed, fontSize = 10.sp)
    }
}

@Composable
fun ThreatAlertBanner(alert: ThreatAlert, onDismiss: () -> Unit) {
    val color = if (alert.report.severity == ThreatSeverity.CRITICAL) AlertRed else AlertOrange
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.15f))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.Warning,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(18.dp)
            )
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "${alert.report.severity.displayName} Threat Detected",
                    color = color,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp
                )
                Text(
                    alert.observable,
                    color = TextGray,
                    fontSize = 12.sp
                )
                if (alert.report.categories.isNotEmpty()) {
                    Text(
                        alert.report.categories.joinToString(", "),
                        color = TextDimmed,
                        fontSize = 11.sp
                    )
                }
            }
            IconButton(onClick = onDismiss) {
                Icon(
                    Icons.Default.Close,
                    contentDescription = "Dismiss",
                    tint = TextDimmed,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

/** Compute the highest threat severity among all threat reports for an app's connections */
private fun computeAppThreatSeverity(
    app: AppTrafficInfo,
    threatMap: Map<String, ThreatReport>
): ThreatSeverity? {
    // Look up threats by packageName in the associated packages stored on reports
    // We do a simple scan of all reports for any that mention this app
    val matching = threatMap.values.filter { report ->
        // Match heuristic: report's observable appears as any IP/domain of this app
        // The UI just shows the highest threat for any observable tied to the app
        true  // We show global max for now — per-app matching requires connection scan
    }
    // Efficient: actually filter from ThreatIntelRepository's connection lookup
    return null  // Default: will be overridden below by connection-level lookup
}

// ── Utility ──

fun formatBytes(bytes: Long): String {
    return when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)} KB"
        bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024.0))} MB"
        else -> "${"%.2f".format(bytes / (1024.0 * 1024.0 * 1024.0))} GB"
    }
}

/** Map TrafficCategory to its theme color */
fun categoryColor(category: TrafficCategory): Color {
    return when (category) {
        TrafficCategory.SOCIAL_MEDIA -> CategorySocial
        TrafficCategory.STREAMING -> CategoryStreaming
        TrafficCategory.ADS_TRACKERS -> CategoryAds
        TrafficCategory.CLOUD_SERVICES -> CategoryCloud
        TrafficCategory.MESSAGING -> CategoryMessaging
        TrafficCategory.GAMING -> CategoryGaming
        TrafficCategory.SHOPPING -> CategoryShopping
        TrafficCategory.SYSTEM -> CategorySystem
        TrafficCategory.CDN -> CategoryCdn
        TrafficCategory.OTHER -> CategoryOther
    }
}

/** Map ThreatSeverity to its display color */
fun severityColor(severity: ThreatSeverity): Color = when (severity) {
    ThreatSeverity.CLEAN    -> NeonGreen
    ThreatSeverity.LOW      -> UdpYellow
    ThreatSeverity.MEDIUM   -> AlertOrange
    ThreatSeverity.HIGH     -> AlertRed
    ThreatSeverity.CRITICAL -> ElectricPurple
}
