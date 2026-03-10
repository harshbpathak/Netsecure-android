package com.example.netsecure.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.netsecure.data.model.ThreatSeverity
import com.example.netsecure.ui.theme.*
import com.example.netsecure.ui.viewmodel.ThreatIntelViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatIntelligenceScreen(
    onBack: () -> Unit,
    vm: ThreatIntelViewModel = viewModel()
) {
    val rows          by vm.rows.collectAsState()
    val counts        by vm.severityCounts.collectAsState()
    val isLoading     by vm.isLoading.collectAsState()
    val errorMessage  by vm.errorMessage.collectAsState()
    val totalOnServer by vm.totalJobsOnServer.collectAsState()

    var searchText     by remember { mutableStateOf("") }
    var activeFilter   by remember { mutableStateOf<ThreatSeverity?>(null) }
    var expandedRow    by remember { mutableStateOf<String?>(null) }

    Scaffold(
        containerColor = DarkNavy,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Threat Intelligence", fontWeight = FontWeight.Bold,
                            color = TextWhite, fontSize = 17.sp)
                        if (totalOnServer > 0)
                            Text("$totalOnServer jobs on IntelOwl server",
                                color = TextDimmed, fontSize = 11.sp)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = CyberCyan)
                    }
                },
                actions = {
                    IconButton(onClick = { vm.fetchRemoteJobs() }) {
                        if (isLoading)
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = CyberCyan, strokeWidth = 2.dp
                            )
                        else
                            Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberCyan)
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
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(bottom = 32.dp, top = 4.dp)
        ) {

            // ── Severity Distribution Chart ──
            item {
                SeverityBarChart(counts = counts)
            }

            // ── Search bar ──
            item {
                OutlinedTextField(
                    value = searchText,
                    onValueChange = { searchText = it; vm.setSearch(it) },
                    placeholder = { Text("Search IP or domain…", color = TextDimmed, fontSize = 13.sp) },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextDimmed) },
                    trailingIcon = {
                        if (searchText.isNotBlank())
                            IconButton(onClick = { searchText = ""; vm.setSearch("") }) {
                                Icon(Icons.Default.Clear, contentDescription = null, tint = TextDimmed)
                            }
                    },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = CardBorder,
                        focusedTextColor = TextWhite,
                        unfocusedTextColor = TextWhite,
                        cursorColor = CyberCyan
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
            }

            // ── Filter chips ──
            item {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    item {
                        FilterPill("All", activeFilter == null, CyberCyan) {
                            activeFilter = null; vm.setFilter(null)
                        }
                    }
                    items(ThreatSeverity.values().toList()) { sev ->
                        FilterPill(sev.displayName, activeFilter == sev, severityColor(sev)) {
                            activeFilter = if (activeFilter == sev) { vm.setFilter(null); null }
                            else { vm.setFilter(sev); sev }
                        }
                    }
                }
            }

            // ── Error banner ──
            if (errorMessage != null) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = AlertRed.copy(alpha = 0.15f)),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Warning, contentDescription = null,
                                tint = AlertRed, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(errorMessage ?: "", color = AlertRed, fontSize = 12.sp)
                        }
                    }
                }
            }

            // ── Empty state ──
            if (rows.isEmpty() && !isLoading) {
                item {
                    Box(Modifier.fillMaxWidth().padding(vertical = 48.dp),
                        contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.Shield, contentDescription = null,
                                tint = TextDimmed, modifier = Modifier.size(56.dp))
                            Spacer(Modifier.height(12.dp))
                            Text(
                                if (activeFilter != null || searchText.isNotBlank())
                                    "No results match your filter"
                                else "No scans yet — start capturing traffic",
                                color = TextGray, fontSize = 14.sp
                            )
                        }
                    }
                }
            }

            // ── Table header ──
            if (rows.isNotEmpty()) {
                item {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 4.dp, vertical = 2.dp)
                    ) {
                        Text("Observable", color = TextDimmed, fontSize = 11.sp, modifier = Modifier.weight(1f))
                        Text("Severity", color = TextDimmed, fontSize = 11.sp, modifier = Modifier.width(70.dp))
                        Text("Score", color = TextDimmed, fontSize = 11.sp, modifier = Modifier.width(40.dp))
                    }
                }
            }

            // ── Observable rows ──
            items(rows, key = { it.observable }) { row ->
                val isExpanded = expandedRow == row.observable
                ObservableCard(
                    row = row,
                    isExpanded = isExpanded,
                    onClick = {
                        expandedRow = if (isExpanded) null else row.observable
                    }
                )
            }
        }
    }
}

// ─────────────────────────────────────── Components ────────────────────────────────────────

@Composable
private fun SeverityBarChart(counts: ThreatIntelViewModel.SeverityCounts) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.BarChart, contentDescription = null,
                    tint = CyberCyan, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Severity Distribution", color = CyberCyan,
                    fontWeight = FontWeight.Bold, fontSize = 15.sp)
                Spacer(Modifier.weight(1f))
                Text("${counts.total} scanned", color = TextDimmed, fontSize = 11.sp)
            }
            Spacer(Modifier.height(16.dp))

            if (counts.total == 0) {
                Text("No data yet", color = TextDimmed, fontSize = 12.sp,
                    modifier = Modifier.align(Alignment.CenterHorizontally))
            } else {
                val bars = listOf(
                    Triple("Critical", counts.critical, AlertRed),
                    Triple("High",     counts.high,     AlertOrange),
                    Triple("Medium",   counts.medium,   UdpYellow),
                    Triple("Low",      counts.low,      NeonGreen.copy(alpha = 0.7f)),
                    Triple("Clean",    counts.clean,    CyberCyan.copy(alpha = 0.6f))
                )
                bars.forEach { (label, count, color) ->
                    if (count > 0 || label == "Clean") {
                        SeverityBarRow(label, count, counts.total, color)
                        Spacer(Modifier.height(8.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun SeverityBarRow(label: String, count: Int, total: Int, color: Color) {
    val fraction = if (total > 0) count.toFloat() / total else 0f
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = TextGray, fontSize = 12.sp,
            modifier = Modifier.width(56.dp))
        Box(
            Modifier
                .weight(1f)
                .height(10.dp)
                .clip(RoundedCornerShape(5.dp))
                .background(CardSurface)
        ) {
            if (fraction > 0f) {
                Box(
                    Modifier
                        .fillMaxHeight()
                        .fillMaxWidth(fraction)
                        .clip(RoundedCornerShape(5.dp))
                        .background(color)
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        Text("$count", color = color, fontSize = 12.sp,
            fontWeight = FontWeight.Bold, modifier = Modifier.width(24.dp))
        Text("(${(fraction * 100).toInt()}%)", color = TextDimmed, fontSize = 10.sp)
    }
}

@Composable
private fun FilterPill(
    label: String,
    selected: Boolean,
    color: Color,
    onClick: () -> Unit
) {
    val bg    = if (selected) color.copy(alpha = 0.20f) else CardSurface
    val textC = if (selected) color else TextGray
    Box(
        Modifier
            .clip(RoundedCornerShape(20.dp))
            .background(bg)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 6.dp)
    ) {
        Text(label, color = textC, fontSize = 12.sp, fontWeight =
            if (selected) FontWeight.SemiBold else FontWeight.Normal)
    }
}

@Composable
private fun ObservableCard(
    row: ThreatIntelViewModel.ObservableRow,
    isExpanded: Boolean,
    onClick: () -> Unit
) {
    val severityColor = severityColor(row.severity)

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isExpanded) CardSurface.copy(alpha = 0.95f) else CardSurface
        ),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
    ) {
        Column(Modifier.fillMaxWidth()) {
            // ── Collapsed row ──
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Type icon
                Icon(
                    if (row.classification == "ip") Icons.Default.Dns else Icons.Default.Language,
                    contentDescription = null,
                    tint = severityColor,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(Modifier.width(10.dp))

                // Observable + summary
                Column(Modifier.weight(1f)) {
                    Text(
                        row.observable,
                        color = TextWhite,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        row.analyzerSummary,
                        color = TextDimmed,
                        fontSize = 11.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Spacer(Modifier.width(8.dp))

                // Severity badge
                SeverityBadge(row.severity)

                Spacer(Modifier.width(8.dp))

                // Score %
                Text(
                    "${(row.score * 100).toInt()}%",
                    color = severityColor,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.width(36.dp)
                )

                // Expand arrow
                Icon(
                    if (isExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    tint = TextDimmed,
                    modifier = Modifier.size(16.dp)
                )
            }

            // ── Score bar ──
            if (row.score > 0f) {
                Box(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp)
                        .height(3.dp)
                        .clip(RoundedCornerShape(2.dp))
                        .background(CardBorder)
                ) {
                    Box(
                        Modifier
                            .fillMaxHeight()
                            .fillMaxWidth(row.score)
                            .clip(RoundedCornerShape(2.dp))
                            .background(severityColor)
                    )
                }
                Spacer(Modifier.height(4.dp))
            }

            // ── Expanded detail ──
            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically(),
                exit = shrinkVertically()
            ) {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(start = 14.dp, end = 14.dp, bottom = 14.dp)
                ) {
                    HorizontalDivider(color = CardBorder, thickness = 0.5.dp)
                    Spacer(Modifier.height(10.dp))

                    // Metadata
                    Row {
                        MetaChip("Type", row.classification.uppercase())
                        Spacer(Modifier.width(8.dp))
                        if (row.intelOwlJobId != null)
                            MetaChip("Job #", "${row.intelOwlJobId}")
                        Spacer(Modifier.width(8.dp))
                        MetaChip("Source", row.source.name)
                    }
                    Spacer(Modifier.height(10.dp))

                    // Analyzer results
                    if (row.analyzersDetail.isEmpty()) {
                        Text(
                            if (row.source == ThreatIntelViewModel.Source.REMOTE)
                                "Tap Refresh to load this job's analyzer results into the local score"
                            else "No analyzer details available",
                            color = TextDimmed, fontSize = 11.sp
                        )
                    } else {
                        Text("Analyzer Results", color = CyberCyan,
                            fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                        Spacer(Modifier.height(6.dp))
                        row.analyzersDetail.forEach { detail ->
                            AnalyzerResultRow(detail)
                            Spacer(Modifier.height(4.dp))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SeverityBadge(severity: ThreatSeverity) {
    val color = severityColor(severity)
    Box(
        Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(color.copy(alpha = 0.18f))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Text(severity.displayName, color = color,
            fontSize = 10.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun MetaChip(label: String, value: String) {
    Row(
        Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(CardBorder.copy(alpha = 0.5f))
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text("$label: ", color = TextDimmed, fontSize = 10.sp)
        Text(value, color = TextWhite, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun AnalyzerResultRow(detail: ThreatIntelViewModel.AnalyzerDetail) {
    val scoreColor = when {
        detail.score >= 0.7f -> AlertRed
        detail.score >= 0.4f -> AlertOrange
        detail.score >= 0.1f -> UdpYellow
        else -> NeonGreen.copy(alpha = 0.7f)
    }
    Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Dot
        Box(
            Modifier
                .size(7.dp)
                .clip(CircleShape)
                .background(scoreColor)
        )
        Spacer(Modifier.width(8.dp))
        Text(detail.name, color = TextGray, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(detail.verdict, color = scoreColor, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.width(8.dp))
        Text("${(detail.score * 100).toInt()}%", color = TextDimmed, fontSize = 11.sp)
    }
}

// severityColor() is defined in DashboardScreen.kt (same package — visible here)
