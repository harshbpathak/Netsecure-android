
package com.example.netsecure.ui.screens

import android.graphics.drawable.Drawable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.AnalyzerResult
import com.example.netsecure.data.model.CategoryStats
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.ThreatSeverity
import com.example.netsecure.data.model.TrafficCategory
import com.example.netsecure.model.ConnectionDescriptor
import com.example.netsecure.ui.theme.*
import com.example.netsecure.ui.viewmodel.AppDetailViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppDetailScreen(
    packageName: String,
    viewModel: AppDetailViewModel,
    onBack: () -> Unit
) {
    LaunchedEffect(packageName) {
        viewModel.loadApp(packageName)
    }

    val appTraffic by viewModel.appTraffic.collectAsState()
    val connections by viewModel.connections.collectAsState()
    val selectedCategory by viewModel.selectedCategory.collectAsState()
    val threatMap by viewModel.threatMap.collectAsState()

    Scaffold(
        containerColor = DarkNavy,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        appTraffic?.appName ?: packageName,
                        fontWeight = FontWeight.Bold,
                        color = TextWhite,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = CyberCyan
                        )
                    }
                },
                actions = {
                    val context = LocalContext.current
                    if (connections.isNotEmpty()) {
                        IconButton(onClick = { viewModel.exportAppConnectionsCsv(context) }) {
                            Icon(
                                Icons.Default.Download,
                                contentDescription = "Download CSV",
                                tint = CyberCyan
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DarkNavy)
            )
        }
    ) { padding ->
        val traffic = appTraffic
        if (traffic == null) {
            Box(
                Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text("No data available", color = TextGray)
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 24.dp)
            ) {
                // App header card
                item {
                    AppHeaderCard(traffic, connections.size)
                }

                // Category breakdown for this app
                if (traffic.categoryBreakdown.isNotEmpty()) {
                    item {
                        AppCategoryBreakdown(traffic.categoryBreakdown)
                    }

                    // Category filter chips
                    item {
                        DetailCategoryChipRow(
                            breakdown = traffic.categoryBreakdown,
                            selectedCategory = selectedCategory,
                            onCategoryClick = { viewModel.selectCategory(it) }
                        )
                    }
                }

                item {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        if (selectedCategory != null) {
                            "${selectedCategory!!.label} Connections (${connections.size})"
                        } else {
                            "Connections (${connections.size})"
                        },
                        color = TextGray,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                items(connections.reversed().take(300), key = { it.incr_id }) { conn ->
                    val threat = remember(conn.incr_id, threatMap) {
                        viewModel.getThreatForConnection(conn)
                    }
                    ConnectionCard(conn, threat)
                }
            }
        }
    }
}

// ── App Category Breakdown Card ──

@Composable
private fun AppCategoryBreakdown(breakdown: Map<TrafficCategory, CategoryStats>) {
    val totalBytes = breakdown.values.sumOf { it.totalBytes }.coerceAtLeast(1)
    val sorted = TrafficCategory.displayOrder.filter { breakdown.containsKey(it) }

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
                "Traffic Categories",
                color = TextWhite,
                fontWeight = FontWeight.SemiBold,
                fontSize = 14.sp
            )
            Spacer(Modifier.height(10.dp))

            // Category rows (show each category with its proportion)
            for (cat in sorted) {
                val stats = breakdown[cat] ?: continue
                val pct = ((stats.totalBytes * 100) / totalBytes).toInt()
                val color = categoryColor(cat)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(color)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        cat.label,
                        color = TextGray,
                        fontSize = 12.sp,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        "${stats.requests} reqs",
                        color = TextDimmed,
                        fontSize = 11.sp
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        formatBytes(stats.totalBytes),
                        color = color,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        "$pct%",
                        color = TextDimmed,
                        fontSize = 11.sp
                    )
                }
            }
        }
    }
}

// ── Detail Category Chip Row ──

@Composable
private fun DetailCategoryChipRow(
    breakdown: Map<TrafficCategory, CategoryStats>,
    selectedCategory: TrafficCategory?,
    onCategoryClick: (TrafficCategory) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        // "All" chip
        FilterChip(
            selected = selectedCategory == null,
            onClick = { if (selectedCategory != null) onCategoryClick(selectedCategory) },
            label = { Text("All", fontSize = 11.sp) },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = CyberCyan.copy(alpha = 0.2f),
                selectedLabelColor = CyberCyan,
                containerColor = CardSurfaceLight,
                labelColor = TextGray
            ),
            border = FilterChipDefaults.filterChipBorder(
                borderColor = Color.Transparent,
                selectedBorderColor = CyberCyan.copy(alpha = 0.5f),
                enabled = true,
                selected = selectedCategory == null
            ),
            shape = RoundedCornerShape(8.dp)
        )

        for (cat in TrafficCategory.displayOrder) {
            if (!breakdown.containsKey(cat)) continue
            val isSelected = selectedCategory == cat
            val color = categoryColor(cat)

            FilterChip(
                selected = isSelected,
                onClick = { onCategoryClick(cat) },
                label = { Text(cat.label, fontSize = 11.sp) },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = color.copy(alpha = 0.15f),
                    selectedLabelColor = color,
                    containerColor = CardSurfaceLight,
                    labelColor = TextGray
                ),
                border = FilterChipDefaults.filterChipBorder(
                    borderColor = Color.Transparent,
                    selectedBorderColor = color.copy(alpha = 0.5f),
                    enabled = true,
                    selected = isSelected
                ),
                shape = RoundedCornerShape(8.dp)
            )
        }
    }
}

// ── Existing components (unchanged) ──

@Composable
private fun AppHeaderCard(traffic: AppTrafficInfo, connectionCount: Int) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // App icon
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.linearGradient(
                            listOf(CyberCyanDark.copy(alpha = 0.3f), ElectricPurpleDark.copy(alpha = 0.3f))
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                if (traffic.appIcon != null) {
                    val bitmap = remember(traffic.appIcon) {
                        traffic.appIcon.toBitmap(48, 48).asImageBitmap()
                    }
                    Image(
                        bitmap = bitmap,
                        contentDescription = traffic.appName,
                        modifier = Modifier.size(48.dp)
                    )
                } else {
                    Text(
                        traffic.appName.take(1).uppercase(),
                        color = CyberCyan,
                        fontWeight = FontWeight.Bold,
                        fontSize = 24.sp
                    )
                }
            }

            Spacer(Modifier.height(12.dp))

            Text(
                traffic.appName,
                color = TextWhite,
                fontWeight = FontWeight.Bold,
                fontSize = 20.sp
            )
            Text(
                traffic.packageName,
                color = TextDimmed,
                fontSize = 12.sp
            )

            Spacer(Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                StatItem("Requests", "${traffic.totalRequests}", CyberCyan)
                StatItem("Data Out", formatBytes(traffic.totalBytesOut), ElectricPurple)
                StatItem("Connections", "$connectionCount", NeonGreen)
            }
        }
    }
}

@Composable
private fun StatItem(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, color = color, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        Text(label, color = TextGray, fontSize = 11.sp)
    }
}

@Composable
private fun ConnectionCard(conn: ConnectionDescriptor, threat: ThreatReport? = null) {
    var expanded by remember { mutableStateOf(false) }

    val isSuspicious = conn.is_blacklisted_domain || conn.is_blacklisted_ip
    val isBlocked = conn.is_blocked
    val l7str = if (conn.l7proto.isNotEmpty()) conn.l7proto else formatL4Proto(conn.ipproto)

    // SNI / Info string to display
    val displayInfo = if (conn.info.isNotEmpty()) {
        conn.info
    } else if (conn.url.isNotEmpty()) {
        conn.url
    } else {
        "${conn.dst_ip}:${conn.dst_port}"
    }

    // Show category tag
    val category = TrafficRepository.getCategoryForConnection(conn.incr_id)

    // Threat severity color
    val threatColor = threat?.let { severityColor(it.severity) }

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                isSuspicious -> AlertRed.copy(alpha = 0.15f)
                threat != null && threat.severity.ordinalScore >= ThreatSeverity.HIGH.ordinalScore -> AlertRed.copy(alpha = 0.10f)
                threat != null && threat.severity == ThreatSeverity.MEDIUM -> AlertOrange.copy(alpha = 0.08f)
                else -> CardSurfaceLight
            }
        ),
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                ProtocolChip(l7str)

                Spacer(Modifier.width(8.dp))

                // Threat shield icon
                if (threat != null && threat.severity != ThreatSeverity.CLEAN) {
                    Icon(
                        Icons.Default.Shield,
                        contentDescription = "Threat: ${threat.severity.displayName}",
                        tint = threatColor ?: TextDimmed,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(4.dp))
                }

                Spacer(Modifier.width(4.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        displayInfo,
                        color = if (isSuspicious) AlertRed else TextWhite,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        // Category tag
                        if (category != TrafficCategory.OTHER) {
                            Text(
                                category.label,
                                color = categoryColor(category),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Spacer(Modifier.width(6.dp))
                            Text("•", color = TextDimmed, fontSize = 10.sp)
                            Spacer(Modifier.width(6.dp))
                        }
                        Text(
                            formatTimestamp(conn.first_seen),
                            color = TextDimmed,
                            fontSize = 11.sp
                        )
                        if (isSuspicious || isBlocked) {
                            Spacer(Modifier.width(6.dp))
                            Icon(
                                Icons.Default.Warning,
                                contentDescription = "Suspicious",
                                tint = AlertRed,
                                modifier = Modifier.size(12.dp)
                            )
                            Spacer(Modifier.width(2.dp))
                            Text(
                                if (isBlocked) "Blocked" else "Suspicious",
                                color = AlertRed,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(horizontalAlignment = Alignment.End) {
                        Text(
                            formatBytes(conn.sent_bytes + conn.rcvd_bytes),
                            color = TextGray,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    Icon(
                        if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        contentDescription = "Expand",
                        tint = TextGray,
                        modifier = Modifier
                            .padding(start = 4.dp)
                            .size(20.dp)
                    )
                }
            }

            // Expanded Details
            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically(animationSpec = tween(300)),
                exit = shrinkVertically(animationSpec = tween(300))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp)
                ) {
                    HorizontalDivider(color = TextDimmed.copy(alpha = 0.2f), thickness = 1.dp)
                    Spacer(Modifier.height(8.dp))

                    DetailRow("Category", category.label)
                    DetailRow("Destination IP", conn.dst_ip)
                    DetailRow("Destination Port", "${conn.dst_port}")
                    if (conn.country.isNotEmpty() && conn.country != "Unknown") {
                        DetailRow("Country", conn.country)
                    }
                    DetailRow("Protocol", if (conn.l7proto.isNotEmpty()) "${conn.l7proto} / ${formatL4Proto(conn.ipproto)}" else formatL4Proto(conn.ipproto))
                    DetailRow("Traffic Size", "Up: ${formatBytes(conn.sent_bytes)}  |  Down: ${formatBytes(conn.rcvd_bytes)}")
                    DetailRow("Packets", "Up: ${conn.sent_pkts}  |  Down: ${conn.rcvd_pkts}")
                    DetailRow("Encryption", if (conn.encrypted_l7) "Encrypted (TLS/SSL)" else "Unencrypted", 
                        icon = if (conn.encrypted_l7) Icons.Default.Lock else Icons.Default.LockOpen,
                        iconColor = if (conn.encrypted_l7) HttpsGreen else HttpOrange)
                    DetailRow("Status", formatStatus(conn.status))

                    // IntelOwl threat detail section
                    if (threat != null) {
                        Spacer(Modifier.height(8.dp))
                        HorizontalDivider(color = TextDimmed.copy(alpha = 0.2f), thickness = 1.dp)
                        Spacer(Modifier.height(8.dp))
                        ThreatDetailSection(threat)
                    }

                    // Payload Chunk View
                    if (!conn.payload_chunks.isNullOrEmpty()) {
                        PayloadDetailSection(conn)
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String, icon: androidx.compose.ui.graphics.vector.ImageVector? = null, iconColor: Color? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = TextGray, fontSize = 12.sp)
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (icon != null && iconColor != null) {
                Icon(icon, contentDescription = null, tint = iconColor, modifier = Modifier.size(12.dp))
                Spacer(Modifier.width(4.dp))
            }
            Text(value, color = TextWhite, fontSize = 12.sp, fontWeight = FontWeight.Medium)
        }
    }
}

@Composable
private fun ProtocolChip(protocol: String) {
    val upperProto = protocol.uppercase()
    val bgColor = when {
        upperProto.contains("DNS") -> DnsBlue
        upperProto.contains("HTTPS") || upperProto.contains("TLS") || upperProto.contains("QUIC") -> HttpsGreen
        upperProto.contains("HTTP") -> HttpOrange
        upperProto.contains("TCP") -> TcpGray
        upperProto.contains("UDP") -> UdpYellow
        else -> ElectricPurple
    }

    Surface(
        shape = RoundedCornerShape(6.dp),
        color = bgColor.copy(alpha = 0.85f),
        modifier = Modifier.defaultMinSize(minWidth = 52.dp)
    ) {
        Text(
            protocol.take(6), // Truncate very long protocol names
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp),
            color = if (bgColor == HttpOrange || bgColor == HttpsGreen || bgColor == UdpYellow) DarkNavy else TextWhite,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center
        )
    }
}

private fun formatL4Proto(ipproto: Int): String {
    return when (ipproto) {
        6 -> "TCP"
        17 -> "UDP"
        1 -> "ICMP"
        else -> "IP-$ipproto"
    }
}

private fun formatStatus(status: Int): String {
    return when (status) {
        0 -> "New"
        1 -> "Active"
        2 -> "Closed"
        3 -> "Unreachable"
        4 -> "Error"
        else -> "Unknown"
    }
}

private fun formatTimestamp(timestampSecs: Long): String {
    if (timestampSecs <= 0) return "Just now"
    val actualMs = if (timestampSecs < 10000000000L) timestampSecs * 1000 else timestampSecs
    val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    return sdf.format(Date(actualMs))
}

// ── Threat Detail Section ──

@Composable
fun ThreatDetailSection(report: ThreatReport) {
    val color = severityColor(report.severity)
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(
                Icons.Default.Shield,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(16.dp)
            )
            Spacer(Modifier.width(6.dp))
            Text(
                "IntelOwl: ${report.severity.displayName} Threat",
                color = color,
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                modifier = Modifier.weight(1f)
            )
            Text(
                "Score: ${"%,.0f".format(report.overallScore * 100)}%",
                color = color,
                fontSize = 12.sp
            )
        }

        // Score bar
        Spacer(Modifier.height(6.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(androidx.compose.foundation.shape.RoundedCornerShape(3.dp))
                .background(CardSurfaceLight)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(report.overallScore.coerceIn(0f, 1f))
                    .fillMaxHeight()
                    .clip(androidx.compose.foundation.shape.RoundedCornerShape(3.dp))
                    .background(color)
            )
        }

        // Categories
        if (report.categories.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                report.categories.forEach { cat ->
                    Surface(
                        shape = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
                        color = color.copy(alpha = 0.2f)
                    ) {
                        Text(
                            cat,
                            color = color,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }
            }
        }

        // Analyzer results
        if (report.analyzerResults.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            report.analyzerResults.forEach { result ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        result.analyzerName,
                        color = TextGray,
                        fontSize = 11.sp,
                        modifier = Modifier.width(120.dp)
                    )
                    val resultColor = severityColor(com.example.netsecure.data.model.ThreatSeverity.fromScore(result.score))
                    Text(
                        result.verdict,
                        color = resultColor,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    }
}

// ── Payload View Section ──

@Composable
fun PayloadDetailSection(conn: ConnectionDescriptor) {
    val chunks = conn.payload_chunks
    if (chunks.isNullOrEmpty()) return

    Spacer(Modifier.height(8.dp))
    HorizontalDivider(color = TextDimmed.copy(alpha = 0.2f), thickness = 1.dp)
    Spacer(Modifier.height(8.dp))

    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Default.Code, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text("Payload Chunks (${chunks.size})", color = CyberCyan, fontWeight = FontWeight.Bold, fontSize = 13.sp)
    }

    Spacer(Modifier.height(6.dp))
    
    // Display max 3 chunks to prevent massive UI lag
    val displayChunks = chunks.take(3)
    for ((index, chunk) in displayChunks.withIndex()) {
        val payloadStr = String(chunk.data, Charsets.UTF_8).take(250) // limit size
        val cleanedPayload = payloadStr.replace(Regex("[\\x00-\\x1F&&[^\r\n\t]]"), ".") // Replace unprintable chars
        
        Surface(
            shape = RoundedCornerShape(8.dp),
            color = DarkNavy.copy(alpha = 0.5f),
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
        ) {
            Column(modifier = Modifier.padding(8.dp)) {
                Text(
                    text = "Chunk ${index + 1} (${chunk.data.size} bytes) - Pkt Type: ${chunk.type}",
                    color = TextGray,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = cleanedPayload.ifBlank { "<Binary or Empty Data>" },
                    color = NeonGreen,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    fontSize = 10.sp,
                    maxLines = 10,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
    
    if (chunks.size > 3) {
        Text("... and ${chunks.size - 3} more chunks", color = TextDimmed, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
    }
}
