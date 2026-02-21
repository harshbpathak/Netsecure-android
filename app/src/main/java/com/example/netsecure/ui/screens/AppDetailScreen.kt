
package com.example.netsecure.ui.screens

import android.graphics.drawable.Drawable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.example.netsecure.data.model.AppTrafficInfo
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

                item {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Connections (${connections.size})",
                        color = TextGray,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                items(connections.reversed().take(300), key = { it.incr_id }) { conn ->
                    ConnectionCard(conn)
                }
            }
        }
    }
}

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
private fun ConnectionCard(conn: ConnectionDescriptor) {
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

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = if (isSuspicious) AlertRed.copy(alpha=0.15f) else CardSurfaceLight),
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

                Spacer(Modifier.width(12.dp))

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
                    Divider(color = TextDimmed.copy(alpha = 0.2f), thickness = 1.dp)
                    Spacer(Modifier.height(8.dp))

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
    // Native timestamps are often in milliseconds, but sometimes seconds.
    // If it's less than a year 2000 in seconds, treat as seconds. 
    // Usually PCAPdroid sends seconds * 1000 + ms for first_seen, meaning ms.
    val actualMs = if (timestampSecs < 10000000000L) timestampSecs * 1000 else timestampSecs
    val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    return sdf.format(Date(actualMs))
}

