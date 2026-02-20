package com.example.netsecure.ui.screens

import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.ConnectionRecord
import com.example.netsecure.data.model.Protocol
import com.example.netsecure.ui.theme.*
import com.example.netsecure.ui.viewmodel.AppDetailViewModel

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

    Scaffold(
        containerColor = DarkNavy,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        appTraffic?.appName ?: packageName,
                        fontWeight = FontWeight.Bold,
                        color = TextWhite
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
                Modifier.fillMaxSize().padding(padding),
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
                    AppHeaderCard(traffic)
                }

                item {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Connections (${traffic.connections.size})",
                        color = TextGray,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                items(traffic.connections.reversed().take(200)) { conn ->
                    ConnectionCard(conn)
                }
            }
        }
    }
}

@Composable
private fun AppHeaderCard(traffic: AppTrafficInfo) {
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
                StatItem("Connections", "${traffic.connections.size}", NeonGreen)
            }
        }
    }
}

@Composable
private fun StatItem(label: String, value: String, color: androidx.compose.ui.graphics.Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, color = color, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        Text(label, color = TextGray, fontSize = 11.sp)
    }
}

@Composable
private fun ConnectionCard(conn: ConnectionRecord) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurfaceLight)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            ProtocolChip(conn.protocol)

            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "${conn.destIp}:${conn.destPort}",
                    color = TextWhite,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    formatTimestamp(conn.timestamp),
                    color = TextDimmed,
                    fontSize = 11.sp
                )
            }

            Text(
                formatBytes(conn.packetSize.toLong()),
                color = TextGray,
                fontSize = 12.sp
            )
        }
    }
}

@Composable
private fun ProtocolChip(protocol: Protocol) {
    val (bgColor, textColor) = when (protocol) {
        Protocol.DNS -> DnsBlue to TextWhite
        Protocol.HTTP -> HttpOrange to DarkNavy
        Protocol.HTTPS -> HttpsGreen to DarkNavy
        Protocol.TCP -> TcpGray to TextWhite
        Protocol.UDP -> UdpYellow to DarkNavy
        Protocol.UNKNOWN -> TextDimmed to TextWhite
    }

    Surface(
        shape = RoundedCornerShape(6.dp),
        color = bgColor.copy(alpha = 0.85f)
    ) {
        Text(
            protocol.label,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
            color = textColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

private fun formatTimestamp(timestamp: Long): String {
    val sdf = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
    return sdf.format(java.util.Date(timestamp))
}
