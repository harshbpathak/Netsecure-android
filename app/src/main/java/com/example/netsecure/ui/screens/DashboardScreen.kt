package com.example.netsecure.ui.screens


import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.ui.theme.*
import com.example.netsecure.ui.viewmodel.DashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel,
    onAppClick: (String) -> Unit,
    onPrepareVpn: () -> Unit
) {
    val appList by viewModel.appTrafficList.collectAsState()
    val isCapturing by viewModel.isCapturing.collectAsState()

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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            // Summary cards
            SummaryRow(appList, isCapturing)

            Spacer(Modifier.height(16.dp))

            if (appList.isEmpty()) {
                EmptyState(isCapturing)
            } else {
                Text(
                    "Apps Detected",
                    color = TextGray,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 80.dp)
                ) {
                    items(appList, key = { it.packageName }) { app ->
                        AppTrafficCard(app = app, onClick = { onAppClick(app.packageName) })
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryRow(appList: List<AppTrafficInfo>, isCapturing: Boolean) {
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
        SummaryCard(
            label = "Data",
            value = formatBytes(appList.sumOf { it.totalBytesOut + it.totalBytesIn }),
            color = NeonGreen,
            modifier = Modifier.weight(1f)
        )
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
private fun AppTrafficCard(app: AppTrafficInfo, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // App icon
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
            }

            // Arrow indicator
            Text("›", color = TextDimmed, fontSize = 22.sp)
        }
    }
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

fun formatBytes(bytes: Long): String {
    return when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)} KB"
        bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024.0))} MB"
        else -> "${"%.2f".format(bytes / (1024.0 * 1024.0 * 1024.0))} GB"
    }
}
