package com.example.netsecure.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.Protocol
import com.example.netsecure.ui.theme.*
import com.example.netsecure.ui.viewmodel.DashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportScreen(viewModel: DashboardViewModel) {
    val appList by viewModel.appTrafficList.collectAsState()

    Scaffold(
        containerColor = DarkNavy,
        topBar = {
            TopAppBar(
                title = {
                    Text("Privacy Report", fontWeight = FontWeight.Bold, color = TextWhite)
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DarkNavy)
            )
        }
    ) { padding ->
        if (appList.isEmpty()) {
            Box(
                Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Default.Info,
                        contentDescription = null,
                        tint = TextDimmed,
                        modifier = Modifier.size(64.dp)
                    )
                    Spacer(Modifier.height(12.dp))
                    Text("No data yet", color = TextGray, fontSize = 16.sp)
                    Text(
                        "Start capturing traffic to generate a report",
                        color = TextDimmed,
                        fontSize = 13.sp
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                contentPadding = PaddingValues(bottom = 24.dp)
            ) {
                // Overall summary
                item { OverallSummary(appList) }

                // Privacy concerns
                val concerns = generateConcerns(appList)
                if (concerns.isNotEmpty()) {
                    item {
                        Text(
                            "⚠️ Privacy Concerns",
                            color = AlertOrange,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp,
                            modifier = Modifier.padding(top = 8.dp)
                        )
                    }
                    items(concerns) { concern ->
                        ConcernCard(concern)
                    }
                }

                // Top talkers
                item {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Top Talkers",
                        color = TextGray,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp
                    )
                }

                items(appList.take(5)) { app ->
                    TopTalkerCard(app)
                }
            }
        }
    }
}

@Composable
private fun OverallSummary(appList: List<AppTrafficInfo>) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface)
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Text("Summary", color = CyberCyan, fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.height(12.dp))

            val totalRequests = appList.sumOf { it.totalRequests }
            val totalData = appList.sumOf { it.totalBytesOut }

            SummaryLine("Total apps communicating", "${appList.size}")
            SummaryLine("Total requests captured", "$totalRequests")
            SummaryLine("Total data transferred", formatBytes(totalData))
        }
    }
}

@Composable
private fun SummaryLine(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = TextGray, fontSize = 14.sp)
        Text(value, color = TextWhite, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
    }
}

data class PrivacyConcern(
    val title: String,
    val description: String,
    val severity: Severity
)

enum class Severity { HIGH, MEDIUM, LOW }

private fun generateConcerns(appList: List<AppTrafficInfo>): List<PrivacyConcern> {
    val concerns = mutableListOf<PrivacyConcern>()

    // Apps with massive data transfers (>10MB)
    val bigSenders = appList.filter { it.totalBytesOut > 10_000_000 }
    for (app in bigSenders) {
        concerns.add(
            PrivacyConcern(
                title = "${app.appName} transferred ${formatBytes(app.totalBytesOut)}",
                description = "Unusually high background data transfer detected. Tap the app to review connections.",
                severity = Severity.HIGH
            )
        )
    }
    
    // High connection frequency
    val spammyApps = appList.filter { it.totalRequests > 1000 }
    for (app in spammyApps) {
        concerns.add(
            PrivacyConcern(
                title = "${app.appName} — High Request Rate",
                description = "This app is making a suspicious amount of connections (${app.totalRequests} reqs).",
                severity = Severity.MEDIUM
            )
        )
    }

    return concerns
}

@Composable
private fun ConcernCard(concern: PrivacyConcern) {
    val borderColor = when (concern.severity) {
        Severity.HIGH -> AlertRed
        Severity.MEDIUM -> AlertOrange
        Severity.LOW -> UdpYellow
    }

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = borderColor.copy(alpha = 0.1f))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.Top
        ) {
            Icon(
                Icons.Default.Warning,
                contentDescription = null,
                tint = borderColor,
                modifier = Modifier.size(20.dp)
            )
            Spacer(Modifier.width(10.dp))
            Column {
                Text(
                    concern.title,
                    color = TextWhite,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    concern.description,
                    color = TextGray,
                    fontSize = 12.sp
                )
            }
        }
    }
}

@Composable
private fun TopTalkerCard(app: AppTrafficInfo) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    app.appName,
                    color = TextWhite,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp
                )
                Text(
                    "${app.totalRequests} requests",
                    color = TextDimmed,
                    fontSize = 12.sp
                )
            }
            Text(
                formatBytes(app.totalBytesOut),
                color = CyberCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
        }
    }
}
