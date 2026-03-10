package com.example.netsecure.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Environment
import android.widget.Toast
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.netsecure.logging.NetSecureLogger
import com.example.netsecure.ui.theme.*
import com.example.netsecure.ui.viewmodel.LogsViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(
    onBack: () -> Unit,
    vm: LogsViewModel = viewModel()
) {
    val context     = LocalContext.current
    val entries     by vm.entries.collectAsState()
    val filterLevel by vm.filterLevel.collectAsState()
    val filterTag   by vm.filterTag.collectAsState()
    val searchQuery by vm.searchQuery.collectAsState()
    val isLive      by vm.isLiveMode.collectAsState()
    val listState   = rememberLazyListState()
    val scope       = rememberCoroutineScope()
    var showClear   by remember { mutableStateOf(false) }

    // Auto-scroll to bottom in live mode
    LaunchedEffect(entries.size, isLive) {
        if (isLive && entries.isNotEmpty()) {
            listState.animateScrollToItem(entries.size - 1)
        }
    }

    Scaffold(
        containerColor = DarkNavy,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("System Logs", fontWeight = FontWeight.Bold,
                            color = TextWhite, fontSize = 17.sp)
                        Text("${entries.size} entries${if (isLive) " • LIVE" else ""}",
                            color = if (isLive) NeonGreen else TextDimmed, fontSize = 11.sp)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = CyberCyan)
                    }
                },
                actions = {
                    // Live toggle
                    IconButton(onClick = { vm.toggleLiveMode() }) {
                        Icon(
                            if (isLive) Icons.Default.Pause else Icons.Default.PlayArrow,
                            contentDescription = if (isLive) "Pause" else "Live",
                            tint = if (isLive) NeonGreen else TextDimmed
                        )
                    }
                    // Refresh
                    IconButton(onClick = { vm.refresh() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = CyberCyan)
                    }
                    // Share
                    IconButton(onClick = { shareLog(context, vm) }) {
                        Icon(Icons.Default.Share, contentDescription = "Share", tint = CyberCyan)
                    }
                    // Overflow: copy / clear / save
                    var showMenu by remember { mutableStateOf(false) }
                    IconButton(onClick = { showMenu = true }) {
                        Icon(Icons.Default.MoreVert, contentDescription = "More", tint = CyberCyan)
                    }
                    DropdownMenu(
                        expanded = showMenu,
                        onDismissRequest = { showMenu = false },
                        containerColor = CardSurface
                    ) {
                        DropdownMenuItem(
                            text = { Text("Copy to Clipboard", color = TextWhite, fontSize = 13.sp) },
                            leadingIcon = { Icon(Icons.Default.ContentCopy, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp)) },
                            onClick = {
                                copyLog(context, vm)
                                showMenu = false
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Save to Downloads", color = TextWhite, fontSize = 13.sp) },
                            leadingIcon = { Icon(Icons.Default.Download, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp)) },
                            onClick = {
                                saveLogToDownloads(context, vm)
                                showMenu = false
                            }
                        )
                        HorizontalDivider(color = CardBorder)
                        DropdownMenuItem(
                            text = { Text("Clear Logs", color = AlertRed, fontSize = 13.sp) },
                            leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = AlertRed, modifier = Modifier.size(16.dp)) },
                            onClick = { showClear = true; showMenu = false }
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DarkNavy)
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // ── Tab row: category filter ──
            val tabs = listOf(
                null to "All",
                NetSecureLogger.TAG_VPN to "VPN Engine",
                NetSecureLogger.TAG_THREAT to "Threat Intel",
                NetSecureLogger.TAG_TRAFFIC to "Traffic",
                NetSecureLogger.TAG_SYSTEM to "System"
            )
            ScrollableTabRow(
                selectedTabIndex = tabs.indexOfFirst { it.first == filterTag }.coerceAtLeast(0),
                containerColor = DarkNavy,
                contentColor = CyberCyan,
                edgePadding = 0.dp
            ) {
                tabs.forEachIndexed { index, (tag, label) ->
                    Tab(
                        selected = filterTag == tag,
                        onClick = { vm.setFilterTag(tag) },
                        text = {
                            Text(label, fontSize = 12.sp,
                                color = if (filterTag == tag) CyberCyan else TextDimmed)
                        }
                    )
                }
            }

            // ── Level filter chips ──
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                LevelChip("All", null, filterLevel)   { vm.setFilterLevel(null) }
                LevelChip("Verbose", NetSecureLogger.VERBOSE, filterLevel) { vm.setFilterLevel(NetSecureLogger.VERBOSE) }
                LevelChip("Debug", NetSecureLogger.DEBUG, filterLevel)   { vm.setFilterLevel(NetSecureLogger.DEBUG) }
                LevelChip("Info", NetSecureLogger.INFO, filterLevel)    { vm.setFilterLevel(NetSecureLogger.INFO) }
                LevelChip("Warn", NetSecureLogger.WARN, filterLevel)    { vm.setFilterLevel(NetSecureLogger.WARN) }
                LevelChip("Error", NetSecureLogger.ERROR, filterLevel)  { vm.setFilterLevel(NetSecureLogger.ERROR) }
            }

            // ── Search bar ──
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { vm.setSearch(it) },
                placeholder = { Text("Search logs…", color = TextDimmed, fontSize = 12.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextDimmed, modifier = Modifier.size(18.dp)) },
                trailingIcon = {
                    if (searchQuery.isNotBlank())
                        IconButton(onClick = { vm.setSearch("") }) {
                            Icon(Icons.Default.Clear, contentDescription = null, tint = TextDimmed, modifier = Modifier.size(16.dp))
                        }
                },
                singleLine = true,
                shape = RoundedCornerShape(8.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = CyberCyan,
                    unfocusedBorderColor = CardBorder,
                    focusedTextColor = TextWhite,
                    unfocusedTextColor = TextWhite,
                    cursorColor = CyberCyan
                ),
                textStyle = LocalTextStyle.current.copy(fontSize = 12.sp, fontFamily = FontFamily.Monospace),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp)
                    .height(50.dp)
            )

            Spacer(Modifier.height(4.dp))

            // ── Log entries ──
            if (entries.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.Terminal, contentDescription = null,
                            tint = TextDimmed, modifier = Modifier.size(52.dp))
                        Spacer(Modifier.height(12.dp))
                        Text("No log entries", color = TextGray, fontSize = 14.sp)
                        Text("Start capturing traffic to see logs", color = TextDimmed, fontSize = 12.sp)
                    }
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    items(entries, key = { "${it.timestampMs}_${it.message.hashCode()}" }) { entry ->
                        LogEntryRow(entry)
                    }
                }
            }
        }
    }

    // ── Clear confirmation dialog ──
    if (showClear) {
        AlertDialog(
            onDismissRequest = { showClear = false },
            containerColor = CardSurface,
            title = { Text("Clear Logs", color = TextWhite, fontWeight = FontWeight.Bold) },
            text = { Text("This will clear the in-memory log and the log file. Continue?",
                color = TextGray, fontSize = 13.sp) },
            confirmButton = {
                TextButton(onClick = { vm.clearLogs(); showClear = false }) {
                    Text("Clear", color = AlertRed, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClear = false }) {
                    Text("Cancel", color = CyberCyan)
                }
            }
        )
    }
}

// ── Components ──────────────────────────────────────────────────────────────

@Composable
private fun LevelChip(
    label: String,
    level: Char?,
    activeLevel: Char?,
    onClick: () -> Unit
) {
    val selected = activeLevel == level
    val color = levelColor(level)
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 11.sp) },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = color.copy(alpha = 0.20f),
            selectedLabelColor = color,
            containerColor = CardSurface,
            labelColor = TextGray
        )
    )
}

@Composable
private fun LogEntryRow(entry: NetSecureLogger.LogEntry) {
    val levelColor = levelColor(entry.level)
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .background(CardSurface.copy(alpha = 0.6f))
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.Top
    ) {
        // Level badge
        Box(
            Modifier
                .clip(CircleShape)
                .background(levelColor.copy(alpha = 0.18f))
                .padding(horizontal = 5.dp, vertical = 2.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                "${entry.level}",
                color = levelColor,
                fontSize = 10.sp,
                fontWeight = FontWeight.ExtraBold,
                fontFamily = FontFamily.Monospace
            )
        }
        Spacer(Modifier.width(6.dp))

        Column(Modifier.weight(1f)) {
            // Timestamp + tag
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(entry.timestamp, color = TextDimmed, fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace)
                Spacer(Modifier.width(6.dp))
                Text(
                    entry.tag,
                    color = tagColor(entry.tag),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
            // Message
            Text(
                entry.message,
                color = if (entry.level == NetSecureLogger.ERROR) AlertRed.copy(alpha = 0.9f)
                        else if (entry.level == NetSecureLogger.WARN) AlertOrange.copy(alpha = 0.9f)
                        else TextWhite.copy(alpha = 0.85f),
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 4,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

private fun levelColor(level: Char?): Color = when (level) {
    NetSecureLogger.VERBOSE -> Color(0xFF78909C)
    NetSecureLogger.DEBUG   -> Color(0xFF90A4AE)
    NetSecureLogger.INFO    -> Color(0xFF00E5FF)
    NetSecureLogger.WARN    -> Color(0xFFFF9100)
    NetSecureLogger.ERROR   -> Color(0xFFFF1744)
    else -> Color(0xFF90A4AE)
}

private fun tagColor(tag: String): Color = when {
    tag.contains(NetSecureLogger.TAG_VPN, ignoreCase = true)     -> Color(0xFFBB86FC)
    tag.contains(NetSecureLogger.TAG_THREAT, ignoreCase = true)  -> Color(0xFFFF9100)
    tag.contains(NetSecureLogger.TAG_TRAFFIC, ignoreCase = true) -> Color(0xFF00E676)
    else -> Color(0xFF42A5F5)
}

private fun shareLog(context: Context, vm: LogsViewModel) {
    val logFile = NetSecureLogger.getLogFile()
    if (logFile != null && logFile.exists()) {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            logFile
        )
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "NetSecure System Log")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share Log"))
    } else {
        // Fall back to text share
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, vm.getAllLogsText())
            putExtra(Intent.EXTRA_SUBJECT, "NetSecure System Log")
        }
        context.startActivity(Intent.createChooser(intent, "Share Log"))
    }
}

private fun copyLog(context: Context, vm: LogsViewModel) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("NetSecure Log", vm.getAllLogsText()))
    Toast.makeText(context, "Log copied to clipboard", Toast.LENGTH_SHORT).show()
}

private fun saveLogToDownloads(context: Context, vm: LogsViewModel) {
    try {
        val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val file = java.io.File(downloads, "netsecure_${System.currentTimeMillis()}.log")
        file.writeText(vm.getAllLogsText())
        Toast.makeText(context, "Saved to Downloads/${file.name}", Toast.LENGTH_LONG).show()
    } catch (e: Exception) {
        Toast.makeText(context, "Save failed: ${e.message}", Toast.LENGTH_SHORT).show()
    }
}
