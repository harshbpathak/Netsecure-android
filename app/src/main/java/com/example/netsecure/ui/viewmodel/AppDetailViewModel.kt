package com.example.netsecure.ui.viewmodel

import android.content.Context
import android.os.Environment
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.netsecure.data.ThreatIntelRepository
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.TrafficCategory
import com.example.netsecure.logging.NetSecureLogger
import com.example.netsecure.model.ConnectionDescriptor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class AppDetailViewModel : ViewModel() {

    private val _targetPackageName = MutableStateFlow<String?>(null)

    /** Currently selected category filter for the detail screen (null = show all) */
    private val _selectedCategory = MutableStateFlow<TrafficCategory?>(null)
    val selectedCategory: StateFlow<TrafficCategory?> = _selectedCategory.asStateFlow()

    val appTraffic: StateFlow<AppTrafficInfo?> = combine(_targetPackageName, TrafficRepository.appTrafficFlow) { targetPkg, list ->
        list.find { it.packageName == targetPkg }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, null)

    val connections: StateFlow<List<ConnectionDescriptor>> = combine(
        appTraffic,
        TrafficRepository.connectionsFlow,
        _selectedCategory
    ) { app, conns, categoryFilter ->
        if (app != null && app.uid != -1) {
            val appConns = conns.filter { it.uid == app.uid }
            if (categoryFilter != null) {
                appConns.filter { conn ->
                    TrafficRepository.getCategoryForConnection(conn.incr_id) == categoryFilter
                }
            } else {
                appConns
            }
        } else {
            emptyList()
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    /**
     * Expose the full threat reports map so ConnectionCard composables can observe it
     * and trigger recomposition when new IntelOwl results arrive.
     * Each card does its own key-lookup from this map rather than calling
     * ThreatIntelRepository directly — this is the correct Compose recomposition pattern.
     */
    val threatMap: StateFlow<Map<String, ThreatReport>> = ThreatIntelRepository.threatReportsFlow

    /** Look up the best threat report for a connection (domain preferred over IP). */
    fun getThreatForConnection(conn: ConnectionDescriptor): ThreatReport? =
        ThreatIntelRepository.getThreatForConnection(conn)

    fun loadApp(packageName: String) {
        _targetPackageName.value = packageName
    }

    fun selectCategory(category: TrafficCategory?) {
        _selectedCategory.value = if (_selectedCategory.value == category) null else category
    }

    fun refresh(packageName: String) {
        loadApp(packageName)
    }

    fun exportAppConnectionsCsv(context: Context) {
        val conns = connections.value
        val appName = appTraffic.value?.appName ?: "Unknown"

        if (conns.isEmpty()) {
            Toast.makeText(context, "No connections to export", Toast.LENGTH_SHORT).show()
            return
        }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (!downloadsDir.exists()) downloadsDir.mkdirs()

                val safeName = appName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
                val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val fileName = "NetSecure_${safeName}_$timeStamp.csv"
                val file = File(downloadsDir, fileName)

                FileOutputStream(file).use { fos ->
                    OutputStreamWriter(fos).use { writer ->
                        writer.write("Protocol,L7 Protocol,Dest IP,Dest Port,Info (URL/SNI),Sent Bytes,Rcvd Bytes,Status\n")

                        for (conn in conns) {
                            val info = conn.info.replace("\"", "\"\"")
                            writer.write("${conn.ipproto},${conn.l7proto},${conn.dst_ip},${conn.dst_port},\"$info\",${conn.sent_bytes},${conn.rcvd_bytes},${conn.status}\n")
                        }
                    }
                }

                NetSecureLogger.i(NetSecureLogger.TAG_SYSTEM, "App CSV saved to: ${file.absolutePath}")

                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "Saved to Downloads: $fileName", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                NetSecureLogger.e(NetSecureLogger.TAG_SYSTEM, "Failed to export CSV: ${e.message}")
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "Failed to export CSV: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}
