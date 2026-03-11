package com.example.netsecure.ui.viewmodel

import android.app.Application
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.netsecure.CaptureService
import com.example.netsecure.data.ThreatIntelRepository
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.CategoryStats
import com.example.netsecure.data.model.ScanStatus
import com.example.netsecure.data.model.ThreatAlert
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.ThreatSummary
import com.example.netsecure.data.model.TrafficCategory
import com.example.netsecure.logging.NetSecureLogger
import com.example.netsecure.model.CaptureStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import android.os.Environment
import android.content.Context
import android.widget.Toast

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    // ── Traffic ──
    val appTrafficList: StateFlow<List<AppTrafficInfo>> = TrafficRepository.appTrafficFlow
    val isCapturing: StateFlow<Boolean> = TrafficRepository.isCapturing
    val captureStats: StateFlow<CaptureStats?> = TrafficRepository.captureStats
    val globalCategoryBreakdown: StateFlow<Map<TrafficCategory, CategoryStats>> =
        TrafficRepository.globalCategoryFlow

    /** Currently selected category filter (null = show all) */
    private val _selectedCategory = MutableStateFlow<TrafficCategory?>(null)
    val selectedCategory: StateFlow<TrafficCategory?> = _selectedCategory.asStateFlow()

    // ── Threat Intelligence ──
    val threatReports: StateFlow<Map<String, ThreatReport>> = ThreatIntelRepository.threatReportsFlow
    val threatAlerts: StateFlow<List<ThreatAlert>> = ThreatIntelRepository.threatAlertsFlow
    val threatSummary: StateFlow<ThreatSummary> = ThreatIntelRepository.threatSummaryFlow
    val scanStatus: StateFlow<ScanStatus> = ThreatIntelRepository.scanStatusFlow

    fun selectCategory(category: TrafficCategory?) {
        _selectedCategory.value = if (_selectedCategory.value == category) null else category
    }

    fun prepareVpn(): android.content.Intent? = VpnService.prepare(getApplication())

    fun startCapture() { CaptureService.start(getApplication()) }

    fun stopCapture() { CaptureService.stop(getApplication()) }

    fun clearData() {
        TrafficRepository.clearAll()
        ThreatIntelRepository.clearAll()
        _selectedCategory.value = null
    }

    fun dismissThreatAlert(alert: ThreatAlert) {
        ThreatIntelRepository.dismissAlert(alert)
    }

    /**
     * Generates a CSV file containing all connection details and saves it to the Downloads folder.
     */
    fun exportConnectionsCsv(context: Context) {
        val connections = TrafficRepository.connectionsFlow.value
        if (connections.isEmpty()) {
            Toast.makeText(context, "No connections to export", Toast.LENGTH_SHORT).show()
            return
        }

        // Launch in background so we don't block the UI thread while writing the file
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (!downloadsDir.exists()) downloadsDir.mkdirs()

                val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val fileName = "NetSecure_Connections_$timeStamp.csv"
                val file = File(downloadsDir, fileName)

                FileOutputStream(file).use { fos ->
                    OutputStreamWriter(fos).use { writer ->
                        writer.write("App Name,Protocol,L7 Protocol,Dest IP,Dest Port,Info (URL/SNI),Sent Bytes,Rcvd Bytes,Status\n")
                        
                        val pm = context.packageManager
                        
                        for (conn in connections) {
                            // Resolve UID to App Name
                            var appName = "uid:${conn.uid}"
                            try {
                                val packages = pm.getPackagesForUid(conn.uid)
                                if (!packages.isNullOrEmpty()) {
                                    val pkgName = packages[0]
                                    val appInfo = pm.getApplicationInfo(pkgName, 0)
                                    appName = pm.getApplicationLabel(appInfo).toString()
                                }
                            } catch (e: Exception) {
                                // Fallback to uid string if resolution fails
                            }

                            // Escape commas and quotes just in case
                            val escapedAppName = appName.replace("\"", "\"\"")
                            val info = conn.info.replace("\"", "\"\"")
                            
                            writer.write("\"$escapedAppName\",${conn.ipproto},${conn.l7proto},${conn.dst_ip},${conn.dst_port},\"$info\",${conn.sent_bytes},${conn.rcvd_bytes},${conn.status}\n")
                        }
                    }
                }

                NetSecureLogger.i(NetSecureLogger.TAG_SYSTEM, "Connections CSV saved to: ${file.absolutePath}")

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
