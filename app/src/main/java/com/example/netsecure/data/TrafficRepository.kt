package com.example.netsecure.data

import android.content.Context
import android.content.pm.PackageManager
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.ConnectionRecord
import com.example.netsecure.data.model.Protocol
import com.example.netsecure.model.CaptureStats
import com.example.netsecure.model.ConnectionDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Singleton repository that bridges the native capture engine with the UI.
 * Receives batched connection data from CaptureService's JNI callbacks.
 */
object TrafficRepository {

    private val _appTrafficMap = mutableMapOf<String, AppTrafficInfo>()
    private val _appTrafficFlow = MutableStateFlow<List<AppTrafficInfo>>(emptyList())
    val appTrafficFlow: StateFlow<List<AppTrafficInfo>> = _appTrafficFlow.asStateFlow()

    private val _isCapturing = MutableStateFlow(false)
    val isCapturing: StateFlow<Boolean> = _isCapturing.asStateFlow()

    private val _captureStats = MutableStateFlow<CaptureStats?>(null)
    val captureStats: StateFlow<CaptureStats?> = _captureStats.asStateFlow()

    // Cache UID -> package name
    private val uidPackageCache = mutableMapOf<Int, String>()

    // Connections flow for ConnectionsScreen
    private val _connectionsFlow = MutableStateFlow<List<ConnectionDescriptor>>(emptyList())
    val connectionsFlow: StateFlow<List<ConnectionDescriptor>> = _connectionsFlow.asStateFlow()

    // Log flow for LogScreen
    private val _logLines = CopyOnWriteArrayList<String>()
    private val _logFlow = MutableStateFlow<List<String>>(emptyList())
    val logFlow: StateFlow<List<String>> = _logFlow.asStateFlow()

    fun setCapturing(active: Boolean) {
        _isCapturing.value = active
    }

    @Synchronized
    fun clearAll() {
        _appTrafficMap.clear()
        uidPackageCache.clear()
        _appTrafficFlow.value = emptyList()
        _captureStats.value = null
        _connectionsFlow.value = emptyList()
        _logLines.clear()
        _logFlow.value = emptyList()
    }

    /**
     * Called from CaptureService when native code sends batched connection updates.
     */
    @Synchronized
    fun onNativeUpdate(context: Context, register: ConnectionsRegister) {
        // Rebuild traffic map from register's per-app stats
        val allStats = register.getAllAppStats()

        for (stat in allStats) {
            val packageName = resolvePackageName(context, stat.uid)
            val existing = _appTrafficMap[packageName]

            if (existing != null) {
                _appTrafficMap[packageName] = existing.copy(
                    totalRequests = stat.numConnections,
                    totalBytesOut = stat.sentBytes,
                    totalBytesIn = stat.rcvdBytes
                )
            } else {
                val appName = resolveAppName(context, packageName)
                val appIcon = resolveAppIcon(context, packageName)
                _appTrafficMap[packageName] = AppTrafficInfo(
                    packageName = packageName,
                    appName = appName,
                    appIcon = appIcon,
                    totalRequests = stat.numConnections,
                    totalBytesOut = stat.sentBytes,
                    totalBytesIn = stat.rcvdBytes
                )
            }
        }

        _appTrafficFlow.value = _appTrafficMap.values
            .sortedByDescending { it.totalBytesOut + it.totalBytesIn }
            .toList()
    }

    fun updateStats(stats: CaptureStats) {
        _captureStats.value = stats
    }

    /**
     * Refresh the connections list from the register.
     * Called periodically from the ViewModel.
     */
    fun refreshConnections(register: ConnectionsRegister) {
        _connectionsFlow.value = register.getAllConnections()
    }

    /**
     * Add a native log line. Called from JNI via CaptureService.
     */
    fun addLogLine(line: String) {
        _logLines.add(line)
        // Keep max 500 lines
        while (_logLines.size > 500) _logLines.removeAt(0)
        _logFlow.value = _logLines.toList()
    }

    /**
     * Legacy method: add a single connection record (for backward compatibility with old code).
     */
    @Synchronized
    fun addConnection(context: Context, record: ConnectionRecord) {
        val packageName = resolvePackageName(context, record.uid)
        val existing = _appTrafficMap[packageName]

        if (existing != null) {
            _appTrafficMap[packageName] = existing.copy(
                totalRequests = existing.totalRequests + 1,
                totalBytesOut = existing.totalBytesOut + record.packetSize,
                connections = existing.connections + record
            )
        } else {
            val appName = resolveAppName(context, packageName)
            val appIcon = resolveAppIcon(context, packageName)
            _appTrafficMap[packageName] = AppTrafficInfo(
                packageName = packageName,
                appName = appName,
                appIcon = appIcon,
                totalRequests = 1,
                totalBytesOut = record.packetSize.toLong(),
                connections = listOf(record)
            )
        }

        _appTrafficFlow.value = _appTrafficMap.values
            .sortedByDescending { it.totalRequests }
            .toList()
    }

    fun getTrafficForApp(packageName: String): AppTrafficInfo? {
        return _appTrafficMap[packageName]
    }

    private fun resolvePackageName(context: Context, uid: Int): String {
        if (uid <= 0) return "unknown"
        uidPackageCache[uid]?.let { return it }

        val pm = context.packageManager
        val packages = pm.getPackagesForUid(uid)
        val name = packages?.firstOrNull() ?: "uid:$uid"
        uidPackageCache[uid] = name
        return name
    }

    private fun resolveAppName(context: Context, packageName: String): String {
        if (packageName == "unknown" || packageName.startsWith("uid:")) return packageName
        return try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            packageName
        }
    }

    private fun resolveAppIcon(context: Context, packageName: String): android.graphics.drawable.Drawable? {
        if (packageName == "unknown" || packageName.startsWith("uid:")) return null
        return try {
            context.packageManager.getApplicationIcon(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }
    }
}
