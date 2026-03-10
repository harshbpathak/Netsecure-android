package com.example.netsecure.data

import android.content.Context
import android.content.pm.PackageManager
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.CategoryStats
import com.example.netsecure.data.model.TrafficCategory
import com.example.netsecure.model.CaptureStats
import com.example.netsecure.model.ConnectionDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Singleton repository that bridges the native capture engine with the UI.
 * Receives batched connection data from CaptureService's JNI callbacks.
 *
 * Enhanced with traffic classification: every connection is categorized
 * into a TrafficCategory for data segregation.
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

    // ── Traffic Segregation ──

    /** Global category breakdown (all apps combined) */
    private val _globalCategoryMap = mutableMapOf<TrafficCategory, CategoryStats>()
    private val _globalCategoryFlow = MutableStateFlow<Map<TrafficCategory, CategoryStats>>(emptyMap())
    val globalCategoryFlow: StateFlow<Map<TrafficCategory, CategoryStats>> = _globalCategoryFlow.asStateFlow()

    /** Per-app category breakdowns (packageName → category → stats) */
    private val _appCategoryMap = mutableMapOf<String, MutableMap<TrafficCategory, CategoryStats>>()

    /** Connection → category cache (incr_id → category) */
    private val connectionCategoryCache = mutableMapOf<Int, TrafficCategory>()

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
        _globalCategoryMap.clear()
        _globalCategoryFlow.value = emptyMap()
        _appCategoryMap.clear()
        connectionCategoryCache.clear()
    }

    /**
     * Called from CaptureService when native code sends batched connection updates.
     * Now also classifies each connection and builds category breakdowns.
     */
    @Synchronized
    fun onNativeUpdate(context: Context, register: ConnectionsRegister) {
        // Rebuild traffic map from register's per-app stats
        val allStats = register.getAllAppStats()

        for (stat in allStats) {
            val packageName = resolvePackageName(context, stat.uid)
            val existing = _appTrafficMap[packageName]
            val catBreakdown = _appCategoryMap[packageName] ?: emptyMap()

            if (existing != null) {
                _appTrafficMap[packageName] = existing.copy(
                    totalRequests = stat.numConnections,
                    totalBytesOut = stat.sentBytes,
                    totalBytesIn = stat.rcvdBytes,
                    categoryBreakdown = catBreakdown.toMap()
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
                    totalBytesIn = stat.rcvdBytes,
                    uid = stat.uid,
                    categoryBreakdown = catBreakdown.toMap()
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
     * Also classifies any new connections and updates category breakdowns.
     */
    @Synchronized
    fun refreshConnections(register: ConnectionsRegister) {
        val allConns = register.getAllConnections()
        _connectionsFlow.value = allConns

        // Classify connections and rebuild category maps
        rebuildCategoryMaps(allConns, register)

        // Feed ThreatIntelRepository with updated connections for observable extraction
        ThreatIntelRepository.onConnectionsUpdated(allConns)
    }

    /**
     * Classify all connections and rebuild global + per-app category maps.
     */
    private fun rebuildCategoryMaps(
        connections: List<ConnectionDescriptor>,
        register: ConnectionsRegister
    ) {
        _globalCategoryMap.clear()
        _appCategoryMap.clear()

        for (conn in connections) {
            // Classify (use cache for performance)
            val category = connectionCategoryCache.getOrPut(conn.incr_id) {
                TrafficClassifier.classify(
                    domain = conn.info.ifEmpty { conn.url.ifEmpty { conn.dst_ip } },
                    l7proto = conn.l7proto,
                    dstIp = conn.dst_ip,
                    dstPort = conn.dst_port
                )
            }

            // Re-check classification if info/l7proto was empty before but now has data
            if (connectionCategoryCache[conn.incr_id] == TrafficCategory.OTHER) {
                if (conn.info.isNotEmpty() || conn.l7proto.isNotEmpty()) {
                    val reclassified = TrafficClassifier.classify(
                        domain = conn.info.ifEmpty { conn.url.ifEmpty { conn.dst_ip } },
                        l7proto = conn.l7proto,
                        dstIp = conn.dst_ip,
                        dstPort = conn.dst_port
                    )
                    if (reclassified != TrafficCategory.OTHER) {
                        connectionCategoryCache[conn.incr_id] = reclassified
                    }
                }
            }

            val finalCategory = connectionCategoryCache[conn.incr_id] ?: TrafficCategory.OTHER
            val bytes = conn.sent_bytes + conn.rcvd_bytes

            // Update global category stats
            val globalStat = _globalCategoryMap[finalCategory] ?: CategoryStats()
            _globalCategoryMap[finalCategory] = CategoryStats(
                requests = globalStat.requests + 1,
                bytesOut = globalStat.bytesOut + conn.sent_bytes,
                bytesIn = globalStat.bytesIn + conn.rcvd_bytes
            )

            // Resolve package for per-app breakdown
            val uid = conn.uid
            val packages = uidPackageCache[uid]
            if (packages != null) {
                val appCats = _appCategoryMap.getOrPut(packages) { mutableMapOf() }
                val appStat = appCats[finalCategory] ?: CategoryStats()
                appCats[finalCategory] = CategoryStats(
                    requests = appStat.requests + 1,
                    bytesOut = appStat.bytesOut + conn.sent_bytes,
                    bytesIn = appStat.bytesIn + conn.rcvd_bytes
                )
            }
        }

        _globalCategoryFlow.value = _globalCategoryMap.toMap()
    }

    /**
     * Get the category for a specific connection.
     */
    fun getCategoryForConnection(connId: Int): TrafficCategory {
        return connectionCategoryCache[connId] ?: TrafficCategory.OTHER
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
    fun addConnection(context: Context, record: com.example.netsecure.data.model.ConnectionRecord) {
        val packageName = resolvePackageName(context, record.uid)
        val existing = _appTrafficMap[packageName]

        if (existing != null) {
            _appTrafficMap[packageName] = existing.copy(
                totalRequests = existing.totalRequests + 1,
                totalBytesOut = existing.totalBytesOut + record.packetSize
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
                uid = record.uid
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
