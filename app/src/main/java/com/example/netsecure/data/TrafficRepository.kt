package com.example.netsecure.data

import android.content.Context
import android.content.pm.PackageManager
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.ConnectionRecord
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Singleton repository that aggregates network traffic per app.
 * The VPN service pushes connection records here; ViewModels observe the flows.
 */
object TrafficRepository {

    private val _appTrafficMap = mutableMapOf<String, AppTrafficInfo>()
    private val _appTrafficFlow = MutableStateFlow<List<AppTrafficInfo>>(emptyList())
    val appTrafficFlow: StateFlow<List<AppTrafficInfo>> = _appTrafficFlow.asStateFlow()

    private val _isCapturing = MutableStateFlow(false)
    val isCapturing: StateFlow<Boolean> = _isCapturing.asStateFlow()

    // Cache UID -> package name mappings
    private val uidPackageCache = mutableMapOf<Int, String>()

    /**
     * Record a new connection from the VPN service.
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

        _appTrafficFlow.update {
            _appTrafficMap.values
                .sortedByDescending { it.totalRequests }
                .toList()
        }
    }

    fun setCapturing(active: Boolean) {
        _isCapturing.value = active
    }

    @Synchronized
    fun clearAll() {
        _appTrafficMap.clear()
        uidPackageCache.clear()
        _appTrafficFlow.value = emptyList()
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
