package com.example.netsecure

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import com.example.netsecure.data.ConnectionsRegister
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.model.BlacklistDescriptor
import com.example.netsecure.model.CaptureStats
import com.example.netsecure.model.ConnectionDescriptor
import com.example.netsecure.model.ConnectionUpdate

/**
 * Main capture service using PCAPdroid's native C engine.
 * This replaces the old pure-Kotlin LocalVpnService.
 *
 * Architecture:
 *   VpnService.Builder → TUN fd → native runPacketLoop() → zdtun + nDPI
 *   Native callbacks → updateConnections() → ConnectionsRegister → UI
 *
 * IMPORTANT: This class must be at com.example.netsecure.CaptureService
 * (not in a sub-package) because jni_impl.c references it as such.
 */
class CaptureService : VpnService(), Runnable {

    companion object {
        private const val TAG = "CaptureService"
        private const val CHANNEL_ID = "netsecure_vpn_channel"
        private const val NOTIFICATION_ID = 1
        private const val VPN_MTU = 10000
        private const val VPN_IPV4 = "10.215.173.1"
        private const val VPN_DNS = "10.215.173.2"
        const val VPN_SESSION_NAME = "NetSecure VPN"
        private const val MAX_CONNECTIONS = 8192

        @Volatile
        var INSTANCE: CaptureService? = null
            private set

        var connectionsRegister: ConnectionsRegister? = null
            private set

        @Volatile
        var lastStats: CaptureStats? = null
            private set

        init {
            System.loadLibrary("capture")
        }

        fun start(context: Context) {
            val intent = Intent(context, CaptureService::class.java).apply {
                action = "START"
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, CaptureService::class.java).apply {
                action = "STOP"
            }
            context.startService(intent)
        }

        fun isRunning(): Boolean = INSTANCE != null
    }

    private var parcelFileDescriptor: ParcelFileDescriptor? = null
    private var captureThread: Thread? = null
    private val handler = Handler(Looper.getMainLooper())
    private var underlyingNetwork: Network? = null

    // ──── Native JNI methods ────
    private external fun runPacketLoop(tunfd: Int, vpn: CaptureService, sdk: Int)
    private external fun stopPacketLoop()
    private external fun initPlatformInfo(appver: String, device: String, os: String)
    private external fun askStatsDump()
    private external fun getFdSetSize(): Int
    private external fun setDnsServer(server: String)
    private external fun getPcapHeader(): ByteArray?
    private external fun reloadBlacklists()
    private external fun getNumCheckedMalwareConnections(): Int
    private external fun getNumCheckedFirewallConnections(): Int
    private external fun setPrivateDnsBlocked(toBlock: Boolean)

    // ──── Service Lifecycle ────

    override fun onCreate() {
        super.onCreate()
        INSTANCE = this
        Log.i(TAG, "CaptureService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "START" -> startCapture()
            "STOP" -> stopCapture()
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (captureThread != null) return

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        // Init platform info for PCAP metadata
        val appVer = try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "1.0"
        } catch (e: Exception) { "1.0" }
        initPlatformInfo(appVer, Build.MODEL, "Android ${Build.VERSION.RELEASE}")

        // Allocate connections register
        connectionsRegister = ConnectionsRegister(MAX_CONNECTIONS)

        // VPN Setup — PCAPdroid architecture:
        // - MTU 10000 (large, avoids fragmentation)
        // - Split routes (0.0.0.0/1 + 128.0.0.0/1 instead of 0.0.0.0/0)
        // - Virtual DNS (10.215.173.2) for DNS interception
        val builder = Builder()
            .setMtu(VPN_MTU)
            .setSession(VPN_SESSION_NAME)
            .addAddress(VPN_IPV4, 30)
            .addRoute("0.0.0.0", 1)        // Split route: first half
            .addRoute("128.0.0.0", 1)       // Split route: second half
            .addDnsServer(VPN_DNS)           // Virtual DNS

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        // Exclude ourselves to avoid infinite loop
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Could not exclude self", e)
        }

        try {
            parcelFileDescriptor = builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "VPN setup failed", e)
            stopSelf()
            return
        }

        if (parcelFileDescriptor == null) {
            Log.e(TAG, "Failed to establish VPN — null PFD")
            stopSelf()
            return
        }

        TrafficRepository.setCapturing(true)
        TrafficRepository.clearAll()

        // Register network callback for underlying network detection
        registerNetworkCallback()

        // Start native capture thread
        captureThread = Thread(this, "CaptureThread").apply { start() }

        Log.i(TAG, "Native capture started with fd=${parcelFileDescriptor!!.fd}")
    }

    /** Entry point for the capture thread. Calls native runPacketLoop. */
    override fun run() {
        val pfd = parcelFileDescriptor ?: return
        val fd = pfd.fd
        val fdSetSize = getFdSetSize()

        if (fd > 0 && fd < fdSetSize) {
            Log.d(TAG, "VPN fd: $fd, FD_SETSIZE: $fdSetSize")
            runPacketLoop(fd, this, Build.VERSION.SDK_INT)
        } else {
            Log.e(TAG, "Invalid VPN fd: $fd (FD_SETSIZE: $fdSetSize)")
        }

        // After capture stops: cleanup
        try {
            parcelFileDescriptor?.close()
        } catch (_: Exception) {}
        parcelFileDescriptor = null

        handler.post {
            stopCapture()
        }
    }

    private fun stopCapture() {
        TrafficRepository.setCapturing(false)

        if (captureThread != null) {
            stopPacketLoop()
            try {
                captureThread?.join(3000)
            } catch (_: InterruptedException) {}
            captureThread = null
        }

        unregisterNetworkCallback()

        try {
            parcelFileDescriptor?.close()
        } catch (_: Exception) {}
        parcelFileDescriptor = null

        connectionsRegister = null
        INSTANCE = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Capture stopped")
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked by system")
        stopCapture()
        super.onRevoke()
    }

    // ──── JNI Callbacks (called from native code) ────

    /** Called from JNI when a fatal error occurs in the native code. */
    @Suppress("unused")
    fun reportError(msg: String) {
        Log.e(TAG, "Native error: $msg")
    }

    /** Called from JNI to resolve a UID to an app name. */
    @Suppress("unused")
    fun getApplicationByUid(uid: Int): String {
        return try {
            val packages = packageManager.getPackagesForUid(uid)
            if (packages != null && packages.isNotEmpty()) {
                val appInfo = packageManager.getApplicationInfo(packages[0], 0)
                packageManager.getApplicationLabel(appInfo).toString()
            } else {
                "uid:$uid"
            }
        } catch (e: PackageManager.NameNotFoundException) {
            "uid:$uid"
        }
    }

    /** Called from JNI to resolve a UID to a package name. */
    @Suppress("unused")
    fun getPackageNameByUid(uid: Int): String {
        return try {
            val packages = packageManager.getPackagesForUid(uid)
            packages?.firstOrNull() ?: "uid:$uid"
        } catch (_: Exception) {
            "uid:$uid"
        }
    }

    /** Called from JNI to load UID mappings for apps. */
    @Suppress("unused")
    fun loadUidMapping(uid: Int, packageName: String, appName: String) {
        // Mapping of UID to package/app for display
        Log.d(TAG, "UID mapping: $uid -> $packageName ($appName)")
    }

    /** Called from JNI for country code lookup (placeholder). */
    @Suppress("unused")
    fun getCountryCode(ipAddr: String): String {
        return "" // Geolocation requires MaxMind GeoIP database
    }

    /** Called from JNI to receive PCAP data for export. */
    @Suppress("unused")
    fun dumpPcapData(data: ByteArray) {
        // PCAP export — can be implemented later
    }

    /** Called from JNI when PCAP dump should stop. */
    @Suppress("unused")
    fun stopPcapDump() {
        // PCAP dump stop
    }

    /** Called from JNI before connection batch updates. */
    @Suppress("unused")
    fun startConnectionsUpdate() {
        // Pre-update hook
    }

    /**
     * Called from JNI with batched connection data.
     * This is the main data path: native → Java/Kotlin.
     */
    @Suppress("unused")
    fun updateConnections(
        newConns: Array<ConnectionDescriptor>?,
        updates: Array<ConnectionUpdate>?
    ) {
        val register = connectionsRegister ?: return

        if (newConns != null && newConns.isNotEmpty()) {
            register.newConnections(newConns)
        }

        if (updates != null && updates.isNotEmpty()) {
            register.connectionsUpdates(updates)
        }

        // Update the TrafficRepository for UI
        TrafficRepository.onNativeUpdate(this, register)
        TrafficRepository.refreshConnections(register)
    }

    /** Called from JNI with capture statistics. */
    @Suppress("unused")
    fun sendStatsDump(stats: CaptureStats) {
        lastStats = stats
        TrafficRepository.updateStats(stats)
    }

    /** Called from JNI to notify service status changes. */
    @Suppress("unused")
    fun sendServiceStatus(status: String) {
        Log.i(TAG, "Service status: $status")
    }

    /** Called from JNI log callback to forward native log lines to the UI. */
    @Suppress("unused")
    fun logLine(line: String) {
        TrafficRepository.addLogLine(line)
    }

    /** Called from JNI to get path to a native library. */
    @Suppress("unused")
    fun getLibprogPath(name: String): String {
        return applicationInfo.nativeLibraryDir + "/lib${name}.so"
    }

    /** Called from JNI after blacklists are loaded. */
    @Suppress("unused")
    fun notifyBlacklistsLoaded(status: Array<Blacklists.NativeBlacklistStatus>) {
        Log.i(TAG, "Blacklists loaded: ${status.size} lists")
    }

    /** Called from JNI to get blacklists info. */
    @Suppress("unused")
    fun getBlacklistsInfo(): Array<BlacklistDescriptor> {
        return emptyArray() // Blacklists can be loaded later
    }

    // ──── Preference Getters (called from JNI via getIntPref/getStringPref) ────

    @Suppress("unused") fun isVpnCapture(): Int = 1
    @Suppress("unused") fun isPcapFileCapture(): Int = 0
    @Suppress("unused") fun getPayloadMode(): Int = 0 // PAYLOAD_MODE_NONE
    @Suppress("unused") fun pcapDumpEnabled(): Int = 0
    @Suppress("unused") fun dumpExtensionsEnabled(): Int = 0
    @Suppress("unused") fun isPcapngEnabled(): Int = 0
    @Suppress("unused") fun getSnaplen(): Int = 0
    @Suppress("unused") fun getMaxPktsPerFlow(): Int = 0
    @Suppress("unused") fun getMaxDumpSize(): Int = 0
    @Suppress("unused") fun getSocks5Enabled(): Int = 0
    @Suppress("unused") fun getSocks5ProxyAddress(): String = "0.0.0.0"
    @Suppress("unused") fun getSocks5ProxyPort(): Int = 0
    @Suppress("unused") fun getSocks5ProxyAuth(): String = ""
    @Suppress("unused") fun malwareDetectionEnabled(): Int = 0
    @Suppress("unused") fun firewallEnabled(): Int = 0
    @Suppress("unused") fun isTlsDecryptionEnabled(): Int = 0
    @Suppress("unused") fun getMitmAddonUid(): Int = -1
    @Suppress("unused") fun getWorkingDir(): String = cacheDir.absolutePath
    @Suppress("unused") fun getPersistentDir(): String = filesDir.absolutePath

    // ──── VPN Capture Preferences (called from capture_vpn.c via getIntPref/getIPv4Pref/getIPv6Pref) ────
    @Suppress("unused") fun getIPv4Enabled(): Int = 1          // Enable IPv4 capture
    @Suppress("unused") fun getDnsServer(): String = "8.8.8.8" // Upstream DNS server
    @Suppress("unused") fun getVpnDns(): String = VPN_DNS      // Internal VPN DNS (10.215.173.2)
    @Suppress("unused") fun getIPv6Enabled(): Int = 0           // Disable IPv6 (no IPv6 routes configured)
    @Suppress("unused") fun getIpv6DnsServer(): String = "::"  // Placeholder IPv6 DNS
    @Suppress("unused") fun getVpnMTU(): Int = VPN_MTU          // MTU = 10000
    @Suppress("unused") fun getBlockQuickMode(): Int = 0        // No QUIC blocking

    /**
     * Called from JNI (uid_resolver.c) on Android 10+ to resolve which app owns a connection.
     * Uses ConnectivityManager.getConnectionOwnerUid() — this is the primary UID resolution
     * path on modern Android. Without this, all traffic shows as "unknown".
     */
    @Suppress("unused")
    fun getUidQ(protocol: Int, saddr: String, sport: Int, daddr: String, dport: Int): Int {
        if (protocol != 6 && protocol != 17) return -1 // TCP=6, UDP=17

        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return -1
        return try {
            val local = java.net.InetSocketAddress(saddr, sport)
            val remote = java.net.InetSocketAddress(daddr, dport)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                cm.getConnectionOwnerUid(protocol, local, remote)
            } else {
                -1
            }
        } catch (e: Exception) {
            Log.w(TAG, "getUidQ failed", e)
            -1
        }
    }

    // ──── Network Callback ────

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                underlyingNetwork = network
                setUnderlyingNetworks(arrayOf(network))
            }
            override fun onLost(network: Network) {
                if (underlyingNetwork == network) {
                    underlyingNetwork = null
                    setUnderlyingNetworks(null)
                }
            }
        }

        cm.registerNetworkCallback(request, networkCallback!!)
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            try {
                cm.unregisterNetworkCallback(it)
            } catch (_: Exception) {}
        }
        networkCallback = null
    }

    // ──── Notification ────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "NetSecure VPN", NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Shows when NetSecure is capturing traffic" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }.setContentTitle("NetSecure")
            .setContentText("Monitoring network traffic…")
            .setSmallIcon(android.R.drawable.ic_menu_manage)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }
}

/**
 * Placeholder for blacklists functionality.
 * Inner class NativeBlacklistStatus is referenced from JNI.
 */
class Blacklists {
    class NativeBlacklistStatus(
        @JvmField val fname: String,
        @JvmField val num_rules: Int
    )
}
