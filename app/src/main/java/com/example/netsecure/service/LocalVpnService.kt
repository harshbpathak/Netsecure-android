package com.example.netsecure.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.example.netsecure.MainActivity
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.service.vpn.*
import java.io.Closeable
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Local VPN service that captures all device traffic via a TUN interface
 * and properly forwards it to the real network using protected sockets.
 *
 * Architecture (inspired by hexene/LocalVPN & PCAPdroid):
 *
 *   TUN ──read──┬── UDP packets ──→ UDPOutput ──→ real servers (DatagramChannel)
 *               │                            ←── UDPInput ──── responses
 *               └── TCP packets ──→ TCPInput ──→ real servers (SocketChannel)
 *                                            ←── TCPOutput ── responses
 *
 *   Responses are written back to TUN via networkToDeviceQueue.
 */
class LocalVpnService : VpnService() {

    companion object {
        const val TAG = "LocalVpnService"
        const val ACTION_START = "com.example.netsecure.START_VPN"
        const val ACTION_STOP = "com.example.netsecure.STOP_VPN"
        private const val CHANNEL_ID = "netsecure_vpn_channel"
        private const val NOTIFICATION_ID = 1
        private const val VPN_MTU = 1500

        fun start(context: Context) {
            val intent = Intent(context, LocalVpnService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, LocalVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var executorService: ExecutorService? = null
    private var udpSelector: Selector? = null
    private var tcpSelector: Selector? = null

    private var deviceToNetworkUDPQueue: ConcurrentLinkedQueue<Packet>? = null
    private var deviceToNetworkTCPQueue: ConcurrentLinkedQueue<Packet>? = null
    private var networkToDeviceQueue: ConcurrentLinkedQueue<ByteBuffer>? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (vpnInterface != null) return

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        try {
            val builder = Builder()
                .setSession("NetSecure")
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .setMtu(VPN_MTU)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            // Exclude ourselves to prevent infinite loops
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.e(TAG, "Could not exclude self", e)
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN")
                stopSelf()
                return
            }

            TrafficRepository.setCapturing(true)
            TrafficRepository.clearAll()

            udpSelector = Selector.open()
            tcpSelector = Selector.open()
            deviceToNetworkUDPQueue = ConcurrentLinkedQueue()
            deviceToNetworkTCPQueue = ConcurrentLinkedQueue()
            networkToDeviceQueue = ConcurrentLinkedQueue()

            executorService = Executors.newFixedThreadPool(5)
            // UDP: reads from real network → TUN
            executorService!!.submit(UDPInput(networkToDeviceQueue!!, udpSelector!!))
            // UDP: forwards from TUN → real network
            executorService!!.submit(UDPOutput(deviceToNetworkUDPQueue!!, udpSelector!!, this))
            // TCP: reads from real network → TUN
            executorService!!.submit(TCPOutput(networkToDeviceQueue!!, tcpSelector!!))
            // TCP: forwards from TUN → real network (state machine)
            executorService!!.submit(TCPInput(deviceToNetworkTCPQueue!!, networkToDeviceQueue!!, tcpSelector!!, this))
            // Main loop: reads TUN, dispatches, writes responses
            executorService!!.submit(
                VPNRunnable(
                    vpnInterface!!,
                    deviceToNetworkUDPQueue!!,
                    deviceToNetworkTCPQueue!!,
                    networkToDeviceQueue!!,
                    this
                )
            )

            Log.i(TAG, "VPN started with packet forwarding")
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        TrafficRepository.setCapturing(false)
        executorService?.shutdownNow()
        executorService = null
        cleanup()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    private fun cleanup() {
        deviceToNetworkTCPQueue = null
        deviceToNetworkUDPQueue = null
        networkToDeviceQueue = null
        ByteBufferPool.clear()
        closeResources(udpSelector, tcpSelector, vpnInterface)
        udpSelector = null
        tcpSelector = null
        vpnInterface = null
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun closeResources(vararg resources: Closeable?) {
        for (res in resources) {
            try { res?.close() } catch (_: Exception) {}
        }
    }

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

    /**
     * Main VPN loop: reads packets from TUN, records stats, dispatches TCP/UDP,
     * and writes response packets back to TUN.
     */
    private class VPNRunnable(
        private val vpnFd: ParcelFileDescriptor,
        private val udpQueue: ConcurrentLinkedQueue<Packet>,
        private val tcpQueue: ConcurrentLinkedQueue<Packet>,
        private val outputQueue: ConcurrentLinkedQueue<ByteBuffer>,
        private val vpnService: LocalVpnService
    ) : Runnable {

        override fun run() {
            Log.i("VPNRunnable", "Started")

            val vpnInput: FileChannel = FileInputStream(vpnFd.fileDescriptor).channel
            val vpnOutput: FileChannel = FileOutputStream(vpnFd.fileDescriptor).channel

            try {
                var bufferToNetwork: ByteBuffer? = null
                var dataSent = true

                while (!Thread.interrupted()) {
                    if (dataSent) {
                        bufferToNetwork = ByteBufferPool.acquire()
                    } else {
                        bufferToNetwork!!.clear()
                    }

                    // Read an IP packet from the TUN device
                    val readBytes = vpnInput.read(bufferToNetwork!!)
                    if (readBytes > 0) {
                        dataSent = true
                        bufferToNetwork.flip() // position=0, limit=readBytes

                        // Record stats using the OLD PacketParser (uses absolute offsets, no side effects)
                        recordPacketStats(bufferToNetwork, readBytes)

                        // Parse with the forwarding Packet class
                        val packet = try {
                            Packet(bufferToNetwork)
                        } catch (e: Exception) {
                            Log.w("VPNRunnable", "Unparsable packet (${e.message})")
                            dataSent = false
                            continue
                        }

                        if (packet.isUDP) {
                            udpQueue.offer(packet)
                        } else if (packet.isTCP) {
                            tcpQueue.offer(packet)
                        } else {
                            Log.d("VPNRunnable", "Skipping non-TCP/UDP: protocol=${packet.ip4Header.protocol}")
                            dataSent = false
                        }
                    } else {
                        dataSent = false
                    }

                    // Write any pending response packets back to TUN
                    var hasWritten = false
                    var bufferFromNetwork = outputQueue.poll()
                    while (bufferFromNetwork != null) {
                        bufferFromNetwork.flip()
                        while (bufferFromNetwork.hasRemaining()) {
                            vpnOutput.write(bufferFromNetwork)
                        }
                        ByteBufferPool.release(bufferFromNetwork)
                        hasWritten = true
                        bufferFromNetwork = outputQueue.poll()
                    }

                    // Avoid busy-waiting
                    if (!dataSent && !hasWritten) {
                        Thread.sleep(10)
                    }
                }
            } catch (_: InterruptedException) {
                Log.i("VPNRunnable", "Stopping")
            } catch (e: Exception) {
                Log.e("VPNRunnable", "Fatal error", e)
            } finally {
                try { vpnInput.close() } catch (_: Exception) {}
                try { vpnOutput.close() } catch (_: Exception) {}
            }
        }

        /**
         * Record packet stats using PacketParser (uses absolute buffer offsets, doesn't modify position).
         * Then restore the buffer position to 0 so Packet() can parse it.
         */
        private fun recordPacketStats(buffer: ByteBuffer, length: Int) {
            try {
                // PacketParser uses absolute offsets (buffer.get(index), buffer.getShort(index))
                // so it doesn't modify the buffer's position
                val array = ByteArray(length)
                buffer.get(array)
                buffer.position(0) // CRITICAL: reset for Packet() constructor

                val parsed = PacketParser.parse(array, length)
                if (parsed != null) {
                    val record = PacketParser.toConnectionRecord(parsed, uid = -1)
                    TrafficRepository.addConnection(vpnService, record)
                }
            } catch (e: Exception) {
                buffer.position(0) // ensure reset even on error
                Log.w("VPNRunnable", "Stats error: ${e.message}")
            }
        }
    }
}
