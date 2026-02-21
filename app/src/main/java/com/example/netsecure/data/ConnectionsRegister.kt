package com.example.netsecure.data

import com.example.netsecure.model.ConnectionDescriptor
import com.example.netsecure.model.ConnectionUpdate

/**
 * Ring buffer for connections, inspired by PCAPdroid's ConnectionsRegister.
 * Fixed size (8192) prevents unbounded memory growth.
 * Thread-safe via synchronized blocks.
 */
class ConnectionsRegister(private val capacity: Int) {

    private val ring = arrayOfNulls<ConnectionDescriptor>(capacity)
    private var tail = 0     // next write position
    private var count = 0    // number of items in the ring
    private val idMap = HashMap<Int, Int>() // incr_id → ring position

    // Per-app stats
    private val appStats = HashMap<Int, AppStats>()

    // Listeners
    private val listeners = mutableListOf<ConnectionsListener>()

    data class AppStats(
        var uid: Int = 0,
        var sentBytes: Long = 0,
        var rcvdBytes: Long = 0,
        var sentPkts: Int = 0,
        var rcvdPkts: Int = 0,
        var numConnections: Int = 0,
        var blockedConnections: Int = 0
    )

    interface ConnectionsListener {
        fun onConnectionsUpdated()
        fun onConnectionsAdded(count: Int)
    }

    @Synchronized
    fun newConnections(conns: Array<ConnectionDescriptor>) {
        for (conn in conns) {
            // Add to ring buffer
            ring[tail] = conn
            idMap[conn.incr_id] = tail
            tail = (tail + 1) % capacity
            if (count < capacity) count++

            // Update per-app stats
            val stats = appStats.getOrPut(conn.uid) { AppStats(uid = conn.uid) }
            stats.numConnections++
            stats.sentBytes += conn.sent_bytes
            stats.rcvdBytes += conn.rcvd_bytes
        }

        notifyAdded(conns.size)
    }

    @Synchronized
    fun connectionsUpdates(updates: Array<ConnectionUpdate>) {
        for (update in updates) {
            val pos = idMap[update.incr_id] ?: continue
            val conn = ring[pos] ?: continue

            // Track old stats for delta
            val oldSent = conn.sent_bytes
            val oldRcvd = conn.rcvd_bytes

            conn.processUpdate(update)

            // Update per-app stats with delta
            val stats = appStats.getOrPut(conn.uid) { AppStats(uid = conn.uid) }
            stats.sentBytes += (conn.sent_bytes - oldSent)
            stats.rcvdBytes += (conn.rcvd_bytes - oldRcvd)
        }

        notifyUpdated()
    }

    @Synchronized
    fun getConnCount(): Int = count

    @Synchronized
    fun getConn(index: Int): ConnectionDescriptor? {
        if (index < 0 || index >= count) return null
        val start = if (count < capacity) 0 else tail
        val actualIdx = (start + index) % capacity
        return ring[actualIdx]
    }

    @Synchronized
    fun getConnById(id: Int): ConnectionDescriptor? {
        val pos = idMap[id] ?: return null
        return ring[pos]
    }

    @Synchronized
    fun getAppStats(uid: Int): AppStats? = appStats[uid]

    @Synchronized
    fun getAllAppStats(): List<AppStats> = appStats.values.toList()

    @Synchronized
    fun getRecentConnections(limit: Int = 100): List<ConnectionDescriptor> {
        val result = mutableListOf<ConnectionDescriptor>()
        val n = minOf(limit, count)
        for (i in count - n until count) {
            getConn(i)?.let { result.add(it) }
        }
        return result
    }

    @Synchronized
    fun getAllConnections(): List<ConnectionDescriptor> {
        val result = mutableListOf<ConnectionDescriptor>()
        for (i in 0 until count) {
            getConn(i)?.let { result.add(it) }
        }
        return result.reversed() // most recent first
    }

    @Synchronized
    fun reset() {
        ring.fill(null)
        tail = 0
        count = 0
        idMap.clear()
        appStats.clear()
    }

    fun addListener(listener: ConnectionsListener) {
        synchronized(listeners) { listeners.add(listener) }
    }

    fun removeListener(listener: ConnectionsListener) {
        synchronized(listeners) { listeners.remove(listener) }
    }

    private fun notifyUpdated() {
        synchronized(listeners) {
            for (l in listeners) {
                try { l.onConnectionsUpdated() } catch (_: Exception) {}
            }
        }
    }

    private fun notifyAdded(n: Int) {
        synchronized(listeners) {
            for (l in listeners) {
                try { l.onConnectionsAdded(n) } catch (_: Exception) {}
            }
        }
    }
}
