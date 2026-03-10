package com.example.netsecure.data

import java.util.concurrent.PriorityBlockingQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * Priority-based scan request queue for IntelOwl threat intelligence.
 *
 * Observables are sorted by threat priority so the most suspicious connections
 * (already flagged by nDPI blacklists, unknown protocols, etc.) are scanned first.
 *
 * Features:
 * - Priority ordering (5 = highest → 0 = skip entirely)
 * - In-queue deduplication (same observable won't be queued twice)
 * - Max 500 items (drops lowest-priority if full)
 * - Configurable whitelist of known-safe observables (skipped at enqueue time)
 */
object ScanQueue {

    private const val MAX_QUEUE_SIZE = 500

    /** A single observable waiting to be analyzed by IntelOwl. */
    data class ScanRequest(
        val observable: String,           // IP address or domain name
        val classification: String,       // "ip", "domain", or "hash"
        val priority: Int,                // 0–5: higher = scanned sooner
        val timestamp: Long = System.currentTimeMillis(),
        val connectionIncrIds: MutableList<Int> = mutableListOf(),
        val associatedPackages: MutableSet<String> = mutableSetOf()
    ) : Comparable<ScanRequest> {
        // Higher priority = sorted first in the blocking queue
        override fun compareTo(other: ScanRequest): Int = other.priority - this.priority
    }

    // ── Private IP ranges to skip (never submit to IntelOwl) ──
    private val PRIVATE_IP_PREFIXES = listOf(
        "10.", "192.168.", "127.", "0.0.0.0",
        "169.254.",         // link-local
        "100.64.", "100.65.", "100.66.", "100.67.", "100.68.",
        "100.69.", "100.70.", "100.71.", "100.72.", "100.73.",
        "100.74.", "100.75.", "100.76.", "100.77.", "100.78.",
        "100.79.", "100.80.", "100.81.", "100.82.", "100.83.",
        "100.84.", "100.85.", "100.86.", "100.87.", "100.88.",
        "100.89.", "100.90.", "100.91.", "100.92.", "100.93.",
        "100.94.", "100.95.", "100.96.", "100.97.", "100.98.",
        "100.99.", "100.100.", "100.101.", "100.102.", "100.103.",
        "100.104.", "100.105.", "100.106.", "100.107.", "100.108.",
        "100.109.", "100.110.", "100.111.", "100.112.", "100.113.",
        "100.114.", "100.115.", "100.116.", "100.117.", "100.118.",
        "100.119.", "100.120.", "100.121.", "100.122.", "100.123.",
        "100.124.", "100.125.", "100.126.", "100.127.",
        "::1", "fe80:", "fc00:", "fd"
    )

    // 172.16.0.0/12 range handled separately since prefix check isn't sufficient
    private fun isRfc1918172(ip: String): Boolean {
        if (!ip.startsWith("172.")) return false
        val second = ip.split(".").getOrNull(1)?.toIntOrNull() ?: return false
        return second in 16..31
    }

    // ── Whitelist: known-safe observables that we skip by default ──
    // (configurable; opt-in default to reduce noise from OS/infra traffic)
    private val DEFAULT_WHITELIST_PATTERNS = setOf(
        "8.8.8.8", "8.8.4.4",          // Google Public DNS
        "1.1.1.1", "1.0.0.1",           // Cloudflare DNS
        "9.9.9.9",                       // Quad9 DNS
        "208.67.222.222",                // OpenDNS
        "255.255.255.255"                // Broadcast
    )

    private val DEFAULT_WHITELIST_SUFFIXES = setOf(
        ".gstatic.com",                  // Google static content delivery
        ".google-analytics.com"          // Analytics (too pervasive to flag)
    )

    @Volatile private var whitelistPatterns = DEFAULT_WHITELIST_PATTERNS.toMutableSet()
    @Volatile private var whitelistSuffixes = DEFAULT_WHITELIST_SUFFIXES.toMutableSet()

    private val queue = PriorityBlockingQueue<ScanRequest>(100)
    private val inQueueSet = mutableSetOf<String>()  // for O(1) dedup check
    private val _queueSize = AtomicInteger(0)

    val size: Int get() = _queueSize.get()

    /**
     * Compute priority score for a connection's observable.
     * Returns 0 if the observable should be skipped entirely.
     */
    fun computePriority(
        observable: String,
        classification: String,
        isBlacklistedIp: Boolean,
        isBlacklistedDomain: Boolean,
        l7proto: String,
        dstPort: Int
    ): Int {
        // Skip private/reserved IPs
        if (classification == "ip" && isPrivateIp(observable)) return 0

        // Skip whitelisted observables
        if (isWhitelisted(observable)) return 0

        // Highest: already flagged by nDPI blacklists
        if (isBlacklistedIp || isBlacklistedDomain) return 5

        // High: hash (potential malware file)
        if (classification == "hash") return 4

        // Medium-high: unknown/unclassified L7
        if (l7proto.isEmpty() || l7proto.equals("unknown", ignoreCase = true)) return 3

        // Medium: non-standard port
        if (dstPort !in listOf(80, 443, 53, 5353, 123, 8080, 8443)) return 2

        // Default
        return 1
    }

    /**
     * Enqueue a [ScanRequest] if:
     * - priority > 0 (not skipped)
     * - observable not already in queue
     *
     * If the queue is full (≥500), the lowest-priority item is dropped to make room.
     */
    @Synchronized
    fun enqueue(request: ScanRequest): Boolean {
        if (request.priority == 0) return false
        val key = normalise(request.observable)

        if (inQueueSet.contains(key)) {
            // Observable already queued — just merge associated connection/package info
            // (we can't easily mutate the queue item, so just ignore the duplicate)
            return false
        }

        if (_queueSize.get() >= MAX_QUEUE_SIZE) {
            // Drop the lowest-priority item from the queue to make room
            val lowest = queue.minByOrNull { it.priority }
            if (lowest != null && lowest.priority < request.priority) {
                queue.remove(lowest)
                inQueueSet.remove(normalise(lowest.observable))
                _queueSize.decrementAndGet()
            } else {
                return false // Our item has lower priority than everything in queue — discard it
            }
        }

        queue.add(request)
        inQueueSet.add(key)
        _queueSize.incrementAndGet()
        return true
    }

    /**
     * Drain up to [max] items from the front of the queue (highest priority first).
     */
    @Synchronized
    fun drainBatch(max: Int): List<ScanRequest> {
        val batch = mutableListOf<ScanRequest>()
        repeat(max) {
            val item = queue.poll() ?: return@repeat
            inQueueSet.remove(normalise(item.observable))
            _queueSize.decrementAndGet()
            batch.add(item)
        }
        return batch
    }

    /**
     * Check if [observable] is already queued (O(1) hash set lookup).
     */
    @Synchronized
    fun isQueued(observable: String): Boolean = inQueueSet.contains(normalise(observable))

    /** Clear all queued items. */
    @Synchronized
    fun clear() {
        queue.clear()
        inQueueSet.clear()
        _queueSize.set(0)
    }

    /** Add a custom observable to the whitelist. */
    @Synchronized
    fun addToWhitelist(observable: String) {
        whitelistPatterns.add(observable.lowercase())
    }

    /** Remove an observable from the whitelist. */
    @Synchronized
    fun removeFromWhitelist(observable: String) {
        whitelistPatterns.remove(observable.lowercase())
    }

    // ── Private Helpers ──

    private fun isPrivateIp(ip: String): Boolean {
        val lower = ip.lowercase()
        if (PRIVATE_IP_PREFIXES.any { lower.startsWith(it) }) return true
        if (isRfc1918172(ip)) return true
        return false
    }

    private fun isWhitelisted(observable: String): Boolean {
        val lower = observable.lowercase()
        if (whitelistPatterns.contains(lower)) return true
        if (whitelistSuffixes.any { lower.endsWith(it) }) return true
        return false
    }

    private fun normalise(observable: String): String = observable.lowercase().trim()
}
