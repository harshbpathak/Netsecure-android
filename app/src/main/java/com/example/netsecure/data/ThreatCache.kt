package com.example.netsecure.data

import android.util.LruCache
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.ThreatSeverity

/**
 * Thread-safe LRU cache for threat intelligence reports with TTL support.
 *
 * - Max 2000 entries (LRU eviction)
 * - TTL: 60 min for meaningful results (any severity), 10 min for unknowns/errors
 * - Negative caching: observables that returned "clean" or "unknown" are still cached
 *   to prevent redundant re-submission, just with shorter TTL for unknowns.
 */
object ThreatCache {

    private const val MAX_ENTRIES = 2000

    /** Clean / meaningful results are kept 60 minutes. */
    private const val TTL_CLEAN_MS = 60L * 60L * 1000L

    /** Unknown / error results are kept only 10 minutes before retry. */
    private const val TTL_UNKNOWN_MS = 10L * 60L * 1000L

    private data class CachedEntry(
        val report: ThreatReport,
        val timestamp: Long,
        val ttlMs: Long
    ) {
        fun isExpired(): Boolean = System.currentTimeMillis() - timestamp > ttlMs
    }

    private val cache = object : LruCache<String, CachedEntry>(MAX_ENTRIES) {}

    /**
     * Retrieve a cached [ThreatReport] for [observable] if it exists and hasn't expired.
     * Returns null if not present or expired (caller should re-submit).
     */
    @Synchronized
    fun get(observable: String): ThreatReport? {
        val entry = cache.get(normalise(observable)) ?: return null
        return if (entry.isExpired()) {
            cache.remove(normalise(observable))
            null
        } else {
            entry.report
        }
    }

    /**
     * Store a [ThreatReport]. TTL is chosen based on the severity:
     * - CLEAN / LOW / MEDIUM / HIGH / CRITICAL → full TTL (60 min)
     * - null (means "error / unavailable") → short TTL (10 min)
     */
    @Synchronized
    fun put(report: ThreatReport) {
        val ttl = if (report.severity == ThreatSeverity.CLEAN && report.analyzerResults.isEmpty()) {
            // Analyzer returned nothing meaningful — use short TTL so we retry soon
            TTL_UNKNOWN_MS
        } else {
            TTL_CLEAN_MS
        }
        cache.put(normalise(report.observable), CachedEntry(report, System.currentTimeMillis(), ttl))
    }

    /**
     * Check if [observable] is in cache (even if expired), used by ScanQueue dedup.
     * Returns true if there's ANY entry for this observable.
     */
    @Synchronized
    fun isInCache(observable: String): Boolean = cache.get(normalise(observable)) != null

    /**
     * Check if [observable] is in cache AND not expired.
     */
    @Synchronized
    fun hasValidEntry(observable: String): Boolean = get(observable) != null

    /**
     * Remove a specific observable from cache (e.g., forced re-scan).
     */
    @Synchronized
    fun invalidate(observable: String) {
        cache.remove(normalise(observable))
    }

    /**
     * Clear all cached entries.
     */
    @Synchronized
    fun clear() {
        cache.evictAll()
    }

    /**
     * Return all non-expired reports currently in cache.
     * Useful for pre-populating UI state on startup.
     */
    @Synchronized
    fun getAllValid(): Map<String, ThreatReport> {
        val result = mutableMapOf<String, ThreatReport>()
        val snapshot = cache.snapshot()
        for ((key, entry) in snapshot) {
            if (!entry.isExpired()) result[key] = entry.report
        }
        return result
    }

    /** Normalise observable to lowercase for consistent keying. */
    private fun normalise(observable: String): String = observable.lowercase().trim()
}
