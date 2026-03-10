package com.example.netsecure.data.model

/**
 * Severity levels for threat intelligence findings.
 * Maps to color coding in the UI.
 */
enum class ThreatSeverity(val displayName: String, val ordinalScore: Int) {
    CLEAN("Clean", 0),
    LOW("Low", 1),
    MEDIUM("Medium", 2),
    HIGH("High", 3),
    CRITICAL("Critical", 4);

    companion object {
        /** Compute severity from a normalized 0.0–1.0 score */
        fun fromScore(score: Float): ThreatSeverity = when {
            score < 0.10f -> CLEAN
            score < 0.30f -> LOW
            score < 0.60f -> MEDIUM
            score < 0.80f -> HIGH
            else          -> CRITICAL
        }
    }
}

/**
 * Full threat intelligence report for a single observable (IP/domain/hash).
 * Produced by scoring the analyzer reports returned by IntelOwl.
 */
data class ThreatReport(
    val observable: String,
    val classification: String,        // "ip", "domain", "hash"
    val overallScore: Float,           // 0.0 (clean) → 1.0 (malicious)
    val severity: ThreatSeverity,
    val analyzerResults: List<AnalyzerResult>,
    val categories: List<String>,      // e.g. "malware","phishing","botnet","tor_exit"
    val firstSeen: Long,
    val lastUpdated: Long,
    val intelOwlJobId: Int? = null
)

/**
 * Condensed result for a single analyzer within the job.
 */
data class AnalyzerResult(
    val analyzerName: String,
    val score: Float,           // normalized 0.0–1.0 score from this analyzer
    val verdict: String,        // human-readable summary ("malicious", "clean", "not found", …)
    val detail: String          // extra detail for UI display
)

/**
 * Active high-severity alert surfaced to the Dashboard.
 */
data class ThreatAlert(
    val observable: String,
    val associatedPackages: List<String>,
    val report: ThreatReport,
    val alertId: String = "${observable}_${report.intelOwlJobId}",
    val createdAt: Long = System.currentTimeMillis(),
    var dismissedAt: Long = 0L
) {
    fun isDismissed(): Boolean = dismissedAt > 0L
}

/**
 * Current status of the IntelOwl scan engine.
 */
enum class ScanStatus {
    IDLE,           // Not started / IntelOwl disabled
    SCANNING,       // Actively submitting or polling jobs
    ERROR,          // API error (last request failed)
    UNAVAILABLE     // IntelOwl server unreachable / not configured
}

/**
 * Summary counts for the Dashboard threat gauge.
 */
data class ThreatSummary(
    val total: Int = 0,
    val clean: Int = 0,
    val low: Int = 0,
    val medium: Int = 0,
    val high: Int = 0,
    val critical: Int = 0,
    val pending: Int = 0   // queued or in-flight
) {
    val flagged: Int get() = medium + high + critical
}

// ── Scoring Constants ──

object ThreatScoring {
    // Analyzer weight contributions (must sum to 1.0)
    const val WEIGHT_ABUSEIPDB   = 0.40f
    const val WEIGHT_OTX         = 0.30f
    const val WEIGHT_MALWAREBAZAAR = 0.20f
    const val WEIGHT_GREYNOISE   = 0.10f

    // If any single analyzer score exceeds this, overall severity is forced to at least HIGH
    const val SINGLE_HIGH_THRESHOLD = 0.70f

    /**
     * Compute AbuseIPDB score from raw report fields.
     * abuseConfidenceScore is 0–100 → normalize to 0.0–1.0
     */
    fun scoreAbuseIPDB(abuseConfidenceScore: Int?): Float =
        ((abuseConfidenceScore ?: 0).coerceIn(0, 100)) / 100.0f

    /**
     * Compute MalwareBazaar score: found = 0.9, not found = 0.0
     */
    fun scoreMalwareBazaar(found: Boolean?): Float =
        if (found == true) 0.9f else 0.0f

    /**
     * Compute OTXQuery score from pulse count.
     * 0 pulses = 0.0; 10+ pulses = 1.0 (capped)
     */
    fun scoreOTX(pulseCount: Int?): Float =
        ((pulseCount ?: 0).coerceAtLeast(0) / 10.0f).coerceAtMost(1.0f)

    /**
     * Compute GreyNoise score:
     * "malicious" → 0.8, "benign" → 0.0, "unknown" → 0.2
     */
    fun scoreGreyNoise(classification: String?): Float = when (classification) {
        "malicious" -> 0.8f
        "benign"    -> 0.0f
        else        -> 0.2f
    }

    /**
     * Weighted aggregate of analyzer scores.
     * If any single score exceeds SINGLE_HIGH_THRESHOLD, severity is elevated.
     */
    fun aggregate(scores: Map<String, Float>): Float {
        if (scores.isEmpty()) return 0.0f
        var weightedSum = 0.0f
        var totalWeight = 0.0f

        for ((name, score) in scores) {
            val weight = when {
                name.contains("AbuseIPDB", ignoreCase = true)      -> WEIGHT_ABUSEIPDB
                name.contains("OTX", ignoreCase = true)            -> WEIGHT_OTX
                name.contains("MalwareBazaar", ignoreCase = true)  -> WEIGHT_MALWAREBAZAAR
                name.contains("GreyNoise", ignoreCase = true)      -> WEIGHT_GREYNOISE
                else -> 0.10f  // fallback weight for any other analyzer
            }
            weightedSum += score * weight
            totalWeight += weight
        }

        val weighted = if (totalWeight > 0f) weightedSum / totalWeight else 0.0f

        // Elevate if any single score is very high
        val maxSingle = scores.values.maxOrNull() ?: 0f
        return if (maxSingle > SINGLE_HIGH_THRESHOLD) {
            // Blend: ensure result is at least 0.6 (HIGH territory)
            weighted.coerceAtLeast(0.65f)
        } else {
            weighted
        }
    }
}
