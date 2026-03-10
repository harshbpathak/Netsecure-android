package com.example.netsecure.data.model

/**
 * Categories for classifying network traffic.
 * Each connection is classified into one of these categories based on
 * its SNI/domain, L7 protocol, and destination info.
 *
 * This is a core differentiator from PCAPdroid — users see WHERE
 * their data goes at a glance, not just raw connections.
 */
enum class TrafficCategory(val label: String) {
    SOCIAL_MEDIA("Social Media"),
    STREAMING("Streaming"),
    ADS_TRACKERS("Ads & Trackers"),
    CLOUD_SERVICES("Cloud"),
    MESSAGING("Messaging"),
    GAMING("Gaming"),
    SHOPPING("Shopping"),
    SYSTEM("System/OS"),
    CDN("CDN/Infra"),
    OTHER("Other");

    companion object {
        /** Ordered list for UI display — most interesting categories first */
        val displayOrder = listOf(
            ADS_TRACKERS, SOCIAL_MEDIA, STREAMING, MESSAGING,
            CLOUD_SERVICES, GAMING, SHOPPING, CDN, SYSTEM, OTHER
        )
    }
}

/**
 * Per-category traffic statistics.
 * Used for breakdowns at both global and per-app level.
 */
data class CategoryStats(
    val requests: Int = 0,
    val bytesOut: Long = 0L,
    val bytesIn: Long = 0L
) {
    val totalBytes: Long get() = bytesOut + bytesIn
}
