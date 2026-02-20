package com.example.netsecure.data.model

/**
 * A single captured network connection / packet record.
 */
data class ConnectionRecord(
    val sourceIp: String,
    val sourcePort: Int,
    val destIp: String,
    val destPort: Int,
    val protocol: Protocol,
    val packetSize: Int,
    val timestamp: Long = System.currentTimeMillis(),
    val uid: Int = -1
)

enum class Protocol(val label: String) {
    TCP("TCP"),
    UDP("UDP"),
    DNS("DNS"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    UNKNOWN("???")
}
