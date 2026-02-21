package com.example.netsecure.model

/**
 * Global capture statistics.
 * Created from JNI (sendStatsDump in jni_impl.c).
 * Constructor signature: ()V
 */
class CaptureStats {
    @JvmField var allocs_summary: String? = null
    @JvmField var sent_bytes: Long = 0
    @JvmField var rcvd_bytes: Long = 0
    @JvmField var ipv6_sent_bytes: Long = 0
    @JvmField var ipv6_rcvd_bytes: Long = 0
    @JvmField var pcap_dump_size: Long = 0
    @JvmField var sent_pkts: Int = 0
    @JvmField var rcvd_pkts: Int = 0
    @JvmField var dropped_pkts: Int = 0
    @JvmField var dropped_connections: Int = 0
    @JvmField var open_sockets: Int = 0
    @JvmField var max_fd: Int = 0
    @JvmField var active_connections: Int = 0
    @JvmField var tot_connections: Int = 0
    @JvmField var num_dns_requests: Int = 0

    /**
     * Called from JNI: statsSetData
     * Signature: (Ljava/lang/String;JJJJJIIIIIIIII)V
     */
    fun setData(
        allocs_summary: String?,
        sent_bytes: Long, rcvd_bytes: Long,
        ipv6_sent_bytes: Long, ipv6_rcvd_bytes: Long,
        pcap_dump_size: Long,
        sent_pkts: Int, rcvd_pkts: Int,
        dropped_pkts: Int, dropped_connections: Int,
        open_sockets: Int, max_fd: Int,
        active_connections: Int, tot_connections: Int,
        num_dns_requests: Int
    ) {
        this.allocs_summary = allocs_summary
        this.sent_bytes = sent_bytes
        this.rcvd_bytes = rcvd_bytes
        this.ipv6_sent_bytes = ipv6_sent_bytes
        this.ipv6_rcvd_bytes = ipv6_rcvd_bytes
        this.pcap_dump_size = pcap_dump_size
        this.sent_pkts = sent_pkts
        this.rcvd_pkts = rcvd_pkts
        this.dropped_pkts = dropped_pkts
        this.dropped_connections = dropped_connections
        this.open_sockets = open_sockets
        this.max_fd = max_fd
        this.active_connections = active_connections
        this.tot_connections = tot_connections
        this.num_dns_requests = num_dns_requests
    }

    val totalBytes: Long get() = sent_bytes + rcvd_bytes
}
