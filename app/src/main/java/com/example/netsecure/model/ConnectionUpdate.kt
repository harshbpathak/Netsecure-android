package com.example.netsecure.model

/**
 * Incremental update for a ConnectionDescriptor.
 * Created from JNI (getConnUpdate in jni_impl.c).
 * Constructor signature: (I)V
 */
class ConnectionUpdate(@JvmField val incr_id: Int) {
    @JvmField var has_stats: Boolean = false
    @JvmField var has_info: Boolean = false
    @JvmField var has_payload: Boolean = false

    // Stats fields
    @JvmField var last_seen: Long = 0
    @JvmField var payload_length: Long = 0
    @JvmField var sent_bytes: Long = 0
    @JvmField var rcvd_bytes: Long = 0
    @JvmField var sent_pkts: Int = 0
    @JvmField var rcvd_pkts: Int = 0
    @JvmField var blocked_pkts: Int = 0
    @JvmField var tcp_flags: Int = 0
    @JvmField var status_flags: Int = 0

    // Info fields
    @JvmField var info: String = ""
    @JvmField var url: String = ""
    @JvmField var l7proto: String = ""
    @JvmField var encrypted_l7: Boolean = false

    // Payload fields
    @JvmField var payload_chunks: ArrayList<PayloadChunk>? = null
    @JvmField var payload_truncated: Boolean = false
    @JvmField var has_decrypted_data: Boolean = false

    /**
     * Called from JNI: connUpdateSetStats
     * Signature: (JJJJIIIII)V
     */
    fun setStats(
        last_seen: Long, payload_length: Long,
        sent_bytes: Long, rcvd_bytes: Long,
        sent_pkts: Int, rcvd_pkts: Int, blocked_pkts: Int,
        tcp_flags: Int, status_flags: Int
    ) {
        has_stats = true
        this.last_seen = last_seen
        this.payload_length = payload_length
        this.sent_bytes = sent_bytes
        this.rcvd_bytes = rcvd_bytes
        this.sent_pkts = sent_pkts
        this.rcvd_pkts = rcvd_pkts
        this.blocked_pkts = blocked_pkts
        this.tcp_flags = tcp_flags
        this.status_flags = status_flags
    }

    /**
     * Called from JNI: connUpdateSetInfo
     * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
     */
    fun setInfo(info: String, url: String, l7proto: String, flags: Int) {
        has_info = true
        this.info = info
        this.url = url
        this.l7proto = l7proto
        this.encrypted_l7 = (flags and 1) == 1
    }

    /**
     * Called from JNI: connUpdateSetPayload
     * Signature: (Ljava/util/ArrayList;I)V
     */
    fun setPayload(chunks: ArrayList<PayloadChunk>?, flags: Int) {
        has_payload = true
        this.payload_chunks = chunks
        this.payload_truncated = (flags and 1) == 1
        this.has_decrypted_data = (flags and 2) == 2
    }
}
