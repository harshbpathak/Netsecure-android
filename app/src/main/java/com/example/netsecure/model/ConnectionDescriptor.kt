package com.example.netsecure.model

/**
 * Holds information about a single connection.
 * Equivalent of zdtun_conn_t from zdtun and pd_conn_t from pcapdroid.c.
 *
 * Created from JNI (dumpNewConnection in jni_impl.c).
 * Constructor signature must match: (IIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIIIZJ)V
 */
class ConnectionDescriptor(
    @JvmField val incr_id: Int,
    @JvmField val ipver: Int,
    @JvmField val ipproto: Int,
    @JvmField val src_ip: String,
    @JvmField val dst_ip: String,
    @JvmField val country: String,
    @JvmField val src_port: Int,
    @JvmField val dst_port: Int,
    @JvmField val local_port: Int,
    @JvmField val uid: Int,
    @JvmField val ifidx: Int,
    @JvmField val mitm_decrypt: Boolean,
    @JvmField val first_seen: Long
) {
    // Updated by processUpdate
    @JvmField var info: String = ""
    @JvmField var url: String = ""
    @JvmField var l7proto: String = ""
    @JvmField var last_seen: Long = first_seen
    @JvmField var payload_length: Long = 0
    @JvmField var sent_bytes: Long = 0
    @JvmField var rcvd_bytes: Long = 0
    @JvmField var sent_pkts: Int = 0
    @JvmField var rcvd_pkts: Int = 0
    @JvmField var blocked_pkts: Int = 0
    @JvmField var status: Int = 0
    @JvmField var is_blocked: Boolean = false
    @JvmField var is_blacklisted_ip: Boolean = false
    @JvmField var is_blacklisted_domain: Boolean = false
    @JvmField var encrypted_l7: Boolean = false
    @JvmField var payload_truncated: Boolean = false
    @JvmField var tcp_flags: Int = 0
    @JvmField var decryption_ignored: Boolean = false
    @JvmField var netd_block_missed: Boolean = false
    @JvmField var port_mapping_applied: Boolean = false
    @JvmField var payload_chunks: ArrayList<PayloadChunk>? = null
    @JvmField var has_decrypted_data: Boolean = false

    enum class Status(val value: Int) {
        STATUS_NEW(0),
        STATUS_ACTIVE(1),
        STATUS_CLOSED(2),
        STATUS_UNREACHABLE(3),
        STATUS_ERROR(4)
    }

    /**
     * Called from JNI to apply an update to this connection.
     * Signature: (Lcom/example/netsecure/model/ConnectionUpdate;)V
     */
    fun processUpdate(update: ConnectionUpdate) {
        if (update.has_stats) {
            last_seen = update.last_seen
            payload_length = update.payload_length
            sent_bytes = update.sent_bytes
            rcvd_bytes = update.rcvd_bytes
            sent_pkts = update.sent_pkts
            rcvd_pkts = update.rcvd_pkts
            blocked_pkts = update.blocked_pkts
            tcp_flags = update.tcp_flags
            status = update.status_flags and 0xFF
            is_blocked = (update.status_flags shr 10) and 1 == 1
            is_blacklisted_ip = (update.status_flags shr 8) and 1 == 1
            is_blacklisted_domain = (update.status_flags shr 9) and 1 == 1
            netd_block_missed = (update.status_flags shr 11) and 1 == 1
            decryption_ignored = (update.status_flags shr 12) and 1 == 1
            port_mapping_applied = (update.status_flags shr 13) and 1 == 1
        }
        if (update.has_info) {
            if (update.info.isNotEmpty()) info = update.info
            if (update.url.isNotEmpty()) url = update.url
            if (update.l7proto.isNotEmpty()) l7proto = update.l7proto
            encrypted_l7 = update.encrypted_l7
        }
        if (update.has_payload) {
            payload_chunks = update.payload_chunks
            payload_truncated = update.payload_truncated
            has_decrypted_data = update.has_decrypted_data
        }
    }

    override fun toString(): String {
        return "[$l7proto] $src_ip:$src_port -> $dst_ip:$dst_port ($info)"
    }
}
