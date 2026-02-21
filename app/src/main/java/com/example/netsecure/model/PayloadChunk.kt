package com.example.netsecure.model

/**
 * A chunk of payload data, created from JNI.
 * Constructor signature: ([BLcom/example/netsecure/model/PayloadChunk$ChunkType;ZJI)V
 */
class PayloadChunk(
    @JvmField val data: ByteArray,
    @JvmField val type: ChunkType,
    @JvmField val is_sent: Boolean,
    @JvmField val timestamp: Long,
    @JvmField val stream_id: Int
) {
    enum class ChunkType {
        RAW,
        HTTP
    }
}
