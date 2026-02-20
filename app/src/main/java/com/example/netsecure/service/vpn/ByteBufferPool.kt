package com.example.netsecure.service.vpn

import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Simple pool of reusable ByteBuffers to reduce GC pressure.
 */
object ByteBufferPool {
    private const val BUFFER_SIZE = 16384
    private val pool = ConcurrentLinkedQueue<ByteBuffer>()

    fun acquire(): ByteBuffer {
        var buffer = pool.poll()
        if (buffer == null) {
            buffer = ByteBuffer.allocate(BUFFER_SIZE)
        }
        buffer.clear()
        return buffer
    }

    fun release(buffer: ByteBuffer) {
        buffer.clear()
        pool.offer(buffer)
    }

    fun clear() {
        pool.clear()
    }
}
