package com.example.netsecure.service.vpn

import android.net.VpnService
import android.util.Log
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Forwards outgoing UDP packets from the TUN device to the real network
 * via protected DatagramChannels.
 */
class UDPOutput(
    private val inputQueue: ConcurrentLinkedQueue<Packet>,
    private val selector: Selector,
    private val vpnService: VpnService
) : Runnable {

    companion object {
        private const val TAG = "UDPOutput"
        private const val MAX_CACHE_SIZE = 50
    }

    private val channelCache = LinkedHashMap<String, DatagramChannel>(
        MAX_CACHE_SIZE, 0.75f, true
    )

    override fun run() {
        Log.i(TAG, "Started")
        try {
            while (!Thread.interrupted()) {
                val currentPacket = inputQueue.poll()
                if (currentPacket == null) {
                    Thread.sleep(10)
                    continue
                }

                val destAddr = currentPacket.ip4Header.destinationAddress
                val destPort = currentPacket.udpHeader!!.destinationPort
                val srcPort = currentPacket.udpHeader!!.sourcePort

                val key = "${destAddr.hostAddress}:$destPort:$srcPort"
                var outputChannel = channelCache[key]

                if (outputChannel == null) {
                    outputChannel = DatagramChannel.open()
                    vpnService.protect(outputChannel.socket())

                    try {
                        outputChannel.connect(InetSocketAddress(destAddr, destPort))
                    } catch (e: Exception) {
                        Log.e(TAG, "Connect error: $key", e)
                        try { outputChannel.close() } catch (_: Exception) {}
                        ByteBufferPool.release(currentPacket.backingBuffer)
                        continue
                    }
                    outputChannel.configureBlocking(false)
                    currentPacket.swapSourceAndDestination()

                    selector.wakeup()
                    outputChannel.register(selector, SelectionKey.OP_READ, currentPacket)

                    // Evict oldest if cache is full
                    if (channelCache.size >= MAX_CACHE_SIZE) {
                        val eldest = channelCache.entries.first()
                        try { eldest.value.close() } catch (_: Exception) {}
                        channelCache.remove(eldest.key)
                    }
                    channelCache[key] = outputChannel
                }

                try {
                    val payloadBuffer = currentPacket.backingBuffer
                    while (payloadBuffer.hasRemaining()) {
                        outputChannel.write(payloadBuffer)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Write error: $key", e)
                    channelCache.remove(key)
                    try { outputChannel.close() } catch (_: Exception) {}
                }

                ByteBufferPool.release(currentPacket.backingBuffer)
            }
        } catch (_: InterruptedException) {
            Log.i(TAG, "Stopping")
        } catch (e: Exception) {
            Log.e(TAG, "Error", e)
        } finally {
            closeAll()
        }
    }

    private fun closeAll() {
        for (channel in channelCache.values) {
            try { channel.close() } catch (_: Exception) {}
        }
        channelCache.clear()
    }
}
