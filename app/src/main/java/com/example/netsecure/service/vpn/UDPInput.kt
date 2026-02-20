package com.example.netsecure.service.vpn

import android.util.Log
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Reads UDP responses from protected DatagramChannels and builds
 * IP+UDP response packets to inject back into the TUN device.
 */
class UDPInput(
    private val outputQueue: ConcurrentLinkedQueue<ByteBuffer>,
    private val selector: Selector
) : Runnable {

    companion object {
        private const val TAG = "UDPInput"
    }

    override fun run() {
        Log.i(TAG, "Started")
        try {
            while (!Thread.interrupted()) {
                val readyChannels = selector.select()
                if (readyChannels == 0) {
                    Thread.sleep(10)
                    continue
                }

                val keys = selector.selectedKeys().iterator()
                while (keys.hasNext()) {
                    val key = keys.next()
                    keys.remove()

                    if (key.isValid && key.isReadable) {
                        val inputChannel = key.channel() as DatagramChannel
                        val referencePacket = key.attachment() as Packet

                        val receiveBuffer = ByteBufferPool.acquire()
                        // Position past IP + UDP header space for payload
                        receiveBuffer.position(Packet.IP4_HEADER_SIZE + Packet.UDP_HEADER_SIZE)

                        val readBytes = inputChannel.read(receiveBuffer)
                        if (readBytes <= 0) {
                            ByteBufferPool.release(receiveBuffer)
                            continue
                        }

                        val payloadSize = readBytes
                        referencePacket.updateUDPBuffer(receiveBuffer, payloadSize)
                        receiveBuffer.position(Packet.IP4_HEADER_SIZE + Packet.UDP_HEADER_SIZE + payloadSize)
                        outputQueue.offer(receiveBuffer)
                    }
                }
            }
        } catch (_: InterruptedException) {
            Log.i(TAG, "Stopping")
        } catch (e: Exception) {
            Log.e(TAG, "Error", e)
        }
    }
}
