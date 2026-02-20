package com.example.netsecure.service.vpn

import android.util.Log
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Reads TCP responses from protected SocketChannels and builds
 * IP+TCP response packets to inject back into the TUN device.
 */
class TCPOutput(
    private val outputQueue: ConcurrentLinkedQueue<ByteBuffer>,
    private val selector: Selector
) : Runnable {

    companion object {
        private const val TAG = "TCPInput"
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

                    if (key.isValid) {
                        when {
                            key.isConnectable -> processConnect(key)
                            key.isReadable -> processInput(key)
                        }
                    }
                }
            }
        } catch (_: InterruptedException) {
            Log.i(TAG, "Stopping")
        } catch (e: Exception) {
            Log.e(TAG, "Error", e)
        }
    }

    private fun processConnect(key: SelectionKey) {
        val tcb = key.attachment() as TCB
        val channel = tcb.channel

        try {
            if (channel.finishConnect()) {
                synchronized(tcb) {
                    tcb.status = TCB.TCBStatus.SYN_RECEIVED
                    val responseBuffer = ByteBufferPool.acquire()
                    tcb.referencePacket.updateTCPBuffer(
                        responseBuffer,
                        (Packet.TCPHeader.SYN or Packet.TCPHeader.ACK).toByte(),
                        tcb.mySequenceNum,
                        tcb.myAcknowledgementNum,
                        0
                    )
                    tcb.mySequenceNum++
                    outputQueue.offer(responseBuffer)
                    key.interestOps(SelectionKey.OP_READ)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Connection finish error: ${tcb.ipAndPort}", e)
            val responseBuffer = ByteBufferPool.acquire()
            tcb.referencePacket.updateTCPBuffer(
                responseBuffer,
                Packet.TCPHeader.RST.toByte(),
                0,
                tcb.myAcknowledgementNum,
                0
            )
            outputQueue.offer(responseBuffer)
            TCB.closeTCB(tcb)
        }
    }

    private fun processInput(key: SelectionKey) {
        val tcb = key.attachment() as TCB
        val receiveBuffer = ByteBufferPool.acquire()

        // Leave room for IP + TCP header
        receiveBuffer.position(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE)

        val channel = tcb.channel as SocketChannel
        val readBytes: Int

        try {
            readBytes = channel.read(receiveBuffer)
        } catch (e: Exception) {
            Log.e(TAG, "Read error: ${tcb.ipAndPort}", e)
            val rstBuffer = ByteBufferPool.acquire()
            tcb.referencePacket.updateTCPBuffer(
                rstBuffer,
                Packet.TCPHeader.RST.toByte(),
                0,
                tcb.myAcknowledgementNum,
                0
            )
            outputQueue.offer(rstBuffer)
            TCB.closeTCB(tcb)
            ByteBufferPool.release(receiveBuffer)
            return
        }

        if (readBytes == -1) {
            // Server closed connection
            synchronized(tcb) {
                key.interestOps(0)
                tcb.waitingForNetworkData = false

                if (tcb.status != TCB.TCBStatus.CLOSE_WAIT) {
                    tcb.status = TCB.TCBStatus.LAST_ACK
                    tcb.referencePacket.updateTCPBuffer(
                        receiveBuffer,
                        (Packet.TCPHeader.FIN or Packet.TCPHeader.ACK).toByte(),
                        tcb.mySequenceNum,
                        tcb.myAcknowledgementNum,
                        0
                    )
                    tcb.mySequenceNum++
                    outputQueue.offer(receiveBuffer)
                } else {
                    ByteBufferPool.release(receiveBuffer)
                }
            }
            return
        }

        if (readBytes == 0) {
            ByteBufferPool.release(receiveBuffer)
            return
        }

        // Send data back through TUN
        synchronized(tcb) {
            tcb.referencePacket.updateTCPBuffer(
                receiveBuffer,
                (Packet.TCPHeader.PSH or Packet.TCPHeader.ACK).toByte(),
                tcb.mySequenceNum,
                tcb.myAcknowledgementNum,
                readBytes
            )
            // Copy payload data to correct position
            receiveBuffer.position(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE + readBytes)
            tcb.mySequenceNum += readBytes
            outputQueue.offer(receiveBuffer)
        }
    }
}
