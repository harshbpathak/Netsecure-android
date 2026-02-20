package com.example.netsecure.service.vpn

import android.net.VpnService
import android.util.Log
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.Random
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Handles outgoing TCP packets from the TUN device.
 * Manages the TCP state machine (SYN/ACK/FIN/RST) and forwards data
 * to real servers via protected SocketChannels.
 */
class TCPInput(
    private val inputQueue: ConcurrentLinkedQueue<Packet>,
    private val outputQueue: ConcurrentLinkedQueue<ByteBuffer>,
    private val selector: Selector,
    private val vpnService: VpnService
) : Runnable {

    companion object {
        private const val TAG = "TCPInput-Handler"
    }

    private val random = Random()

    override fun run() {
        Log.i(TAG, "Started")
        try {
            while (!Thread.interrupted()) {
                val currentPacket = inputQueue.poll()
                if (currentPacket == null) {
                    Thread.sleep(10)
                    continue
                }

                val payloadBuffer = currentPacket.backingBuffer
                val responseBuffer = ByteBufferPool.acquire()

                val destAddr = currentPacket.ip4Header.destinationAddress
                val tcpHeader = currentPacket.tcpHeader!!
                val destPort = tcpHeader.destinationPort
                val srcPort = tcpHeader.sourcePort

                val key = "${destAddr.hostAddress}:$destPort:$srcPort"
                val tcb = TCB.getTCB(key)

                if (tcb == null) {
                    initializeConnection(key, destAddr, destPort, currentPacket, tcpHeader, responseBuffer)
                } else if (tcpHeader.isSYN()) {
                    processDuplicateSYN(tcb, tcpHeader, responseBuffer)
                } else if (tcpHeader.isRST()) {
                    closeCleanly(tcb, responseBuffer)
                } else if (tcpHeader.isFIN()) {
                    processFIN(tcb, tcpHeader, responseBuffer)
                } else if (tcpHeader.isACK()) {
                    processACK(tcb, tcpHeader, payloadBuffer, responseBuffer)
                }

                if (responseBuffer.position() == 0) {
                    ByteBufferPool.release(responseBuffer)
                }
                ByteBufferPool.release(payloadBuffer)
            }
        } catch (_: InterruptedException) {
            Log.i(TAG, "Stopping")
        } catch (e: Exception) {
            Log.e(TAG, "Error", e)
        } finally {
            TCB.closeAll()
        }
    }

    private fun initializeConnection(
        key: String,
        destAddr: java.net.InetAddress,
        destPort: Int,
        currentPacket: Packet,
        tcpHeader: Packet.TCPHeader,
        responseBuffer: ByteBuffer
    ) {
        currentPacket.swapSourceAndDestination()

        if (tcpHeader.isSYN()) {
            val outputChannel = SocketChannel.open()
            outputChannel.configureBlocking(false)
            vpnService.protect(outputChannel.socket())

            val tcb = TCB(
                key,
                random.nextInt(Short.MAX_VALUE + 1).toLong(),
                tcpHeader.sequenceNumber,
                tcpHeader.sequenceNumber + 1,
                tcpHeader.acknowledgementNumber,
                outputChannel,
                currentPacket
            )
            TCB.putTCB(key, tcb)

            try {
                outputChannel.connect(InetSocketAddress(destAddr, destPort))
                if (outputChannel.finishConnect()) {
                    tcb.status = TCB.TCBStatus.SYN_RECEIVED
                    currentPacket.updateTCPBuffer(
                        responseBuffer,
                        (Packet.TCPHeader.SYN or Packet.TCPHeader.ACK).toByte(),
                        tcb.mySequenceNum,
                        tcb.myAcknowledgementNum,
                        0
                    )
                    tcb.mySequenceNum++
                } else {
                    tcb.status = TCB.TCBStatus.SYN_SENT
                    selector.wakeup()
                    tcb.selectionKey = outputChannel.register(selector, SelectionKey.OP_CONNECT, tcb)
                    return
                }
            } catch (e: Exception) {
                Log.e(TAG, "Connect error: $key", e)
                currentPacket.updateTCPBuffer(
                    responseBuffer,
                    Packet.TCPHeader.RST.toByte(),
                    0,
                    tcb.myAcknowledgementNum,
                    0
                )
                TCB.closeTCB(tcb)
            }
        } else {
            currentPacket.updateTCPBuffer(
                responseBuffer,
                Packet.TCPHeader.RST.toByte(),
                0,
                tcpHeader.sequenceNumber + 1,
                0
            )
        }
        outputQueue.offer(responseBuffer)
    }

    private fun processDuplicateSYN(tcb: TCB, tcpHeader: Packet.TCPHeader, responseBuffer: ByteBuffer) {
        synchronized(tcb) {
            if (tcb.status == TCB.TCBStatus.SYN_SENT) {
                tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + 1
                return
            }
        }
        sendRST(tcb, 1, responseBuffer)
    }

    private fun processFIN(tcb: TCB, tcpHeader: Packet.TCPHeader, responseBuffer: ByteBuffer) {
        synchronized(tcb) {
            tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + 1
            tcb.theirAcknowledgementNum = tcpHeader.acknowledgementNumber

            if (tcb.waitingForNetworkData) {
                tcb.status = TCB.TCBStatus.CLOSE_WAIT
                tcb.referencePacket.updateTCPBuffer(
                    responseBuffer,
                    Packet.TCPHeader.ACK.toByte(),
                    tcb.mySequenceNum,
                    tcb.myAcknowledgementNum,
                    0
                )
            } else {
                tcb.status = TCB.TCBStatus.LAST_ACK
                tcb.referencePacket.updateTCPBuffer(
                    responseBuffer,
                    (Packet.TCPHeader.FIN or Packet.TCPHeader.ACK).toByte(),
                    tcb.mySequenceNum,
                    tcb.myAcknowledgementNum,
                    0
                )
                tcb.mySequenceNum++
            }
        }
        outputQueue.offer(responseBuffer)
    }

    private fun processACK(
        tcb: TCB,
        tcpHeader: Packet.TCPHeader,
        payloadBuffer: ByteBuffer,
        responseBuffer: ByteBuffer
    ) {
        val payloadSize = payloadBuffer.remaining()

        synchronized(tcb) {
            val outputChannel = tcb.channel

            if (tcb.status == TCB.TCBStatus.SYN_RECEIVED) {
                tcb.status = TCB.TCBStatus.ESTABLISHED
                selector.wakeup()
                tcb.selectionKey = outputChannel.register(selector, SelectionKey.OP_READ, tcb)
                tcb.waitingForNetworkData = true
            } else if (tcb.status == TCB.TCBStatus.LAST_ACK) {
                closeCleanly(tcb, responseBuffer)
                return
            }

            if (payloadSize == 0) return // Empty ACK

            if (!tcb.waitingForNetworkData) {
                selector.wakeup()
                tcb.selectionKey?.interestOps(SelectionKey.OP_READ)
                tcb.waitingForNetworkData = true
            }

            // Forward payload to real server
            try {
                while (payloadBuffer.hasRemaining()) {
                    outputChannel.write(payloadBuffer)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Write error: ${tcb.ipAndPort}", e)
                sendRST(tcb, payloadSize, responseBuffer)
                return
            }

            tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + payloadSize
            tcb.theirAcknowledgementNum = tcpHeader.acknowledgementNumber

            tcb.referencePacket.updateTCPBuffer(
                responseBuffer,
                Packet.TCPHeader.ACK.toByte(),
                tcb.mySequenceNum,
                tcb.myAcknowledgementNum,
                0
            )
        }
        outputQueue.offer(responseBuffer)
    }

    private fun sendRST(tcb: TCB, prevPayloadSize: Int, buffer: ByteBuffer) {
        tcb.referencePacket.updateTCPBuffer(
            buffer,
            Packet.TCPHeader.RST.toByte(),
            0,
            tcb.myAcknowledgementNum + prevPayloadSize,
            0
        )
        outputQueue.offer(buffer)
        TCB.closeTCB(tcb)
    }

    private fun closeCleanly(tcb: TCB, buffer: ByteBuffer) {
        ByteBufferPool.release(buffer)
        TCB.closeTCB(tcb)
    }
}
