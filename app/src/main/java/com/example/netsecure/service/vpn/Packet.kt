package com.example.netsecure.service.vpn

import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Represents a parsed IP packet with TCP or UDP headers.
 * Supports reading fields from and writing constructed packets back to ByteBuffers.
 *
 * IMPORTANT: After construction, backingBuffer.position points to the START of the
 * transport payload (past all IP + TCP/UDP headers including options).
 */
class Packet(val backingBuffer: ByteBuffer) {

    val ip4Header: IP4Header
    var tcpHeader: TCPHeader? = null
        private set
    var udpHeader: UDPHeader? = null
        private set

    var isTCP = false
        private set
    var isUDP = false
        private set

    /** Actual byte offset where transport payload starts */
    var payloadStart: Int = 0
        private set

    init {
        ip4Header = IP4Header(backingBuffer)

        // Skip any IP options (IHL=5 means 20 bytes, IHL=6 means 24, etc.)
        val ipHeaderEnd = ip4Header.ihl * 4
        backingBuffer.position(ipHeaderEnd)

        when (ip4Header.protocol) {
            IP4Header.TCP -> {
                tcpHeader = TCPHeader(backingBuffer)
                isTCP = true
                // Position past the FULL TCP header (including options)
                payloadStart = ipHeaderEnd + tcpHeader!!.headerLength
                backingBuffer.position(payloadStart)
            }
            IP4Header.UDP -> {
                udpHeader = UDPHeader(backingBuffer)
                isUDP = true
                payloadStart = ipHeaderEnd + UDP_HEADER_SIZE
                // Buffer is already at the right position after UDPHeader reads 8 bytes
            }
            else -> {
                payloadStart = ipHeaderEnd
            }
        }
    }

    fun swapSourceAndDestination() {
        val tmp = ip4Header.sourceAddress
        ip4Header.sourceAddress = ip4Header.destinationAddress
        ip4Header.destinationAddress = tmp

        if (isTCP) {
            val tmpPort = tcpHeader!!.sourcePort
            tcpHeader!!.sourcePort = tcpHeader!!.destinationPort
            tcpHeader!!.destinationPort = tmpPort
        } else if (isUDP) {
            val tmpPort = udpHeader!!.sourcePort
            udpHeader!!.sourcePort = udpHeader!!.destinationPort
            udpHeader!!.destinationPort = tmpPort
        }
    }

    /**
     * Build a TCP response into the given buffer.
     * Always creates a minimal 20-byte TCP header with no options.
     */
    fun updateTCPBuffer(
        buffer: ByteBuffer,
        flags: Byte,
        sequenceNum: Long,
        ackNum: Long,
        payloadSize: Int
    ) {
        buffer.position(0)
        ip4Header.fillHeader(buffer)
        tcpHeader?.fillHeader(buffer, flags, sequenceNum, ackNum)

        val dataOffset = IP4_HEADER_SIZE + TCP_HEADER_SIZE

        // Update IP total length
        val totalLength = dataOffset + payloadSize
        updateIpTotalLength(buffer, totalLength)

        // IP checksum
        updateIpChecksum(buffer)

        // TCP checksum (pseudo-header + TCP header + payload)
        updateTcpChecksum(buffer, totalLength - IP4_HEADER_SIZE)

        buffer.position(totalLength)
    }

    /**
     * Build a UDP response into the given buffer.
     */
    fun updateUDPBuffer(buffer: ByteBuffer, payloadSize: Int) {
        buffer.position(0)
        ip4Header.fillHeader(buffer)
        udpHeader?.fillHeader(buffer, payloadSize)

        val totalLength = IP4_HEADER_SIZE + UDP_HEADER_SIZE + payloadSize
        updateIpTotalLength(buffer, totalLength)
        updateIpChecksum(buffer)
        // UDP checksum is optional for IPv4; set to 0
        buffer.putShort(IP4_HEADER_SIZE + 6, 0)

        buffer.position(totalLength)
    }

    private fun updateIpTotalLength(buffer: ByteBuffer, totalLength: Int) {
        buffer.putShort(2, totalLength.toShort())
    }

    private fun updateIpChecksum(buffer: ByteBuffer) {
        buffer.putShort(10, 0) // clear checksum
        // IHL is always 5 in our constructed packets (no options)
        val len = 20
        var sum = 0L
        for (i in 0 until len step 2) {
            sum += (buffer.getShort(i).toLong() and 0xFFFF)
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        buffer.putShort(10, (sum.inv() and 0xFFFF).toShort())
    }

    private fun updateTcpChecksum(buffer: ByteBuffer, tcpLength: Int) {
        // Clear TCP checksum field
        buffer.putShort(IP4_HEADER_SIZE + 16, 0)

        // Pseudo-header checksum
        var sum = 0L
        // Source IP (bytes 12-15)
        sum += (buffer.getShort(12).toLong() and 0xFFFF)
        sum += (buffer.getShort(14).toLong() and 0xFFFF)
        // Dest IP (bytes 16-19)
        sum += (buffer.getShort(16).toLong() and 0xFFFF)
        sum += (buffer.getShort(18).toLong() and 0xFFFF)
        // Protocol (TCP = 6)
        sum += 6L
        // TCP segment length
        sum += tcpLength.toLong()

        // Sum the TCP header + data
        val start = IP4_HEADER_SIZE
        var i = 0
        while (i < tcpLength - 1) {
            sum += (buffer.getShort(start + i).toLong() and 0xFFFF)
            i += 2
        }
        // Handle odd-length segment
        if (tcpLength % 2 != 0) {
            sum += ((buffer.get(start + tcpLength - 1).toLong() and 0xFF) shl 8)
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        buffer.putShort(IP4_HEADER_SIZE + 16, (sum.inv() and 0xFFFF).toShort())
    }

    companion object {
        const val IP4_HEADER_SIZE = 20   // our constructed IP headers are always 20 bytes
        const val TCP_HEADER_SIZE = 20   // our constructed TCP headers are always 20 bytes
        const val UDP_HEADER_SIZE = 8
    }

    /**
     * IPv4 header representation.
     * Reads the fixed 20-byte portion. Caller must advance past options using ihl.
     */
    class IP4Header(buffer: ByteBuffer) {
        var version: Int
        var ihl: Int              // header length in 32-bit words (5 = 20 bytes, etc.)
        var totalLength: Int
        var identification: Int
        var flags: Int
        var fragmentOffset: Int
        var ttl: Int
        var protocol: Int
        var headerChecksum: Int
        var sourceAddress: InetAddress
        var destinationAddress: InetAddress

        init {
            val versionAndIHL = buffer.get().toInt() and 0xFF
            version = versionAndIHL shr 4
            ihl = versionAndIHL and 0x0F

            buffer.get() // TOS

            totalLength = buffer.short.toInt() and 0xFFFF
            identification = buffer.short.toInt() and 0xFFFF

            val flagsAndOffset = buffer.short.toInt() and 0xFFFF
            flags = flagsAndOffset shr 13
            fragmentOffset = flagsAndOffset and 0x1FFF

            ttl = buffer.get().toInt() and 0xFF
            protocol = buffer.get().toInt() and 0xFF
            headerChecksum = buffer.short.toInt() and 0xFFFF

            val srcBytes = ByteArray(4)
            buffer.get(srcBytes)
            sourceAddress = InetAddress.getByAddress(srcBytes)

            val dstBytes = ByteArray(4)
            buffer.get(dstBytes)
            destinationAddress = InetAddress.getByAddress(dstBytes)
            // NOTE: buffer is now at position 20. Caller skips past options via ihl*4.
        }

        /**
         * Write a minimal 20-byte IP header (IHL=5, no options).
         */
        fun fillHeader(buffer: ByteBuffer) {
            buffer.put(((4 shl 4) or 5).toByte()) // version=4, ihl=5
            buffer.put(0.toByte())                  // TOS
            buffer.putShort(0)                       // totalLength (updated later)
            buffer.putShort(identification.toShort())
            buffer.putShort(0x4000.toShort())        // Don't Fragment flag set
            buffer.put(64.toByte())                  // TTL
            buffer.put(protocol.toByte())
            buffer.putShort(0)                       // checksum (computed later)
            buffer.put(sourceAddress.address)
            buffer.put(destinationAddress.address)
        }

        companion object {
            const val TCP = 6
            const val UDP = 17
        }
    }

    /**
     * TCP header representation.
     * Reads the fixed 20-byte portion. Caller must advance past options using headerLength.
     */
    class TCPHeader(buffer: ByteBuffer) {
        var sourcePort: Int
        var destinationPort: Int
        var sequenceNumber: Long
        var acknowledgementNumber: Long
        var headerLength: Int     // actual header length in bytes (data offset * 4)
        var flags: Int
        var window: Int
        var checksum: Int
        var urgentPointer: Int

        init {
            sourcePort = buffer.short.toInt() and 0xFFFF
            destinationPort = buffer.short.toInt() and 0xFFFF
            sequenceNumber = buffer.int.toLong() and 0xFFFFFFFFL
            acknowledgementNumber = buffer.int.toLong() and 0xFFFFFFFFL
            val dataOffsetByte = buffer.get().toInt() and 0xFF
            headerLength = (dataOffsetByte shr 4) * 4  // typically 20, 32, or 40
            flags = buffer.get().toInt() and 0xFF
            window = buffer.short.toInt() and 0xFFFF
            checksum = buffer.short.toInt() and 0xFFFF
            urgentPointer = buffer.short.toInt() and 0xFFFF
            // NOTE: buffer is now at position +20. Caller skips past options via headerLength.
        }

        fun isSYN(): Boolean = (flags and SYN) != 0
        fun isACK(): Boolean = (flags and ACK) != 0
        fun isFIN(): Boolean = (flags and FIN) != 0
        fun isRST(): Boolean = (flags and RST) != 0

        /**
         * Write a minimal 20-byte TCP header (data offset = 5, no options).
         */
        fun fillHeader(buffer: ByteBuffer, flags: Byte, seq: Long, ack: Long) {
            buffer.putShort(sourcePort.toShort())
            buffer.putShort(destinationPort.toShort())
            buffer.putInt(seq.toInt())
            buffer.putInt(ack.toInt())
            buffer.put((5 shl 4).toByte()) // data offset = 5 (20 bytes)
            buffer.put(flags)
            buffer.putShort(65535.toShort()) // window
            buffer.putShort(0)               // checksum (computed later)
            buffer.putShort(0)               // urgent pointer
        }

        companion object {
            const val FIN = 0x01
            const val SYN = 0x02
            const val RST = 0x04
            const val PSH = 0x08
            const val ACK = 0x10
        }
    }

    /**
     * UDP header (always 8 bytes, no options).
     */
    class UDPHeader(buffer: ByteBuffer) {
        var sourcePort: Int
        var destinationPort: Int
        var length: Int
        var checksum: Int

        init {
            sourcePort = buffer.short.toInt() and 0xFFFF
            destinationPort = buffer.short.toInt() and 0xFFFF
            length = buffer.short.toInt() and 0xFFFF
            checksum = buffer.short.toInt() and 0xFFFF
        }

        fun fillHeader(buffer: ByteBuffer, payloadSize: Int) {
            val udpLen = UDP_HEADER_SIZE + payloadSize
            buffer.putShort(sourcePort.toShort())
            buffer.putShort(destinationPort.toShort())
            buffer.putShort(udpLen.toShort())
            buffer.putShort(0) // checksum (0 = disabled for IPv4)
        }
    }
}
