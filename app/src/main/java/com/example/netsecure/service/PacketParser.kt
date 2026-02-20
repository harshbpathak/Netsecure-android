package com.example.netsecure.service

import com.example.netsecure.data.model.ConnectionRecord
import com.example.netsecure.data.model.Protocol
import java.nio.ByteBuffer

/**
 * Parses raw IP packets read from the TUN file descriptor.
 * Supports IPv4 with TCP/UDP transport layer extraction.
 */
object PacketParser {

    data class ParsedPacket(
        val sourceIp: String,
        val destIp: String,
        val sourcePort: Int,
        val destPort: Int,
        val protocol: Protocol,
        val totalLength: Int
    )

    /**
     * Parse a raw IP packet from bytes.
     * Returns null if the packet is malformed or unsupported.
     */
    fun parse(packet: ByteArray, length: Int): ParsedPacket? {
        if (length < 20) return null // minimum IPv4 header size

        val buffer = ByteBuffer.wrap(packet, 0, length)

        val versionAndIhl = buffer.get(0).toInt() and 0xFF
        val version = versionAndIhl shr 4

        if (version != 4) return null // only support IPv4 for now

        val ihl = (versionAndIhl and 0x0F) * 4 // header length in bytes
        if (ihl < 20 || length < ihl) return null

        val totalLength = buffer.getShort(2).toInt() and 0xFFFF
        val protocolByte = buffer.get(9).toInt() and 0xFF

        val sourceIp = formatIpv4(buffer, 12)
        val destIp = formatIpv4(buffer, 16)

        // Parse transport layer
        var sourcePort = 0
        var destPort = 0

        when (protocolByte) {
            6 -> { // TCP
                if (length >= ihl + 4) {
                    sourcePort = buffer.getShort(ihl).toInt() and 0xFFFF
                    destPort = buffer.getShort(ihl + 2).toInt() and 0xFFFF
                }
            }
            17 -> { // UDP
                if (length >= ihl + 4) {
                    sourcePort = buffer.getShort(ihl).toInt() and 0xFFFF
                    destPort = buffer.getShort(ihl + 2).toInt() and 0xFFFF
                }
            }
            else -> {
                // ICMP or other protocols — record but no port info
            }
        }

        val protocol = classifyProtocol(protocolByte, destPort, sourcePort)

        return ParsedPacket(
            sourceIp = sourceIp,
            destIp = destIp,
            sourcePort = sourcePort,
            destPort = destPort,
            protocol = protocol,
            totalLength = totalLength
        )
    }

    /**
     * Convert a ParsedPacket to a ConnectionRecord.
     */
    fun toConnectionRecord(parsed: ParsedPacket, uid: Int = -1): ConnectionRecord {
        return ConnectionRecord(
            sourceIp = parsed.sourceIp,
            sourcePort = parsed.sourcePort,
            destIp = parsed.destIp,
            destPort = parsed.destPort,
            protocol = parsed.protocol,
            packetSize = parsed.totalLength,
            uid = uid
        )
    }

    private fun classifyProtocol(ipProtocol: Int, destPort: Int, sourcePort: Int): Protocol {
        return when {
            destPort == 53 || sourcePort == 53 -> Protocol.DNS
            destPort == 80 || sourcePort == 80 -> Protocol.HTTP
            destPort == 443 || sourcePort == 443 -> Protocol.HTTPS
            ipProtocol == 6 -> Protocol.TCP
            ipProtocol == 17 -> Protocol.UDP
            else -> Protocol.UNKNOWN
        }
    }

    private fun formatIpv4(buffer: ByteBuffer, offset: Int): String {
        return buildString {
            for (i in 0 until 4) {
                if (i > 0) append('.')
                append(buffer.get(offset + i).toInt() and 0xFF)
            }
        }
    }
}
