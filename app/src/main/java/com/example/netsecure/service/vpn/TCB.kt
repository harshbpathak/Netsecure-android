package com.example.netsecure.service.vpn

import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap

/**
 * TCP Control Block — tracks the state of each TCP connection proxied through the VPN.
 */
class TCB(
    val ipAndPort: String,
    var mySequenceNum: Long,
    var theirSequenceNum: Long,
    var myAcknowledgementNum: Long,
    var theirAcknowledgementNum: Long,
    val channel: SocketChannel,
    val referencePacket: Packet
) {
    var status: TCBStatus = TCBStatus.SYN_SENT
    var selectionKey: SelectionKey? = null
    var waitingForNetworkData = false

    enum class TCBStatus {
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        CLOSE_WAIT,
        LAST_ACK
    }

    companion object {
        private val tcbCache = ConcurrentHashMap<String, TCB>()

        fun getTCB(key: String): TCB? = tcbCache[key]

        fun putTCB(key: String, tcb: TCB) {
            tcbCache[key] = tcb
        }

        fun closeTCB(tcb: TCB) {
            tcbCache.remove(tcb.ipAndPort)
            try {
                tcb.channel.close()
            } catch (_: Exception) {}
        }

        fun closeAll() {
            for (tcb in tcbCache.values) {
                try {
                    tcb.channel.close()
                } catch (_: Exception) {}
            }
            tcbCache.clear()
        }
    }
}
