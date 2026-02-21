package com.example.netsecure.model

/**
 * Describes a malware blacklist source. Referenced from JNI for blacklist loading.
 */
class BlacklistDescriptor(
    @JvmField val fname: String,
    @JvmField val type: Type,
    @JvmField val label: String = "",
    @JvmField val url: String = ""
) {
    enum class Type {
        IP_BLACKLIST,
        DOMAIN_BLACKLIST
    }
}
