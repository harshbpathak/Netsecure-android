package com.example.netsecure.model

/**
 * A match list for firewall/whitelist/decryption rules.
 * Provides ListDescriptor inner class referenced from JNI.
 */
class MatchList(val name: String) {
    val apps = mutableListOf<String>()
    val hosts = mutableListOf<String>()
    val ips = mutableListOf<String>()
    val countries = mutableListOf<String>()

    /**
     * JNI-accessible descriptor. Fields referenced from jni_impl.c.
     */
    class ListDescriptor {
        @JvmField val apps: List<String> = emptyList()
        @JvmField val hosts: List<String> = emptyList()
        @JvmField val ips: List<String> = emptyList()
        @JvmField val countries: List<String> = emptyList()
    }
}
