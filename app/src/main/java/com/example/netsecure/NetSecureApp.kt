package com.example.netsecure

import android.app.Application
import android.util.Log
import com.example.netsecure.logging.NetSecureLogger
import com.example.netsecure.network.IntelOwlConfig

/**
 * Application class for NetSecure.
 * Initializes singletons before any activity or service.
 */
class NetSecureApp : Application() {

    companion object {
        private const val TAG = "NetSecureApp"

        @Volatile
        var instance: NetSecureApp? = null
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        NetSecureLogger.init(this)           // start file logger before anything else
        IntelOwlConfig.init(this)
        NetSecureLogger.i(NetSecureLogger.TAG_SYSTEM, "NetSecure application started")
    }
}
