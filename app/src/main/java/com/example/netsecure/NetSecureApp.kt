package com.example.netsecure

import android.app.Application
import android.util.Log

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
        Log.i(TAG, "NetSecure application initialized")
    }
}
