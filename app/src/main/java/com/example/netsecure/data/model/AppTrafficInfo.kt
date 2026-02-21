package com.example.netsecure.data.model

import android.graphics.drawable.Drawable

/**
 * Aggregated traffic information for a single app.
 */
data class AppTrafficInfo(
    val packageName: String,
    val appName: String,
    val appIcon: Drawable? = null,
    val totalRequests: Int = 0,
    val totalBytesOut: Long = 0L,
    val totalBytesIn: Long = 0L,
    val uid: Int = -1
)
