package com.example.netsecure.notification

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.example.netsecure.MainActivity
import com.example.netsecure.data.model.ThreatAlert
import com.example.netsecure.data.model.ThreatSeverity
import com.example.netsecure.logging.NetSecureLogger
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages heads-up, ongoing (non-dismissible) Android notifications for
 * HIGH/CRITICAL threat alerts and IDS signature matches.
 *
 * Uses a dedicated IMPORTANCE_HIGH notification channel separate from the
 * low-priority VPN capture channel.
 */
object ThreatNotificationManager {

    private const val TAG = "ThreatNotifMgr"
    const val THREAT_CHANNEL_ID = "netsecure_threat_channel"
    private const val GROUP_KEY = "netsecure_threat_group"
    private const val SUMMARY_NOTIFICATION_ID = 9000
    private const val BASE_NOTIFICATION_ID = 9001

    private var appContext: Context? = null

    /** observable → notification ID */
    private val activeNotifications = ConcurrentHashMap<String, Int>()
    private var nextId = BASE_NOTIFICATION_ID

    fun init(context: Context) {
        appContext = context.applicationContext
        createThreatChannel()
        NetSecureLogger.i(NetSecureLogger.TAG_SYSTEM, "ThreatNotificationManager initialized")
    }

    private fun createThreatChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                THREAT_CHANNEL_ID,
                "Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Critical security alerts from threat detection and IDS"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 300, 200, 300)
                enableLights(true)
                lightColor = 0xFFFF1744.toInt() // AlertRed
                setBypassDnd(true)
            }
            val nm = appContext?.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            nm?.createNotificationChannel(channel)
        }
    }

    /**
     * Show a heads-up ongoing notification for a threat alert.
     * Call for HIGH/CRITICAL IntelOwl results and ALL IDS signature matches.
     */
    fun showThreatNotification(alert: ThreatAlert) {
        val ctx = appContext ?: return

        // Deduplicate — don't re-notify for the same observable
        if (activeNotifications.containsKey(alert.observable)) return

        val notifId = nextId++
        activeNotifications[alert.observable] = notifId

        val severityLabel = alert.report.severity.displayName.uppercase()
        val isSignature = alert.report.classification == "payload_signature"
        val title = if (isSignature) {
            "\u26A0\uFE0F IDS Alert: $severityLabel"
        } else {
            "\u26A0\uFE0F $severityLabel Threat Detected"
        }

        val appNames = alert.associatedPackages.joinToString(", ")
        val body = buildString {
            append(alert.observable)
            if (appNames.isNotBlank()) append(" — $appNames")
            if (alert.report.categories.isNotEmpty()) {
                append("\n${alert.report.categories.joinToString(", ")}")
            }
        }

        val detailText = buildString {
            append("Observable: ${alert.observable}\n")
            append("Severity: ${alert.report.severity.displayName} (${(alert.report.overallScore * 100).toInt()}%)\n")
            if (appNames.isNotBlank()) append("Apps: $appNames\n")
            for (ar in alert.report.analyzerResults) {
                append("• ${ar.analyzerName}: ${ar.verdict} (${(ar.score * 100).toInt()}%)\n")
            }
        }

        // Tap → open app
        val tapIntent = PendingIntent.getActivity(
            ctx, notifId,
            Intent(ctx, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("navigate_to", "threat_intelligence")
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Dismiss action
        val dismissIntent = PendingIntent.getBroadcast(
            ctx, notifId + 50000,
            Intent("com.example.netsecure.DISMISS_THREAT").apply {
                setPackage(ctx.packageName)
                putExtra("alert_id", alert.alertId)
                putExtra("observable", alert.observable)
                putExtra("notif_id", notifId)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val color = if (alert.report.severity == ThreatSeverity.CRITICAL) {
            0xFFFF1744.toInt()
        } else {
            0xFFFF9100.toInt()
        }

        val notification = NotificationCompat.Builder(ctx, THREAT_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(detailText))
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setColor(color)
            .setOngoing(true)
            .setAutoCancel(false)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setContentIntent(tapIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Dismiss", dismissIntent)
            .setGroup(GROUP_KEY)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ActivityCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                NetSecureLogger.w(TAG, "POST_NOTIFICATIONS permission not granted, skipping notification")
                return
            }
        }

        NotificationManagerCompat.from(ctx).notify(notifId, notification)

        // Show summary group notification when >1 active
        if (activeNotifications.size > 1) {
            showGroupSummary(ctx)
        }

        NetSecureLogger.i(TAG, "Threat notification shown for ${alert.observable} (ID=$notifId)")
    }

    private fun showGroupSummary(ctx: Context) {
        val summary = NotificationCompat.Builder(ctx, THREAT_CHANNEL_ID)
            .setContentTitle("NetSecure — ${activeNotifications.size} Active Threats")
            .setContentText("${activeNotifications.size} security alerts require attention")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setColor(0xFFFF1744.toInt())
            .setOngoing(true)
            .setGroup(GROUP_KEY)
            .setGroupSummary(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ActivityCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) return
        }
        NotificationManagerCompat.from(ctx).notify(SUMMARY_NOTIFICATION_ID, summary)
    }

    /**
     * Cancel a specific threat notification (called when user dismisses the alert).
     */
    fun cancelNotification(observable: String) {
        val ctx = appContext ?: return
        val notifId = activeNotifications.remove(observable) ?: return
        NotificationManagerCompat.from(ctx).cancel(notifId)

        if (activeNotifications.isEmpty()) {
            NotificationManagerCompat.from(ctx).cancel(SUMMARY_NOTIFICATION_ID)
        } else if (activeNotifications.size == 1) {
            NotificationManagerCompat.from(ctx).cancel(SUMMARY_NOTIFICATION_ID)
        }

        NetSecureLogger.i(TAG, "Threat notification cancelled for $observable")
    }

    /**
     * Cancel all threat notifications.
     */
    fun cancelAll() {
        val ctx = appContext ?: return
        for ((_, notifId) in activeNotifications) {
            NotificationManagerCompat.from(ctx).cancel(notifId)
        }
        NotificationManagerCompat.from(ctx).cancel(SUMMARY_NOTIFICATION_ID)
        activeNotifications.clear()
    }
}
