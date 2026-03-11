package com.example.netsecure.notification

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Singleton configuration holder for email alert notifications.
 *
 * SMTP password is stored encrypted via AndroidKeyStore + EncryptedSharedPreferences
 * (same MasterKey pattern as IntelOwlConfig).
 *
 * Must call [init] once during app startup before using.
 */
object EmailConfig {

    private const val TAG = "EmailConfig"
    private const val PREFS_NAME = "email_prefs"
    private const val ENCRYPTED_PREFS_NAME = "email_encrypted"

    // Keys
    private const val KEY_ENABLED = "enabled"
    private const val KEY_SMTP_HOST = "smtp_host"
    private const val KEY_SMTP_PORT = "smtp_port"
    private const val KEY_SENDER_EMAIL = "sender_email"
    private const val KEY_SENDER_PASSWORD = "sender_password" // encrypted
    private const val KEY_RECIPIENTS = "recipients"
    private const val KEY_COOLDOWN_MINUTES = "cooldown_minutes"
    private const val KEY_ENABLE_HIGH_CRITICAL = "enable_high_critical"
    private const val KEY_ENABLE_IDS = "enable_ids"

    // In-memory state
    @Volatile var enabled: Boolean = false
        private set
    @Volatile var smtpHost: String = "smtp.gmail.com"
        private set
    @Volatile var smtpPort: Int = 587
        private set
    @Volatile var senderEmail: String = ""
        private set
    @Volatile var senderPassword: String = ""
        private set
    @Volatile var recipients: List<String> = emptyList()
        private set
    @Volatile var cooldownMinutes: Int = 15
        private set
    @Volatile var enableForHighCritical: Boolean = true
        private set
    @Volatile var enableForIds: Boolean = true
        private set

    private var regularPrefs: SharedPreferences? = null
    private var encryptedPrefs: SharedPreferences? = null

    /** Initialize from SharedPreferences. Call once on startup. */
    fun init(context: Context) {
        regularPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        encryptedPrefs = try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                ENCRYPTED_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create EncryptedSharedPreferences, falling back to regular", e)
            regularPrefs
        }

        load()
    }

    private fun load() {
        val prefs = regularPrefs ?: return
        enabled = prefs.getBoolean(KEY_ENABLED, false)
        smtpHost = prefs.getString(KEY_SMTP_HOST, "smtp.gmail.com") ?: "smtp.gmail.com"
        smtpPort = prefs.getInt(KEY_SMTP_PORT, 587)
        senderEmail = prefs.getString(KEY_SENDER_EMAIL, "") ?: ""
        val recipientsStr = prefs.getString(KEY_RECIPIENTS, null)
        recipients = if (recipientsStr.isNullOrBlank()) emptyList()
                     else recipientsStr.split(",").map { it.trim() }.filter { it.isNotBlank() }
        cooldownMinutes = prefs.getInt(KEY_COOLDOWN_MINUTES, 15)
        enableForHighCritical = prefs.getBoolean(KEY_ENABLE_HIGH_CRITICAL, true)
        enableForIds = prefs.getBoolean(KEY_ENABLE_IDS, true)
        senderPassword = encryptedPrefs?.getString(KEY_SENDER_PASSWORD, "") ?: ""
    }

    /** Save all settings at once. */
    fun save(
        context: Context,
        enabled: Boolean,
        smtpHost: String,
        smtpPort: Int,
        senderEmail: String,
        senderPassword: String,
        recipients: List<String>,
        cooldownMinutes: Int,
        enableForHighCritical: Boolean,
        enableForIds: Boolean
    ) {
        if (regularPrefs == null) init(context)
        regularPrefs?.edit()?.apply {
            putBoolean(KEY_ENABLED, enabled)
            putString(KEY_SMTP_HOST, smtpHost)
            putInt(KEY_SMTP_PORT, smtpPort)
            putString(KEY_SENDER_EMAIL, senderEmail)
            putString(KEY_RECIPIENTS, recipients.joinToString(","))
            putInt(KEY_COOLDOWN_MINUTES, cooldownMinutes)
            putBoolean(KEY_ENABLE_HIGH_CRITICAL, enableForHighCritical)
            putBoolean(KEY_ENABLE_IDS, enableForIds)
            apply()
        }
        encryptedPrefs?.edit()?.apply {
            putString(KEY_SENDER_PASSWORD, senderPassword)
            apply()
        }
        // Update in-memory state
        this.enabled = enabled
        this.smtpHost = smtpHost
        this.smtpPort = smtpPort
        this.senderEmail = senderEmail
        this.senderPassword = senderPassword
        this.recipients = recipients
        this.cooldownMinutes = cooldownMinutes
        this.enableForHighCritical = enableForHighCritical
        this.enableForIds = enableForIds
    }

    /** Returns true when we have enough config to send emails. */
    fun isConfigured(): Boolean =
        enabled && senderEmail.isNotBlank() && senderPassword.isNotBlank() && recipients.isNotEmpty()
}
