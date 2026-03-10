package com.example.netsecure.network

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.GsonBuilder
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/**
 * Singleton configuration holder for IntelOwl integration.
 *
 * Sensitive data (API token) is stored encrypted via AndroidKeyStore +
 * EncryptedSharedPreferences. Non-sensitive settings use regular SharedPreferences.
 *
 * Must call [init] once during app startup (e.g., from Application.onCreate or
 * before first CaptureService start) before calling [buildService].
 */
object IntelOwlConfig {

    private const val TAG = "IntelOwlConfig"
    private const val PREFS_NAME = "intelowl_prefs"
    private const val ENCRYPTED_PREFS_NAME = "intelowl_encrypted"

    // Keys
    private const val KEY_SERVER_URL = "server_url"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_TLP = "tlp"
    private const val KEY_ANALYZERS = "analyzers"
    private const val KEY_MAX_JOBS = "max_concurrent_jobs"
    private const val KEY_CACHE_TTL = "cache_ttl_minutes"
    private const val KEY_API_TOKEN = "api_token"  // stored in encrypted prefs

    // Default analyzer list
    val DEFAULT_ANALYZERS = listOf(
        "AbuseIPDB",
        "MalwareBazaar_Get_Observable",
        "OTXQuery",
        "GreyNoiseCommunity"
    )

    // TLP options
    val TLP_OPTIONS = listOf("CLEAR", "GREEN", "AMBER", "RED")

    // In-memory state (loaded from prefs on init)
    @Volatile var serverUrl: String = ""
        private set
    @Volatile var apiToken: String = ""
        private set
    @Volatile var enabled: Boolean = false
        private set
    @Volatile var tlp: String = "AMBER"
        private set
    @Volatile var selectedAnalyzers: List<String> = DEFAULT_ANALYZERS
        private set
    @Volatile var maxConcurrentJobs: Int = 5
        private set
    @Volatile var cacheTtlMinutes: Int = 60
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
            regularPrefs // fallback — token won't be encrypted but app won't crash
        }

        load()
    }

    private fun load() {
        val prefs = regularPrefs ?: return
        serverUrl = prefs.getString(KEY_SERVER_URL, "") ?: ""
        enabled = prefs.getBoolean(KEY_ENABLED, false)
        tlp = prefs.getString(KEY_TLP, "AMBER") ?: "AMBER"
        maxConcurrentJobs = prefs.getInt(KEY_MAX_JOBS, 5)
        cacheTtlMinutes = prefs.getInt(KEY_CACHE_TTL, 60)
        val analyzersStr = prefs.getString(KEY_ANALYZERS, null)
        selectedAnalyzers = if (analyzersStr != null) analyzersStr.split(",") else DEFAULT_ANALYZERS
        apiToken = encryptedPrefs?.getString(KEY_API_TOKEN, "") ?: ""
    }

    /** Save and apply all settings at once. */
    fun save(
        context: Context,
        serverUrl: String,
        apiToken: String,
        enabled: Boolean,
        tlp: String,
        selectedAnalyzers: List<String>,
        maxConcurrentJobs: Int,
        cacheTtlMinutes: Int
    ) {
        if (regularPrefs == null) init(context)
        regularPrefs?.edit()?.apply {
            putString(KEY_SERVER_URL, serverUrl)
            putBoolean(KEY_ENABLED, enabled)
            putString(KEY_TLP, tlp)
            putString(KEY_ANALYZERS, selectedAnalyzers.joinToString(","))
            putInt(KEY_MAX_JOBS, maxConcurrentJobs)
            putInt(KEY_CACHE_TTL, cacheTtlMinutes)
            apply()
        }
        encryptedPrefs?.edit()?.apply {
            putString(KEY_API_TOKEN, apiToken)
            apply()
        }
        // Update in-memory state
        this.serverUrl = serverUrl
        this.apiToken = apiToken
        this.enabled = enabled
        this.tlp = tlp
        this.selectedAnalyzers = selectedAnalyzers
        this.maxConcurrentJobs = maxConcurrentJobs
        this.cacheTtlMinutes = cacheTtlMinutes
    }

    /** Returns true if we have enough config to make API calls. */
    fun isConfigured(): Boolean = enabled && serverUrl.isNotBlank() && apiToken.isNotBlank()

    /**
     * Build a new Retrofit service instance based on current config.
     * Returns null if not configured.
     */
    fun buildService(): IntelOwlApiService? {
        if (!isConfigured()) return null

        val baseUrl = serverUrl.trimEnd('/') + "/"

        val authInterceptor = Interceptor { chain ->
            val request = chain.request().newBuilder()
                .addHeader("Authorization", "Token $apiToken")
                .addHeader("Accept", "application/json")
                .addHeader("Content-Type", "application/json")
                // Bypass ngrok browser-warning interstitial page
                .addHeader("ngrok-skip-browser-warning", "true")
                .build()
            chain.proceed(request)
        }

        val loggingInterceptor = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }

        val okHttp = OkHttpClient.Builder()
            .addInterceptor(authInterceptor)
            .addInterceptor(loggingInterceptor)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()

        val gson = GsonBuilder()
            .setLenient()
            .create()

        return try {
            Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(okHttp)
                .addConverterFactory(GsonConverterFactory.create(gson))
                .build()
                .create(IntelOwlApiService::class.java)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to build Retrofit service: ${e.message}")
            null
        }
    }

    /**
     * Build a throwaway Retrofit service with explicit credentials.
     * Used by the Settings screen "Test Connection" button — does NOT
     * require the global config to be saved first.
     */
    fun buildServiceForCredentials(url: String, token: String): IntelOwlApiService? {
        if (url.isBlank() || token.isBlank()) return null
        val baseUrl = url.trimEnd('/') + "/"
        val interceptor = Interceptor { chain ->
            val req = chain.request().newBuilder()
                .addHeader("Authorization", "Token $token")
                .addHeader("Accept", "application/json")
                .addHeader("ngrok-skip-browser-warning", "true")
                .build()
            chain.proceed(req)
        }
        val client = OkHttpClient.Builder()
            .addInterceptor(interceptor)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
        return try {
            Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(client)
                .addConverterFactory(GsonConverterFactory.create(GsonBuilder().setLenient().create()))
                .build()
                .create(IntelOwlApiService::class.java)
        } catch (e: Exception) {
            Log.e(TAG, "buildServiceForCredentials error: ${e.message}")
            null
        }
    }
}
