package com.example.netsecure.logging

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileWriter
import java.io.PrintWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors

/**
 * NetSecure's persistent in-app logger — inspired by PCAPdroid's Log.java.
 *
 * - Writes every entry to <cacheDir>/netsecure.log (max 1 MB, rotates to .1)
 * - Keeps the last [RING_BUFFER_SIZE] entries in memory for the LogsScreen
 * - Mirrors every entry to android.util.Log (Logcat)
 * - Thread-safe: background single-thread executor handles all file I/O
 *
 * Usage:
 *   NetSecureLogger.init(context)
 *   NetSecureLogger.i("TAG", "something happened")
 */
object NetSecureLogger {

    // ── Log levels ──────────────────────────────────────────────────────────
    const val VERBOSE = 'V'
    const val DEBUG   = 'D'
    const val INFO    = 'I'
    const val WARN    = 'W'
    const val ERROR   = 'E'

    // ── Log tags / categories for tab filtering ──────────────────────────────
    const val TAG_VPN      = "VPN"
    const val TAG_THREAT   = "Threat"
    const val TAG_TRAFFIC  = "Traffic"
    const val TAG_SYSTEM   = "System"

    data class LogEntry(
        val timestampMs: Long,
        val level: Char,
        val tag: String,
        val message: String
    ) {
        val timestamp: String get() =
            SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(Date(timestampMs))
        val fullTimestamp: String get() =
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(Date(timestampMs))
    }

    private const val LOG_FILE_NAME   = "netsecure.log"
    private const val LOG_FILE_BACKUP = "netsecure.log.1"
    private const val MAX_FILE_BYTES  = 1_000_000L   // 1 MB
    private const val RING_BUFFER_SIZE = 1000

    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "NetSecureLogger") }
    private val ringBuffer = ArrayBlockingQueue<LogEntry>(RING_BUFFER_SIZE)

    @Volatile private var logFile: File? = null
    @Volatile private var initialized = false

    // ── Init ──────────────────────────────────────────────────────────────────

    fun init(context: Context) {
        if (initialized) return
        logFile = File(context.cacheDir, LOG_FILE_NAME)
        initialized = true
        i(TAG_SYSTEM, "─── NetSecure logger started ───")
    }

    fun getLogFile(): File? = logFile

    // ── Public logging API ────────────────────────────────────────────────────

    fun v(tag: String, msg: String) = write(VERBOSE, tag, msg)
    fun d(tag: String, msg: String) = write(DEBUG,   tag, msg)
    fun i(tag: String, msg: String) = write(INFO,    tag, msg)
    fun w(tag: String, msg: String) = write(WARN,    tag, msg)
    fun e(tag: String, msg: String) = write(ERROR,   tag, msg)
    fun e(tag: String, msg: String, t: Throwable) = write(ERROR, tag, "$msg: ${t.message}")

    // ── In-memory access ─────────────────────────────────────────────────────

    /** Returns the in-memory ring buffer entries, newest last. */
    fun getLogs(): List<LogEntry> = ringBuffer.toList()

    /** Returns entries filtered by tag (category). */
    fun getLogs(tag: String): List<LogEntry> =
        ringBuffer.filter { it.tag.contains(tag, ignoreCase = true) }

    /** Clears in-memory buffer (does NOT clear the log file). */
    fun clearMemory() { ringBuffer.clear() }

    /** Formats all in-memory logs as a plain-text string for share/copy. */
    fun getAllLogsText(): String = buildString {
        append("=== NetSecure System Log ===\n")
        append("Generated: ${fmt.format(Date())}\n\n")
        for (e in getLogs()) {
            append("[${e.fullTimestamp}] ${e.level}/${e.tag}: ${e.message}\n")
        }
    }

    /** Returns the entire log file content as text (last [maxLines] lines). */
    fun getFileLogText(maxLines: Int = 500): String {
        val file = logFile ?: return ""
        if (!file.exists()) return ""
        return try {
            val lines = file.readLines()
            lines.takeLast(maxLines).joinToString("\n")
        } catch (e: Exception) {
            ""
        }
    }

    /** Clears the log file completely. */
    fun clearLogFile() {
        executor.execute {
            try { logFile?.writeText("") } catch (_: Exception) {}
        }
    }

    // ── Internal write ────────────────────────────────────────────────────────

    private fun write(level: Char, tag: String, message: String) {
        val entry = LogEntry(System.currentTimeMillis(), level, tag, message)

        // Mirror to Logcat
        when (level) {
            VERBOSE -> Log.v(tag, message)
            DEBUG   -> Log.d(tag, message)
            INFO    -> Log.i(tag, message)
            WARN    -> Log.w(tag, message)
            ERROR   -> Log.e(tag, message)
        }

        // Add to ring buffer (drop oldest if full)
        if (!ringBuffer.offer(entry)) {
            ringBuffer.poll()
            ringBuffer.offer(entry)
        }

        // Write to file on background thread
        executor.execute { writeToFile(entry) }
    }

    private fun writeToFile(entry: LogEntry) {
        val file = logFile ?: return
        try {
            // Rotate if over 1 MB
            if (file.exists() && file.length() > MAX_FILE_BYTES) {
                val backup = File(file.parent, LOG_FILE_BACKUP)
                backup.delete()
                file.renameTo(backup)
            }
            PrintWriter(FileWriter(file, true)).use { pw ->
                pw.println("[${entry.fullTimestamp}] ${entry.level}/${entry.tag}: ${entry.message}")
            }
        } catch (_: Exception) {}
    }
}
