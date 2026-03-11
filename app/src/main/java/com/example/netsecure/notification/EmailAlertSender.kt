package com.example.netsecure.notification

import android.util.Log
import com.example.netsecure.data.model.ThreatAlert
import com.example.netsecure.data.model.ThreatSeverity
import com.example.netsecure.logging.NetSecureLogger
import com.google.gson.GsonBuilder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.activation.DataHandler
import javax.mail.*
import javax.mail.internet.*
import javax.mail.util.ByteArrayDataSource

/**
 * Sends email alerts for HIGH/CRITICAL threats and IDS signature matches
 * via SMTP using JavaMail.
 *
 * Features:
 * - HTML email body with analyzer summary
 * - JSON report file attachment
 * - Per-observable cooldown to prevent email flooding
 * - 1 retry on MessagingException with 5s delay
 * - Non-blocking IO via coroutine scope
 */
object EmailAlertSender {

    private const val TAG = "EmailAlertSender"
    private val gson = GsonBuilder().setPrettyPrinting().create()

    /** observable → last email sent timestamp */
    private val cooldownTracker = ConcurrentHashMap<String, Long>()

    /**
     * Send an alert email if email notifications are configured and enabled.
     * Should be called from an IO dispatcher (non-blocking).
     */
    suspend fun sendAlertEmail(alert: ThreatAlert) {
        if (!EmailConfig.isConfigured()) return

        // Check trigger conditions
        val isHighCritical = alert.report.severity.ordinalScore >= ThreatSeverity.HIGH.ordinalScore
        val isSignature = alert.report.classification == "payload_signature"

        if (isHighCritical && !EmailConfig.enableForHighCritical) return
        if (isSignature && !EmailConfig.enableForIds) return
        if (!isHighCritical && !isSignature) return

        // Cooldown check
        val now = System.currentTimeMillis()
        val cooldownMs = EmailConfig.cooldownMinutes * 60_000L
        val lastSent = cooldownTracker[alert.observable]
        if (lastSent != null && (now - lastSent) < cooldownMs) {
            NetSecureLogger.i(TAG, "Email skipped (cooldown) for ${alert.observable}")
            return
        }

        // Attempt send with 1 retry
        var success = false
        for (attempt in 1..2) {
            try {
                doSend(alert)
                success = true
                cooldownTracker[alert.observable] = System.currentTimeMillis()
                NetSecureLogger.i(TAG, "Alert email sent for ${alert.observable}")
                break
            } catch (e: MessagingException) {
                Log.e(TAG, "Email send attempt $attempt failed: ${e.message}")
                if (attempt < 2) {
                    delay(5000)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Email send error: ${e.message}")
                break
            }
        }

        if (!success) {
            NetSecureLogger.e(TAG, "Failed to send email for ${alert.observable} after retries")
        }
    }

    /**
     * Send a test email to verify SMTP configuration.
     * Returns a result message.
     */
    suspend fun sendTestEmail(): String {
        if (!EmailConfig.isConfigured()) {
            return "Email not configured — fill in all fields first"
        }

        return try {
            val session = buildSession()
            val message = MimeMessage(session).apply {
                setFrom(InternetAddress(EmailConfig.senderEmail))
                for (recipient in EmailConfig.recipients) {
                    addRecipient(Message.RecipientType.TO, InternetAddress(recipient.trim()))
                }
                subject = "[NetSecure] Test Email — Configuration Verified"
                setContent(buildTestBody(), "text/html; charset=utf-8")
                sentDate = Date()
            }
            Transport.send(message)
            NetSecureLogger.i(TAG, "Test email sent successfully")
            "Test email sent successfully!"
        } catch (e: AuthenticationFailedException) {
            "Authentication failed — check email/password (use App Password for Gmail)"
        } catch (e: MessagingException) {
            "SMTP error: ${e.message?.take(100)}"
        } catch (e: Exception) {
            "Error: ${e.javaClass.simpleName}: ${e.message?.take(100)}"
        }
    }

    private fun doSend(alert: ThreatAlert) {
        val session = buildSession()

        val message = MimeMessage(session).apply {
            setFrom(InternetAddress(EmailConfig.senderEmail))
            for (recipient in EmailConfig.recipients) {
                addRecipient(Message.RecipientType.TO, InternetAddress(recipient.trim()))
            }
            val severityLabel = alert.report.severity.displayName.uppercase()
            subject = "[NetSecure] $severityLabel Threat Alert — ${alert.observable}"
            sentDate = Date()
        }

        // Multipart: HTML body + JSON attachment
        val multipart = MimeMultipart()

        // HTML body part
        val bodyPart = MimeBodyPart()
        bodyPart.setContent(buildAlertBody(alert), "text/html; charset=utf-8")
        multipart.addBodyPart(bodyPart)

        // JSON report attachment
        val attachPart = MimeBodyPart()
        val jsonReport = gson.toJson(alert.report)
        val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val safeObservable = alert.observable.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        attachPart.dataHandler = DataHandler(
            ByteArrayDataSource(jsonReport.toByteArray(Charsets.UTF_8), "application/json")
        )
        attachPart.fileName = "threat_report_${safeObservable}_${timestamp}.json"
        multipart.addBodyPart(attachPart)

        message.setContent(multipart)

        Transport.send(message)
    }

    private fun buildSession(): Session {
        val props = Properties().apply {
            put("mail.smtp.auth", "true")
            put("mail.smtp.starttls.enable", "true")
            put("mail.smtp.host", EmailConfig.smtpHost)
            put("mail.smtp.port", EmailConfig.smtpPort.toString())
            put("mail.smtp.connectiontimeout", "15000")
            put("mail.smtp.timeout", "15000")
            put("mail.smtp.writetimeout", "15000")
        }

        return Session.getInstance(props, object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                return PasswordAuthentication(EmailConfig.senderEmail, EmailConfig.senderPassword)
            }
        })
    }

    private fun buildAlertBody(alert: ThreatAlert): String {
        val score = (alert.report.overallScore * 100).toInt()
        val severity = alert.report.severity.displayName.uppercase()
        val dateStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(Date(alert.createdAt))

        val analyzersHtml = alert.report.analyzerResults.joinToString("\n") { ar ->
            "<li><b>${ar.analyzerName}</b>: ${ar.verdict} (${(ar.score * 100).toInt()}%)" +
            if (ar.detail.isNotBlank()) " — ${ar.detail}" else "" +
            "</li>"
        }

        val categories = alert.report.categories.joinToString(", ")
        val apps = alert.associatedPackages.joinToString(", ")

        return """
        <!DOCTYPE html>
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0d1117; color: #e6edf3; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #161b22; border-radius: 12px; padding: 24px; border: 1px solid #30363d;">
                <h2 style="color: ${if (severity == "CRITICAL") "#FF1744" else "#FF9100"}; margin-top: 0;">
                    ⚠️ $severity Threat Detected
                </h2>
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
                    <tr><td style="padding: 6px 0; color: #8b949e;">Severity:</td><td style="color: #e6edf3;"><b>$severity</b> | Score: ${score}%</td></tr>
                    <tr><td style="padding: 6px 0; color: #8b949e;">Observable:</td><td style="color: #e6edf3;">${alert.observable} (${alert.report.classification})</td></tr>
                    <tr><td style="padding: 6px 0; color: #8b949e;">Associated App:</td><td style="color: #e6edf3;">$apps</td></tr>
                    <tr><td style="padding: 6px 0; color: #8b949e;">Detected:</td><td style="color: #e6edf3;">$dateStr</td></tr>
                    <tr><td style="padding: 6px 0; color: #8b949e;">Categories:</td><td style="color: #e6edf3;">$categories</td></tr>
                </table>
                <h3 style="color: #58a6ff; margin-bottom: 8px;">Analyzer Summary</h3>
                <ul style="color: #e6edf3; padding-left: 20px;">
                    $analyzersHtml
                </ul>
                <hr style="border: none; border-top: 1px solid #30363d; margin: 16px 0;">
                <p style="color: #8b949e; font-size: 12px;">
                    This alert was generated by NetSecure. A full JSON report is attached.
                </p>
            </div>
        </body>
        </html>
        """.trimIndent()
    }

    private fun buildTestBody(): String {
        return """
        <!DOCTYPE html>
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0d1117; color: #e6edf3; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #161b22; border-radius: 12px; padding: 24px; border: 1px solid #30363d;">
                <h2 style="color: #00E5FF; margin-top: 0;">✅ NetSecure Email Configuration Verified</h2>
                <p style="color: #e6edf3;">
                    This is a test email from <b>NetSecure</b>. If you received this, your SMTP configuration is working correctly.
                </p>
                <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
                    <tr><td style="padding: 6px 0; color: #8b949e;">SMTP Host:</td><td style="color: #e6edf3;">${EmailConfig.smtpHost}:${EmailConfig.smtpPort}</td></tr>
                    <tr><td style="padding: 6px 0; color: #8b949e;">Sender:</td><td style="color: #e6edf3;">${EmailConfig.senderEmail}</td></tr>
                    <tr><td style="padding: 6px 0; color: #8b949e;">Recipients:</td><td style="color: #e6edf3;">${EmailConfig.recipients.joinToString(", ")}</td></tr>
                </table>
                <p style="color: #8b949e; font-size: 12px;">
                    You will receive alerts for HIGH/CRITICAL threats and IDS signature matches based on your settings.
                </p>
            </div>
        </body>
        </html>
        """.trimIndent()
    }
}
