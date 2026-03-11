package com.example.netsecure.data

import com.example.netsecure.data.model.AnalyzerResult
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.ThreatSeverity
import com.example.netsecure.logging.NetSecureLogger
import com.example.netsecure.model.ConnectionDescriptor

/**
 * Scans unencrypted or decrypted connection payload chunks for malicious signatures.
 * This is an MVP demonstrating local Intrusion Detection System (IDS) capabilities.
 */
object SignatureScanner {

    data class ThreatSignature(
        val id: String,
        val name: String,
        val regex: Regex,
        val severity: ThreatSeverity = ThreatSeverity.CRITICAL
    )

    // MVP list of signatures matching common plaintext or URL patterns
    private val signatures = listOf(
        // Suspicious botnet User-Agents often seen in cleartext HTTP
        ThreatSignature(
            id = "SIG-001",
            name = "Suspicious User-Agent (XmrMiner)",
            regex = Regex("User-Agent:.*XmrMiner", RegexOption.IGNORE_CASE)
        ),
        // Simple heuristic for plaintext IRC botnet command
        ThreatSignature(
            id = "SIG-002",
            name = "IRC Botnet JOIN command",
            regex = Regex("JOIN #[a-zA-Z0-9]+", RegexOption.IGNORE_CASE),
            severity = ThreatSeverity.HIGH
        ),
        // Standard EICAR Antivirus Test String
        ThreatSignature(
            id = "SIG-003",
            name = "EICAR Standard Antivirus Test String",
            regex = Regex("X5O!P%@AP\\[4\\\\PZX54\\(P\\^\\)7CC\\)7\\}\\\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\\\$H\\+H\\*")
        ),
        // Common web-shell or curl/wget pipe to bash in URL or HTTP request
        ThreatSignature(
            id = "SIG-004",
            name = "Suspicious Shell Script Download",
            regex = Regex("GET .*(wget|curl).* HTTP/1\\.[01]", RegexOption.IGNORE_CASE)
        ),
        // Plaintext exposure of password in GET request query strings
        ThreatSignature(
            id = "SIG-005",
            name = "Cleartext Password Exposure",
            regex = Regex("(&|\\?)(password|pwd|pass|secret)=[^&\\s]+", RegexOption.IGNORE_CASE),
            severity = ThreatSeverity.MEDIUM
        ),
        // Simplistic SQL injection string attempt
        ThreatSignature(
            id = "SIG-006",
            name = "SQL Injection Attempt Alert",
            regex = Regex("UNION SELECT.*FROM", RegexOption.IGNORE_CASE),
            severity = ThreatSeverity.HIGH
        ),

        // ── DNS-based signatures (plaintext UDP/53 payloads) ──

        // DNS query for known cryptomining pool domains
        ThreatSignature(
            id = "SIG-DNS-001",
            name = "DNS Query to Cryptomining Pool",
            regex = Regex("(coinhive\\.com|minero\\.cc|crypto-loot\\.com|coin-hive\\.com|jsecoin\\.com|ppoi\\.org|authedmine\\.com|monerominer)", RegexOption.IGNORE_CASE),
            severity = ThreatSeverity.HIGH
        ),
        // DNS query for known malware C2 domains (test-safe examples)
        ThreatSignature(
            id = "SIG-DNS-002",
            name = "DNS Query to Known Malware C2 Domain",
            regex = Regex("(malware\\.testcategory\\.com|botnet\\.test\\.org|evil\\.corp\\.test)", RegexOption.IGNORE_CASE),
            severity = ThreatSeverity.CRITICAL
        ),
        // DNS query containing suspicious TLD patterns commonly used by DGA malware
        ThreatSignature(
            id = "SIG-DNS-003",
            name = "Suspicious DGA-like Domain Query",
            regex = Regex("[a-z0-9]{20,}\\.(top|xyz|club|buzz|tk|ml|ga|cf|gq)", RegexOption.IGNORE_CASE),
            severity = ThreatSeverity.MEDIUM
        ),
        // DNS query for Tor hidden service resolution
        ThreatSignature(
            id = "SIG-DNS-004",
            name = "DNS Query for Tor/Onion Resolution",
            regex = Regex("\\.onion", RegexOption.IGNORE_CASE),
            severity = ThreatSeverity.HIGH
        ),
        // DNS query for known phishing test domains
        ThreatSignature(
            id = "SIG-DNS-005",
            name = "DNS Query to Known Phishing Domain",
            regex = Regex("(paypal.*login.*secure|apple.*id.*verify|google.*account.*alert)\\.", RegexOption.IGNORE_CASE),
            severity = ThreatSeverity.HIGH
        )
    )

    // Tracks how many payload chunks have been scanned for a given connection
    // Map of connection incr_id -> number of scanned chunks
    private val scannedChunksTracker = mutableMapOf<Int, Int>()

    /**
     * Scans any NEW payload chunks inside the active connections.
     * This avoids rescanning the same chunk over and over as the connection stays alive.
     */
    fun scan(connections: List<ConnectionDescriptor>) {
        if (connections.isEmpty()) return

        for (conn in connections) {
            val chunks = conn.payload_chunks
            if (chunks.isNullOrEmpty()) continue

            // The index of the first unscanned chunk
            val alreadyScannedCount = scannedChunksTracker[conn.incr_id] ?: 0
            if (chunks.size <= alreadyScannedCount) continue // Nothing new

            // Scan only the new chunks
            for (i in alreadyScannedCount until chunks.size) {
                val chunk = chunks[i]
                
                // Convert chunk byte data to UTF-8 String.
                // Note: For binary payloads, regex might be inefficient, but it works for cleartext MVP
                val payloadString = String(chunk.data, Charsets.UTF_8)

                for (sig in signatures) {
                    if (sig.regex.containsMatchIn(payloadString)) {
                        NetSecureLogger.w(NetSecureLogger.TAG_THREAT, "Signature match [${sig.name}] on connection ${conn.incr_id}")
                        reportThreat(conn, sig, payloadString.take(100).replace("\n", " "))
                        break // We record one match per chunk to avoid alert flooding
                    }
                }
            }

            // Update chunk tracker marking them as scanned
            scannedChunksTracker[conn.incr_id] = chunks.size
        }
    }

    private fun reportThreat(conn: ConnectionDescriptor, sig: ThreatSignature, matchSnippet: String) {
        val observable = conn.info.ifEmpty { conn.url.ifEmpty { conn.dst_ip } }.ifEmpty { "Connection \n${conn.incr_id}" }

        val normalizedScore = when (sig.severity) {
            ThreatSeverity.CRITICAL -> 0.95f
            ThreatSeverity.HIGH -> 0.75f
            ThreatSeverity.MEDIUM -> 0.55f
            ThreatSeverity.LOW -> 0.25f
            ThreatSeverity.CLEAN -> 0.0f
        }

        val report = ThreatReport(
            observable = observable,
            classification = "payload_signature",
            overallScore = normalizedScore,
            severity = sig.severity,
            analyzerResults = listOf(
                AnalyzerResult(
                    analyzerName = "Local Signature Scanner",
                    score = normalizedScore,
                    verdict = "malicious",
                    detail = "Signature Match [${sig.id}]: ${sig.name} | Snippet: $matchSnippet"
                )
            ),
            categories = listOf("signature_match", "payload_inspection"),
            firstSeen = System.currentTimeMillis(),
            lastUpdated = System.currentTimeMillis()
        )

        // Inject this report into the IntelOwl ThreatIntelRepository so it alerts the user
        ThreatIntelRepository.injectSignatureThreat(report, conn.uid)
    }

    /**
     * Fires a synthetic test signature to verify the full pipeline works.
     * Injects a fake threat report as if a real payload matched a signature.
     */
    fun fireTestSignature() {
        NetSecureLogger.w(NetSecureLogger.TAG_THREAT, "Firing TEST signature to verify pipeline")

        val report = ThreatReport(
            observable = "test-payload-scan.netsecure.local",
            classification = "payload_signature",
            overallScore = 0.75f,
            severity = ThreatSeverity.HIGH,
            analyzerResults = listOf(
                AnalyzerResult(
                    analyzerName = "Local Signature Scanner",
                    score = 0.75f,
                    verdict = "malicious",
                    detail = "TEST: Simulated signature match [SIG-TEST] | Snippet: GET /login?password=hunter2 HTTP/1.1"
                )
            ),
            categories = listOf("signature_match", "payload_inspection", "test"),
            firstSeen = System.currentTimeMillis(),
            lastUpdated = System.currentTimeMillis()
        )

        ThreatIntelRepository.injectSignatureThreat(report, -1)
        NetSecureLogger.w(NetSecureLogger.TAG_THREAT, "TEST signature injected successfully")
    }

    /**
     * Call this when the VPN stops to free memory
     */
    fun clear() {
        scannedChunksTracker.clear()
        NetSecureLogger.i(NetSecureLogger.TAG_THREAT, "SignatureScanner trackers cleared")
    }
}
