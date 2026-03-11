package com.example.netsecure.data

import android.util.Log
import com.example.netsecure.data.model.AnalyzerResult
import com.example.netsecure.data.model.ScanStatus
import com.example.netsecure.data.model.ThreatAlert
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.ThreatScoring
import com.example.netsecure.data.model.ThreatSeverity
import com.example.netsecure.data.model.ThreatSummary
import com.example.netsecure.model.ConnectionDescriptor
import com.example.netsecure.logging.NetSecureLogger
import com.example.netsecure.network.IntelOwlConfig
import com.example.netsecure.network.model.AvailabilityRequest
import com.example.netsecure.network.model.MultiObservableRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * Central orchestration layer for IntelOwl threat intelligence.
 *
 * Responsibilities:
 * - Extract unique observables (IPs/domains) from [ConnectionDescriptor] updates
 * - Enqueue them in [ScanQueue] with appropriate priority
 * - Batch-submit to IntelOwl every 5 seconds (respecting rate limits)
 * - Poll pending jobs every 10 seconds for results
 * - Score analyzer reports and publish to UI via [StateFlow]s
 *
 * Follows the same singleton `object` pattern used by [TrafficRepository].
 */
object ThreatIntelRepository {

    private const val TAG = "ThreatIntelRepo"
    private const val BATCH_INTERVAL_MS = 5_000L
    private const val POLL_INTERVAL_MS = 10_000L
    private const val MAX_BATCH_SIZE = 10
    private const val JOB_TIMEOUT_MS = 5 * 60 * 1000L  // 5 minutes

    // ── Public StateFlows ──

    private val _threatReportsFlow = MutableStateFlow<Map<String, ThreatReport>>(emptyMap())
    val threatReportsFlow: StateFlow<Map<String, ThreatReport>> = _threatReportsFlow.asStateFlow()

    private val _threatAlertsFlow = MutableStateFlow<List<ThreatAlert>>(emptyList())
    val threatAlertsFlow: StateFlow<List<ThreatAlert>> = _threatAlertsFlow.asStateFlow()

    private val _scanStatusFlow = MutableStateFlow(ScanStatus.IDLE)
    val scanStatusFlow: StateFlow<ScanStatus> = _scanStatusFlow.asStateFlow()

    private val _threatSummaryFlow = MutableStateFlow(ThreatSummary())
    val threatSummaryFlow: StateFlow<ThreatSummary> = _threatSummaryFlow.asStateFlow()

    // ── Internal State ──

    /** job_id → (observable, submittedAt) */
    private val pendingJobs = ConcurrentHashMap<Int, PendingJob>()

    private data class PendingJob(
        val observable: String,
        val classification: String,
        val submittedAt: Long = System.currentTimeMillis(),
        val associatedPackages: Set<String> = emptySet()
    )

    private val reportsMutable = ConcurrentHashMap<String, ThreatReport>()
    private val dismissedAlertIds = mutableSetOf<String>()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var dispatcherJob: Job? = null
    private var pollerJob: Job? = null

    // Exponential backoff state
    private val backoffMutex = Mutex()
    private var backoffDelayMs = 5_000L
    private val MAX_BACKOFF_MS = 60_000L

    // ── Lifecycle ──

    /** Start the scan dispatcher and job poller. Call from CaptureService.startCapture(). */
    fun start() {
        if (!IntelOwlConfig.isConfigured()) {
            _scanStatusFlow.value = ScanStatus.UNAVAILABLE
            Log.i(TAG, "IntelOwl not configured — threat scanning disabled")
            return
        }
        if (dispatcherJob?.isActive == true) return  // already running

        _scanStatusFlow.value = ScanStatus.IDLE
        Log.i(TAG, "ThreatIntelRepository started")

        // Seed UI with any valid cached entries from previous session
        val cached = ThreatCache.getAllValid()
        if (cached.isNotEmpty()) {
            reportsMutable.putAll(cached)
            _threatReportsFlow.value = reportsMutable.toMap()
            recomputeSummary()
        }

        dispatcherJob = scope.launch { runBatchDispatcher() }
        pollerJob = scope.launch { runJobPoller() }
    }

    /** Stop all coroutines and clean up. Call from CaptureService.stopCapture(). */
    fun stop() {
        dispatcherJob?.cancel()
        pollerJob?.cancel()
        dispatcherJob = null
        pollerJob = null
        _scanStatusFlow.value = ScanStatus.IDLE
        SignatureScanner.clear()
        Log.i(TAG, "ThreatIntelRepository stopped")
        NetSecureLogger.i(NetSecureLogger.TAG_THREAT, "ThreatIntelRepository stopped")
    }

    // ── Observable Extraction (called by TrafficRepository) ──

    /**
     * Called every time connections are refreshed. Extracts unique IPs/domains
     * from [connections] and enqueues them in [ScanQueue] with appropriate priority.
     *
     * This is the connection-level deduplication step — runs on whatever thread
     * calls TrafficRepository.refreshConnections(), which is the JNI callback thread.
     */
    fun onConnectionsUpdated(connections: List<ConnectionDescriptor>) {
        // First run the purely local lightweight signature scanner to check payloads
        SignatureScanner.scan(connections)

        if (!IntelOwlConfig.isConfigured()) return

        for (conn in connections) {
            val packageName = "uid:${conn.uid}"  // Will be resolved properly by UI layer

            // ── Extract IP observable ──
            val ip = conn.dst_ip
            if (ip.isNotBlank() && !ThreatCache.hasValidEntry(ip) && !ScanQueue.isQueued(ip)) {
                val priority = ScanQueue.computePriority(
                    observable = ip,
                    classification = "ip",
                    isBlacklistedIp = conn.is_blacklisted_ip,
                    isBlacklistedDomain = conn.is_blacklisted_domain,
                    l7proto = conn.l7proto,
                    dstPort = conn.dst_port
                )
                if (priority > 0) {
                    ScanQueue.enqueue(
                        ScanQueue.ScanRequest(
                            observable = ip,
                            classification = "ip",
                            priority = priority,
                            connectionIncrIds = mutableListOf(conn.incr_id),
                            associatedPackages = mutableSetOf(packageName)
                        )
                    )
                }
            }

            // ── Extract domain/SNI observable ──
            val domain = conn.info.trim()
            if (domain.isNotBlank() && domain != ip &&
                !ThreatCache.hasValidEntry(domain) && !ScanQueue.isQueued(domain)) {
                val priority = ScanQueue.computePriority(
                    observable = domain,
                    classification = "domain",
                    isBlacklistedIp = conn.is_blacklisted_ip,
                    isBlacklistedDomain = conn.is_blacklisted_domain,
                    l7proto = conn.l7proto,
                    dstPort = conn.dst_port
                )
                if (priority > 0) {
                    ScanQueue.enqueue(
                        ScanQueue.ScanRequest(
                            observable = domain,
                            classification = "domain",
                            priority = priority,
                            connectionIncrIds = mutableListOf(conn.incr_id),
                            associatedPackages = mutableSetOf(packageName)
                        )
                    )
                }
            }
        }
    }

    // ── Batch Dispatcher Coroutine ──

    private suspend fun runBatchDispatcher() {
        Log.d(TAG, "Batch dispatcher started")
        while (currentCoroutineContext().isActive) {
            try {
                val service = IntelOwlConfig.buildService()
                if (service == null) {
                    _scanStatusFlow.value = ScanStatus.UNAVAILABLE
                    delay(BATCH_INTERVAL_MS)
                    continue
                }

                if (pendingJobs.size >= IntelOwlConfig.maxConcurrentJobs) {
                    delay(BATCH_INTERVAL_MS)
                    continue
                }

                val batch = ScanQueue.drainBatch(MAX_BATCH_SIZE)
                if (batch.isEmpty()) {
                    _scanStatusFlow.value = ScanStatus.IDLE
                    delay(BATCH_INTERVAL_MS)
                    continue
                }

                _scanStatusFlow.value = ScanStatus.SCANNING

                // Check availability before submitting (avoid redundant IntelOwl calls)
                val toSubmit = mutableListOf<ScanQueue.ScanRequest>()
                for (request in batch) {
                    try {
                        val md5 = md5Hex(request.observable.lowercase())
                        val availResp = service.askAnalysisAvailability(
                            AvailabilityRequest(md5 = md5, analyzers = IntelOwlConfig.selectedAnalyzers)
                        )
                        val existingJobId = availResp.body()?.jobIds?.firstOrNull()
                            ?: availResp.body()?.jobId
                        if (availResp.isSuccessful && existingJobId != null) {
                            // Reuse existing result
                            Log.d(TAG, "Reusing existing job $existingJobId for ${request.observable}")
                            pendingJobs[existingJobId] = PendingJob(
                                request.observable, request.classification,
                                associatedPackages = request.associatedPackages.toSet()
                            )
                        } else {
                            toSubmit.add(request)
                        }
                    } catch (_: Exception) {
                        toSubmit.add(request)
                    }
                }

                // Group by classification and submit as batches
                val grouped = toSubmit.groupBy { it.classification }
                for ((classification, requests) in grouped) {
                    submitBatch(service, classification, requests)
                }

                // Reset backoff on success
                backoffMutex.withLock { backoffDelayMs = 5_000L }

            } catch (e: Exception) {
                Log.e(TAG, "Dispatcher error: ${e.message}")
                _scanStatusFlow.value = ScanStatus.ERROR
                val delay = backoffMutex.withLock {
                    val d = backoffDelayMs
                    backoffDelayMs = (backoffDelayMs * 2).coerceAtMost(MAX_BACKOFF_MS)
                    d
                }
                delay(delay)
                continue
            }

            delay(BATCH_INTERVAL_MS)
        }
    }

    private suspend fun submitBatch(
        service: com.example.netsecure.network.IntelOwlApiService,
        classification: String,
        requests: List<ScanQueue.ScanRequest>
    ) {
        try {
            // Build IntelOwl "observables" list format: [[classification, name], ...]
            val observablesList = requests.map { listOf(classification, it.observable) }
            val reqBody = MultiObservableRequest(
                observables = observablesList,
                analyzersRequested = IntelOwlConfig.selectedAnalyzers,
                tlp = IntelOwlConfig.tlp
            )
            val resp = service.analyzeMultipleObservables(reqBody)
            if (resp.isSuccessful) {
                val results = resp.body()?.results ?: emptyList()
                results.forEachIndexed { idx, result ->
                    val jobId = result.jobId
                    val observable = requests.getOrNull(idx)?.observable ?: return@forEachIndexed
                    val packages = requests.getOrNull(idx)?.associatedPackages ?: emptySet()
                    if (jobId != null) {
                        pendingJobs[jobId] = PendingJob(observable, classification,
                            associatedPackages = packages.toSet())
                        Log.d(TAG, "Submitted job $jobId for $observable ($classification)")
                    }
                }
            } else if (resp.code() == 429) {
                // Rate limited — push requests back to queue with short delay
                requests.forEach { ScanQueue.enqueue(it) }
                backoffMutex.withLock {
                    backoffDelayMs = (backoffDelayMs * 2).coerceAtMost(MAX_BACKOFF_MS)
                }
                Log.w(TAG, "Rate limited (429) — backing off for ${backoffDelayMs}ms")
                delay(backoffDelayMs)
            } else {
                Log.w(TAG, "Batch submit failed: HTTP ${resp.code()}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "submitBatch error: ${e.message}")
        }
    }

    // ── Job Poller Coroutine ──

    private suspend fun runJobPoller() {
        Log.d(TAG, "Job poller started")
        while (currentCoroutineContext().isActive) {
            delay(POLL_INTERVAL_MS)
            if (pendingJobs.isEmpty()) continue

            val service = IntelOwlConfig.buildService() ?: continue
            val now = System.currentTimeMillis()
            val toRemove = mutableListOf<Int>()

            for ((jobId, pendingJob) in pendingJobs) {
                // Timeout check
                if (now - pendingJob.submittedAt > JOB_TIMEOUT_MS) {
                    Log.w(TAG, "Job $jobId timed out after 5 min — marking as unknown")
                    storeUnknownResult(pendingJob)
                    toRemove.add(jobId)
                    continue
                }

                try {
                    val resp = service.getJob(jobId)
                    if (resp.isSuccessful) {
                        val jobResult = resp.body() ?: continue
                        if (jobResult.isTerminal()) {
                            Log.d(TAG, "Job $jobId complete: ${jobResult.status} for ${pendingJob.observable}")
                            processJobResult(jobResult, pendingJob)
                            toRemove.add(jobId)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Poll error for job $jobId: ${e.message}")
                }
            }

            toRemove.forEach { pendingJobs.remove(it) }
        }
    }

    // ── Result Processing + Scoring ──

    private fun processJobResult(
        jobResult: com.example.netsecure.network.model.JobResult,
        pendingJob: PendingJob
    ) {
        val analyzerReports = jobResult.analyzerReports ?: emptyList()
        val scores = mutableMapOf<String, Float>()
        val analyzerResults = mutableListOf<AnalyzerResult>()
        val categories = mutableSetOf<String>()

        for (report in analyzerReports) {
            // Case-insensitive: IntelOwl v6 returns "SUCCESS" (uppercase), not "success"
            if (!report.status.equals("success", ignoreCase = true) || report.report == null) continue
            Log.d(TAG, "Scoring ${report.name} (status=${report.status}): ${report.report}")

            when {
                report.name.contains("AbuseIPDB", ignoreCase = true) -> {
                    // IntelOwl AbuseIPDB report nests fields under "data":
                    // {"data": {"abuseConfidenceScore": 92, "countryCode": "DE", "isp": "...", ...}}
                    val dataObj = try {
                        report.report.asJsonObject?.get("data")?.asJsonObject
                    } catch (_: Exception) { null }
                    val confidence = try { dataObj?.get("abuseConfidenceScore")?.asInt } catch (_: Exception) { null }
                    val country    = try { dataObj?.get("countryCode")?.asString } catch (_: Exception) { null }
                    val isp        = try { dataObj?.get("isp")?.asString } catch (_: Exception) { null }
                    val score = ThreatScoring.scoreAbuseIPDB(confidence)
                    scores[report.name] = score
                    if (score > 0.3f) categories.add("abuse")
                    Log.d(TAG, "AbuseIPDB: confidence=$confidence score=$score")
                    analyzerResults.add(AnalyzerResult(
                        analyzerName = "AbuseIPDB",
                        score = score,
                        verdict = if (confidence != null && confidence > 0) "Abusive (${confidence}% confidence)" else "Clean",
                        detail = "Country: ${country ?: "N/A"}, ISP: ${isp ?: "N/A"}"
                    ))
                }

                report.name.contains("MalwareBazaar", ignoreCase = true) -> {
                    // IntelOwl MalwareBazaar uses query_status == "data_found" (not a boolean "found")
                    val queryStatus = try { report.report.asJsonObject?.get("query_status")?.asString } catch (_: Exception) { null }
                    val found = queryStatus == "data_found"
                    val fileType = try { report.report.asJsonObject?.get("data")?.asJsonArray
                        ?.firstOrNull()?.asJsonObject?.get("file_type")?.asString } catch (_: Exception) { null }
                    val score = ThreatScoring.scoreMalwareBazaar(found)
                    scores[report.name] = score
                    if (found) categories.add("malware")
                    Log.d(TAG, "MalwareBazaar: queryStatus=$queryStatus found=$found score=$score")
                    analyzerResults.add(AnalyzerResult(
                        analyzerName = "MalwareBazaar",
                        score = score,
                        verdict = if (found) "Known malware" else "Not found",
                        detail = if (fileType != null) "File type: $fileType" else ""
                    ))
                }

                report.name.contains("OTX", ignoreCase = true) -> {
                    // IntelOwl OTX report: pulse count at report.pulse_info.count
                    val pulseCount = try {
                        report.report.asJsonObject?.get("pulse_info")
                            ?.asJsonObject?.get("count")?.asInt
                            ?: report.report.asJsonObject?.get("pulse_count")?.asInt  // fallback
                            ?: 0
                    } catch (_: Exception) { 0 }
                    val score = ThreatScoring.scoreOTX(pulseCount)
                    scores[report.name] = score
                    if (score > 0.3f) categories.add("threat")
                    Log.d(TAG, "OTX: pulseCount=$pulseCount score=$score")
                    analyzerResults.add(AnalyzerResult(
                        analyzerName = "OTXQuery",
                        score = score,
                        verdict = if (pulseCount > 0) "$pulseCount OTX pulses" else "No pulses",
                        detail = "Pulse count: $pulseCount"
                    ))
                }

                report.name.contains("GreyNoise", ignoreCase = true) -> {
                    // GreyNoise Community: classification directly at top level ✓
                    val classification = try { report.report.asJsonObject?.get("classification")?.asString } catch (_: Exception) { null }
                    val name = try { report.report.asJsonObject?.get("name")?.asString } catch (_: Exception) { null }
                    val score = ThreatScoring.scoreGreyNoise(classification)
                    scores[report.name] = score
                    if (classification == "malicious") categories.add("scanner")
                    Log.d(TAG, "GreyNoise: classification=$classification score=$score")
                    analyzerResults.add(AnalyzerResult(
                        analyzerName = "GreyNoiseCommunity",
                        score = score,
                        verdict = classification?.replaceFirstChar { it.uppercase() } ?: "Unknown",
                        detail = "Name: ${name ?: "N/A"}"
                    ))
                }

                else -> {
                    analyzerResults.add(AnalyzerResult(
                        analyzerName = report.name,
                        score = 0f,
                        verdict = "Completed",
                        detail = ""
                    ))
                }
            }
        }

        // ── IntelOwl v6 data_model fallback ──
        // IntelOwl attaches its own verdict ("malicious"/"benign"/"unknown") and tags to the job.
        // Use this as a floor score so that even if our per-analyzer extraction fails,
        // the correct severity is surfaced.
        val dataModelEvaluation = jobResult.dataModel?.evaluation
        val dataModelTags       = jobResult.dataModel?.tags ?: emptyList()

        Log.d(TAG, "data_model evaluation=$dataModelEvaluation tags=$dataModelTags scores=$scores")

        // Merge IntelOwl's own threat tags into categories
        if (dataModelTags.isNotEmpty()) {
            categories.addAll(dataModelTags.take(5).map { it.lowercase() })
        }

        // Apply floor scores from IntelOwl's verdict when our scoring is low
        var overallScore = ThreatScoring.aggregate(scores)
        if (overallScore < 0.3f && dataModelEvaluation?.equals("malicious", ignoreCase = true) == true) {
            overallScore = 0.75f   // HIGH — IntelOwl explicitly says malicious
            Log.d(TAG, "Score floored to HIGH (0.75) from data_model evaluation=malicious")
        }
        if (overallScore < 0.1f && dataModelEvaluation?.equals("suspicious", ignoreCase = true) == true) {
            overallScore = 0.35f   // MEDIUM
        }

        val severity = ThreatSeverity.fromScore(overallScore)
        NetSecureLogger.i(NetSecureLogger.TAG_THREAT, "Verdict for ${pendingJob.observable}: $severity (score=$overallScore)")
        Log.i(TAG, "Final verdict for ${pendingJob.observable}: $severity (score=$overallScore)")


        val report = ThreatReport(
            observable = pendingJob.observable,
            classification = pendingJob.classification,
            overallScore = overallScore,
            severity = severity,
            analyzerResults = analyzerResults,
            categories = categories.toList(),
            firstSeen = System.currentTimeMillis(),
            lastUpdated = System.currentTimeMillis(),
            intelOwlJobId = jobResult.id
        )

        storeReport(report, pendingJob.associatedPackages)
    }

    private fun storeUnknownResult(pendingJob: PendingJob) {
        val report = ThreatReport(
            observable = pendingJob.observable,
            classification = pendingJob.classification,
            overallScore = 0f,
            severity = ThreatSeverity.CLEAN,
            analyzerResults = emptyList(),
            categories = emptyList(),
            firstSeen = System.currentTimeMillis(),
            lastUpdated = System.currentTimeMillis()
        )
        storeReport(report, pendingJob.associatedPackages)
    }

    private fun storeReport(report: ThreatReport, associatedPackages: Set<String>) {
        ThreatCache.put(report)
        reportsMutable[report.observable.lowercase()] = report
        _threatReportsFlow.value = reportsMutable.toMap()

        // Emit alert for HIGH and CRITICAL findings
        if (report.severity.ordinalScore >= ThreatSeverity.HIGH.ordinalScore) {
            val alert = ThreatAlert(
                observable = report.observable,
                associatedPackages = associatedPackages.toList(),
                report = report
            )
            val existing = _threatAlertsFlow.value.toMutableList()
            if (existing.none { it.alertId == alert.alertId }) {
                existing.add(0, alert) // prepend (newest first)
                _threatAlertsFlow.value = existing
            }
        }

        recomputeSummary()
    }

    private fun recomputeSummary() {
        val reports = reportsMutable.values
        val summary = ThreatSummary(
            total = reports.size,
            clean = reports.count { it.severity == ThreatSeverity.CLEAN },
            low = reports.count { it.severity == ThreatSeverity.LOW },
            medium = reports.count { it.severity == ThreatSeverity.MEDIUM },
            high = reports.count { it.severity == ThreatSeverity.HIGH },
            critical = reports.count { it.severity == ThreatSeverity.CRITICAL },
            pending = pendingJobs.size
        )
        _threatSummaryFlow.value = summary
    }

    // ── Public API ──

    /**
     * Get the best available threat report for a connection.
     * Prefers domain over IP if both are available (domain is more specific).
     */
    fun getThreatForConnection(conn: ConnectionDescriptor): ThreatReport? {
        val byDomain = if (conn.info.isNotBlank()) {
            reportsMutable[conn.info.lowercase()]
        } else null
        val byIp = reportsMutable[conn.dst_ip.lowercase()]
        return listOfNotNull(byDomain, byIp).maxByOrNull { it.overallScore }
    }

    fun getThreatForObservable(observable: String): ThreatReport? =
        reportsMutable[observable.lowercase()]

    fun dismissAlert(alert: ThreatAlert) {
        dismissedAlertIds.add(alert.alertId)
        _threatAlertsFlow.value = _threatAlertsFlow.value
            .filterNot { it.alertId == alert.alertId }
    }

    fun clearAll() {
        reportsMutable.clear()
        pendingJobs.clear()
        _threatReportsFlow.value = emptyMap()
        _threatAlertsFlow.value = emptyList()
        _threatSummaryFlow.value = ThreatSummary()
        ScanQueue.clear()
        ThreatCache.clear()
    }

    /**
     * Called by SignatureScanner when a local payload regex matches.
     * Injects the threat directly into the active flow and triggers alerts.
     */
    fun injectSignatureThreat(report: ThreatReport, uid: Int) {
        val packageName = TrafficRepository.getTrafficForApp("uid:$uid")?.packageName ?: "uid:$uid"
        val existing = reportsMutable[report.observable]
        
        // Merge if new or more severe
        if (existing == null || report.severity.ordinalScore > existing.severity.ordinalScore) {
            NetSecureLogger.w(NetSecureLogger.TAG_THREAT, "Injecting Signature Threat for ${report.observable} (Severity: ${report.severity.name})")
            storeReport(report, setOf(packageName))
        }
    }

    // ── Utilities ──

    private fun md5Hex(input: String): String {
        val bytes = MessageDigest.getInstance("MD5").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
