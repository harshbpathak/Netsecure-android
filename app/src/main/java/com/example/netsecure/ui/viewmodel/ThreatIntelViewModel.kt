package com.example.netsecure.ui.viewmodel

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.netsecure.data.ThreatIntelRepository
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.ThreatScoring
import com.example.netsecure.data.model.ThreatSeverity
import com.example.netsecure.network.IntelOwlConfig
import com.example.netsecure.network.model.JobListItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel for ThreatIntelligenceScreen.
 * Merges local in-memory [ThreatIntelRepository.threatReportsFlow] with
 * remote job history fetched from IntelOwl's GET /api/jobs endpoint.
 */
class ThreatIntelViewModel : ViewModel() {

    private val TAG = "ThreatIntelVM"

    // ── Unified row for the history table ──

    data class ObservableRow(
        val observable: String,
        val classification: String,    // "ip" | "domain" | "hash"
        val severity: ThreatSeverity,
        val score: Float,              // 0.0–1.0
        val intelOwlJobId: Int?,
        val analyzerSummary: String,   // human-readable one-liner
        val analyzersDetail: List<AnalyzerDetail>,
        val scannedAt: Long,
        val source: Source
    )

    data class AnalyzerDetail(
        val name: String,
        val verdict: String,
        val score: Float
    )

    enum class Source { LOCAL, REMOTE, MERGED }

    // ── Exposed state ──

    private val _rows = MutableStateFlow<List<ObservableRow>>(emptyList())
    val rows: StateFlow<List<ObservableRow>> = _rows.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _severityCounts = MutableStateFlow(SeverityCounts())
    val severityCounts: StateFlow<SeverityCounts> = _severityCounts.asStateFlow()

    private val _totalJobsOnServer = MutableStateFlow(0)
    val totalJobsOnServer: StateFlow<Int> = _totalJobsOnServer.asStateFlow()

    data class SeverityCounts(
        val clean:    Int = 0,
        val low:      Int = 0,
        val medium:   Int = 0,
        val high:     Int = 0,
        val critical: Int = 0
    ) {
        val total get() = clean + low + medium + high + critical
    }

    // current filter state (set from UI)
    var filterSeverity: ThreatSeverity? = null
        private set
    var searchQuery: String = ""
        private set

    private var allRows: List<ObservableRow> = emptyList()

    init {
        // Observe local cache continuously
        viewModelScope.launch {
            ThreatIntelRepository.threatReportsFlow.collect { reports ->
                mergeLocal(reports)
            }
        }
        // Fetch remote history once on start
        fetchRemoteJobs()
    }

    // ── Local ──

    private fun mergeLocal(reports: Map<String, ThreatReport>) {
        val localRows = reports.values.map { r ->
            ObservableRow(
                observable       = r.observable,
                classification   = r.classification,
                severity         = r.severity,
                score            = r.overallScore,
                intelOwlJobId    = r.intelOwlJobId,
                analyzerSummary  = buildSummary(r),
                analyzersDetail  = r.analyzerResults.map {
                    AnalyzerDetail(it.analyzerName, it.verdict, it.score)
                },
                scannedAt        = r.lastUpdated,
                source           = Source.LOCAL
            )
        }
        // Merge with any existing remote-only rows
        val remoteOnly = allRows.filter { it.source == Source.REMOTE }
        val merged = mergeRows(localRows, remoteOnly)
        allRows = merged
        applyFilters()
    }

    // ── Remote ──

    fun fetchRemoteJobs() {
        if (!IntelOwlConfig.isConfigured()) return
        viewModelScope.launch {
            _isLoading.value = true
            _errorMessage.value = null
            try {
                val service = IntelOwlConfig.buildService() ?: return@launch
                val resp = service.getJobs(page = 1, pageSize = 100)
                if (resp.isSuccessful) {
                    val body = resp.body()
                    _totalJobsOnServer.value = body?.count ?: 0
                    val remoteRows = (body?.results ?: emptyList()).map { it.toObservableRow() }
                    val localRows = allRows.filter { it.source == Source.LOCAL }
                    allRows = mergeRows(localRows, remoteRows)
                    applyFilters()
                } else {
                    _errorMessage.value = "Server error ${resp.code()}"
                    Log.w(TAG, "getJobs failed: ${resp.code()}")
                }
            } catch (e: Exception) {
                _errorMessage.value = "${e.javaClass.simpleName}: ${e.message?.take(80)}"
                Log.e(TAG, "fetchRemoteJobs error", e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    // ── Filters & Search ──

    fun setFilter(severity: ThreatSeverity?) {
        filterSeverity = severity
        applyFilters()
    }

    fun setSearch(query: String) {
        searchQuery = query
        applyFilters()
    }

    private fun applyFilters() {
        var filtered = allRows
        filterSeverity?.let { sev -> filtered = filtered.filter { it.severity == sev } }
        if (searchQuery.isNotBlank()) {
            val q = searchQuery.trim().lowercase()
            filtered = filtered.filter { it.observable.lowercase().contains(q) }
        }
        filtered = filtered.sortedByDescending { it.scannedAt }
        _rows.value = filtered
        recomputeCounts()
    }

    private fun recomputeCounts() {
        val src = allRows
        _severityCounts.value = SeverityCounts(
            clean    = src.count { it.severity == ThreatSeverity.CLEAN },
            low      = src.count { it.severity == ThreatSeverity.LOW },
            medium   = src.count { it.severity == ThreatSeverity.MEDIUM },
            high     = src.count { it.severity == ThreatSeverity.HIGH },
            critical = src.count { it.severity == ThreatSeverity.CRITICAL }
        )
    }

    // ── Utilities ──

    private fun mergeRows(local: List<ObservableRow>, remote: List<ObservableRow>): List<ObservableRow> {
        val map = LinkedHashMap<String, ObservableRow>()
        // Local takes priority (has analyzer details)
        local.forEach { map[it.observable.lowercase()] = it }
        // Remote fills in any gaps
        remote.forEach { r ->
            val key = r.observable.lowercase()
            if (!map.containsKey(key)) map[key] = r
        }
        return map.values.toList()
    }

    private fun buildSummary(r: ThreatReport): String {
        val top = r.analyzerResults.maxByOrNull { it.score }
        return when {
            r.categories.isNotEmpty() -> r.categories.joinToString(", ")
            top != null -> "${top.analyzerName}: ${top.verdict}"
            else -> r.severity.name.lowercase().replaceFirstChar { it.uppercase() }
        }
    }

    private fun JobListItem.toObservableRow(): ObservableRow {
        val displayStatus = status.replace("_", " ").replaceFirstChar { it.uppercase() }
        return ObservableRow(
            observable      = observableName,
            classification  = observableClassification,
            severity        = ThreatSeverity.CLEAN,   // remote-only rows have no local score
            score           = 0f,
            intelOwlJobId   = id,
            analyzerSummary = displayStatus,
            analyzersDetail = emptyList(),
            scannedAt       = System.currentTimeMillis(),
            source          = Source.REMOTE
        )
    }
}
