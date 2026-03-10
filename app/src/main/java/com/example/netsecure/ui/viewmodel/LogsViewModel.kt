package com.example.netsecure.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.netsecure.logging.NetSecureLogger
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class LogsViewModel : ViewModel() {

    private val _entries = MutableStateFlow<List<NetSecureLogger.LogEntry>>(emptyList())
    val entries: StateFlow<List<NetSecureLogger.LogEntry>> = _entries.asStateFlow()

    private val _filterLevel = MutableStateFlow<Char?>(null)   // null = All
    val filterLevel: StateFlow<Char?> = _filterLevel.asStateFlow()

    private val _filterTag = MutableStateFlow<String?>(null)   // null = All tabs
    val filterTag: StateFlow<String?> = _filterTag.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _isLiveMode = MutableStateFlow(true)
    val isLiveMode: StateFlow<Boolean> = _isLiveMode.asStateFlow()

    init {
        startPolling()
    }

    private fun startPolling() {
        viewModelScope.launch {
            while (true) {
                if (_isLiveMode.value) refresh()
                delay(1500)
            }
        }
    }

    fun refresh() {
        val all = NetSecureLogger.getLogs()
        val filtered = applyFilters(all)
        _entries.value = filtered
    }

    fun setFilterLevel(level: Char?) {
        _filterLevel.value = level
        refresh()
    }

    fun setFilterTag(tag: String?) {
        _filterTag.value = tag
        refresh()
    }

    fun setSearch(q: String) {
        _searchQuery.value = q
        refresh()
    }

    fun toggleLiveMode() {
        _isLiveMode.value = !_isLiveMode.value
    }

    fun clearLogs() {
        NetSecureLogger.clearMemory()
        NetSecureLogger.clearLogFile()
        _entries.value = emptyList()
    }

    fun getAllLogsText(): String = NetSecureLogger.getAllLogsText()

    private fun applyFilters(all: List<NetSecureLogger.LogEntry>): List<NetSecureLogger.LogEntry> {
        var result = all
        _filterTag.value?.let { tag -> result = result.filter { it.tag.contains(tag, ignoreCase = true) } }
        _filterLevel.value?.let { lvl ->
            val minOrdinal = levelOrdinal(lvl)
            result = result.filter { levelOrdinal(it.level) >= minOrdinal }
        }
        val q = _searchQuery.value.trim()
        if (q.isNotBlank()) {
            result = result.filter {
                it.message.contains(q, ignoreCase = true) || it.tag.contains(q, ignoreCase = true)
            }
        }
        return result
    }

    private fun levelOrdinal(c: Char) = when (c) {
        NetSecureLogger.VERBOSE -> 0
        NetSecureLogger.DEBUG   -> 1
        NetSecureLogger.INFO    -> 2
        NetSecureLogger.WARN    -> 3
        NetSecureLogger.ERROR   -> 4
        else -> 0
    }
}
