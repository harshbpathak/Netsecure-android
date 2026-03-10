package com.example.netsecure.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.netsecure.data.ThreatIntelRepository
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.TrafficCategory
import com.example.netsecure.model.ConnectionDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn

class AppDetailViewModel : ViewModel() {

    private val _targetPackageName = MutableStateFlow<String?>(null)

    /** Currently selected category filter for the detail screen (null = show all) */
    private val _selectedCategory = MutableStateFlow<TrafficCategory?>(null)
    val selectedCategory: StateFlow<TrafficCategory?> = _selectedCategory.asStateFlow()

    val appTraffic: StateFlow<AppTrafficInfo?> = combine(_targetPackageName, TrafficRepository.appTrafficFlow) { targetPkg, list ->
        list.find { it.packageName == targetPkg }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, null)

    val connections: StateFlow<List<ConnectionDescriptor>> = combine(
        appTraffic,
        TrafficRepository.connectionsFlow,
        _selectedCategory
    ) { app, conns, categoryFilter ->
        if (app != null && app.uid != -1) {
            val appConns = conns.filter { it.uid == app.uid }
            if (categoryFilter != null) {
                appConns.filter { conn ->
                    TrafficRepository.getCategoryForConnection(conn.incr_id) == categoryFilter
                }
            } else {
                appConns
            }
        } else {
            emptyList()
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    /**
     * Expose the full threat reports map so ConnectionCard composables can observe it
     * and trigger recomposition when new IntelOwl results arrive.
     * Each card does its own key-lookup from this map rather than calling
     * ThreatIntelRepository directly — this is the correct Compose recomposition pattern.
     */
    val threatMap: StateFlow<Map<String, ThreatReport>> = ThreatIntelRepository.threatReportsFlow

    /** Look up the best threat report for a connection (domain preferred over IP). */
    fun getThreatForConnection(conn: ConnectionDescriptor): ThreatReport? =
        ThreatIntelRepository.getThreatForConnection(conn)

    fun loadApp(packageName: String) {
        _targetPackageName.value = packageName
    }

    fun selectCategory(category: TrafficCategory?) {
        _selectedCategory.value = if (_selectedCategory.value == category) null else category
    }

    fun refresh(packageName: String) {
        loadApp(packageName)
    }
}
