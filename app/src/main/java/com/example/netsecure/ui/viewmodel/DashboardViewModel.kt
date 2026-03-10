package com.example.netsecure.ui.viewmodel

import android.app.Application
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import com.example.netsecure.CaptureService
import com.example.netsecure.data.ThreatIntelRepository
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.data.model.CategoryStats
import com.example.netsecure.data.model.ScanStatus
import com.example.netsecure.data.model.ThreatAlert
import com.example.netsecure.data.model.ThreatReport
import com.example.netsecure.data.model.ThreatSummary
import com.example.netsecure.data.model.TrafficCategory
import com.example.netsecure.model.CaptureStats
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    // ── Traffic ──
    val appTrafficList: StateFlow<List<AppTrafficInfo>> = TrafficRepository.appTrafficFlow
    val isCapturing: StateFlow<Boolean> = TrafficRepository.isCapturing
    val captureStats: StateFlow<CaptureStats?> = TrafficRepository.captureStats
    val globalCategoryBreakdown: StateFlow<Map<TrafficCategory, CategoryStats>> =
        TrafficRepository.globalCategoryFlow

    /** Currently selected category filter (null = show all) */
    private val _selectedCategory = MutableStateFlow<TrafficCategory?>(null)
    val selectedCategory: StateFlow<TrafficCategory?> = _selectedCategory.asStateFlow()

    // ── Threat Intelligence ──
    val threatReports: StateFlow<Map<String, ThreatReport>> = ThreatIntelRepository.threatReportsFlow
    val threatAlerts: StateFlow<List<ThreatAlert>> = ThreatIntelRepository.threatAlertsFlow
    val threatSummary: StateFlow<ThreatSummary> = ThreatIntelRepository.threatSummaryFlow
    val scanStatus: StateFlow<ScanStatus> = ThreatIntelRepository.scanStatusFlow

    fun selectCategory(category: TrafficCategory?) {
        _selectedCategory.value = if (_selectedCategory.value == category) null else category
    }

    fun prepareVpn(): android.content.Intent? = VpnService.prepare(getApplication())

    fun startCapture() { CaptureService.start(getApplication()) }

    fun stopCapture() { CaptureService.stop(getApplication()) }

    fun clearData() {
        TrafficRepository.clearAll()
        ThreatIntelRepository.clearAll()
        _selectedCategory.value = null
    }

    fun dismissThreatAlert(alert: ThreatAlert) {
        ThreatIntelRepository.dismissAlert(alert)
    }
}
