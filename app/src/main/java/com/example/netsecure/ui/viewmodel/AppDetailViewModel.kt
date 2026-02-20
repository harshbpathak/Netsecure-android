package com.example.netsecure.ui.viewmodel

import androidx.lifecycle.ViewModel
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.data.model.AppTrafficInfo
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class AppDetailViewModel : ViewModel() {

    private val _appTraffic = MutableStateFlow<AppTrafficInfo?>(null)
    val appTraffic: StateFlow<AppTrafficInfo?> = _appTraffic.asStateFlow()

    fun loadApp(packageName: String) {
        _appTraffic.value = TrafficRepository.getTrafficForApp(packageName)
    }

    fun refresh(packageName: String) {
        loadApp(packageName)
    }
}
