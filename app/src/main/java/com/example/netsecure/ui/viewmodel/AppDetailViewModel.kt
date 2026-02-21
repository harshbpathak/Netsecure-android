package com.example.netsecure.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.model.ConnectionDescriptor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn

class AppDetailViewModel : ViewModel() {

    private val _targetPackageName = MutableStateFlow<String?>(null)

    val appTraffic: StateFlow<AppTrafficInfo?> = combine(_targetPackageName, TrafficRepository.appTrafficFlow) { targetPkg, list ->
        list.find { it.packageName == targetPkg }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, null)

    val connections: StateFlow<List<ConnectionDescriptor>> = combine(appTraffic, TrafficRepository.connectionsFlow) { app, conns ->
        if (app != null && app.uid != -1) {
            conns.filter { it.uid == app.uid }
        } else {
            emptyList()
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    fun loadApp(packageName: String) {
        _targetPackageName.value = packageName
    }

    fun refresh(packageName: String) {
        loadApp(packageName)
    }
}
