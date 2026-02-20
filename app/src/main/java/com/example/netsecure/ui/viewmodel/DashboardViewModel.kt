package com.example.netsecure.ui.viewmodel

import android.app.Application
import android.content.Context
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import com.example.netsecure.data.TrafficRepository
import com.example.netsecure.data.model.AppTrafficInfo
import com.example.netsecure.service.LocalVpnService
import kotlinx.coroutines.flow.StateFlow

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    val appTrafficList: StateFlow<List<AppTrafficInfo>> = TrafficRepository.appTrafficFlow
    val isCapturing: StateFlow<Boolean> = TrafficRepository.isCapturing

    /**
     * Returns the VPN prepare intent if user hasn't granted permission yet, null if ready.
     */
    fun prepareVpn(): android.content.Intent? {
        return VpnService.prepare(getApplication())
    }

    fun startCapture() {
        LocalVpnService.start(getApplication())
    }

    fun stopCapture() {
        LocalVpnService.stop(getApplication())
    }

    fun clearData() {
        TrafficRepository.clearAll()
    }
}
