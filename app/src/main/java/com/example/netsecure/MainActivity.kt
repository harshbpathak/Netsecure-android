package com.example.netsecure

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.netsecure.navigation.NetSecureNavGraph
import com.example.netsecure.navigation.Routes
import com.example.netsecure.ui.theme.*
import com.example.netsecure.ui.viewmodel.DashboardViewModel

class MainActivity : ComponentActivity() {

    private val dashboardViewModel: DashboardViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            dashboardViewModel.startCapture()
        } else {
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        // Even if not granted, VPN still works — just no notification on 13+
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this, Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        setContent {
            NetSecureTheme {
                MainApp(
                    dashboardViewModel = dashboardViewModel,
                    onPrepareVpn = ::prepareAndStartVpn
                )
            }
        }
    }

    private fun prepareAndStartVpn() {
        val prepareIntent: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            VpnService.prepare(this)
        } else {
            TODO("VERSION.SDK_INT < ICE_CREAM_SANDWICH")
        }
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            // Already have permission
            dashboardViewModel.startCapture()
        }
    }
}

@Composable
fun MainApp(
    dashboardViewModel: DashboardViewModel,
    onPrepareVpn: () -> Unit
) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    // Only show bottom bar on top-level destinations
    val showBottomBar = currentRoute in listOf(Routes.DASHBOARD, Routes.REPORT)

    Scaffold(
        containerColor = DarkNavy,
        bottomBar = {
            if (showBottomBar) {
                NavigationBar(
                    containerColor = DarkSurface,
                    contentColor = CyberCyan
                ) {
                    NavigationBarItem(
                        selected = currentRoute == Routes.DASHBOARD,
                        onClick = {
                            if (currentRoute != Routes.DASHBOARD) {
                                navController.navigate(Routes.DASHBOARD) {
                                    popUpTo(Routes.DASHBOARD) { inclusive = true }
                                }
                            }
                        },
                        icon = {
                            Icon(
                                Icons.Default.Dashboard,
                                contentDescription = "Dashboard"
                            )
                        },
                        label = {
                            Text(
                                "Dashboard",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = CyberCyan,
                            selectedTextColor = CyberCyan,
                            unselectedIconColor = TextDimmed,
                            unselectedTextColor = TextDimmed,
                            indicatorColor = CyberCyan.copy(alpha = 0.12f)
                        )
                    )
                    NavigationBarItem(
                        selected = currentRoute == Routes.REPORT,
                        onClick = {
                            if (currentRoute != Routes.REPORT) {
                                navController.navigate(Routes.REPORT) {
                                    popUpTo(Routes.DASHBOARD)
                                }
                            }
                        },
                        icon = {
                            Icon(
                                Icons.Default.Assessment,
                                contentDescription = "Report"
                            )
                        },
                        label = {
                            Text(
                                "Report",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = CyberCyan,
                            selectedTextColor = CyberCyan,
                            unselectedIconColor = TextDimmed,
                            unselectedTextColor = TextDimmed,
                            indicatorColor = CyberCyan.copy(alpha = 0.12f)
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding)) {
            NetSecureNavGraph(
                navController = navController,
                dashboardViewModel = dashboardViewModel,
                onPrepareVpn = onPrepareVpn
            )
        }
    }
}
