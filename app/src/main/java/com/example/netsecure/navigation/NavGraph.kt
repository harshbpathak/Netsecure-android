package com.example.netsecure.navigation

import androidx.compose.runtime.Composable
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.example.netsecure.ui.screens.AppDetailScreen
import com.example.netsecure.ui.screens.DashboardScreen
import com.example.netsecure.ui.screens.ReportScreen
import com.example.netsecure.ui.viewmodel.AppDetailViewModel
import com.example.netsecure.ui.viewmodel.DashboardViewModel

object Routes {
    const val DASHBOARD = "dashboard"
    const val APP_DETAIL = "app_detail/{packageName}"
    const val REPORT = "report"

    fun appDetail(packageName: String) = "app_detail/${java.net.URLEncoder.encode(packageName, "UTF-8")}"
}

@Composable
fun NetSecureNavGraph(
    navController: NavHostController,
    dashboardViewModel: DashboardViewModel,
    onPrepareVpn: () -> Unit
) {
    NavHost(
        navController = navController,
        startDestination = Routes.DASHBOARD
    ) {
        composable(Routes.DASHBOARD) {
            DashboardScreen(
                viewModel = dashboardViewModel,
                onAppClick = { pkg ->
                    navController.navigate(Routes.appDetail(pkg))
                },
                onPrepareVpn = onPrepareVpn
            )
        }

        composable(
            route = Routes.APP_DETAIL,
            arguments = listOf(navArgument("packageName") { type = NavType.StringType })
        ) { backStackEntry ->
            val packageName = java.net.URLDecoder.decode(
                backStackEntry.arguments?.getString("packageName") ?: "",
                "UTF-8"
            )
            val viewModel: AppDetailViewModel = viewModel()
            AppDetailScreen(
                packageName = packageName,
                viewModel = viewModel,
                onBack = { navController.popBackStack() }
            )
        }

        composable(Routes.REPORT) {
            ReportScreen(viewModel = dashboardViewModel)
        }
    }
}
