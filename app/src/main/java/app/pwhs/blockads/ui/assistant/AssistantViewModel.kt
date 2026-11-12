package app.pwhs.blockads.ui.assistant

import android.app.Application
import android.graphics.drawable.Drawable
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.pwhs.blockads.data.dao.DnsLogDao
import app.pwhs.blockads.data.datastore.AppPreferences
import app.pwhs.blockads.service.AdBlockVpnService
import app.pwhs.blockads.service.RootProxyService
import app.pwhs.blockads.service.ServiceController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AssistantAppItem(
    val packageName: String,
    val appName: String,
    val blockedCount: Int,
    val lastBlockedDomain: String,
    val isFilteringEnabled: Boolean,
    val icon: Drawable? = null
)

sealed interface AssistantEvent {
    data class PickerActivated(val message: String) : AssistantEvent
    data class AppToggled(val appName: String, val enabled: Boolean) : AssistantEvent
}

class AssistantViewModel(
    application: Application,
    private val dnsLogDao: DnsLogDao,
    private val appPrefs: AppPreferences
) : AndroidViewModel(application) {

    private val _recentApps = MutableStateFlow<List<AssistantAppItem>>(emptyList())
    val recentApps: StateFlow<List<AssistantAppItem>> = _recentApps.asStateFlow()

    private val _isLoading = MutableStateFlow(true)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _events = MutableSharedFlow<AssistantEvent>()
    val events: SharedFlow<AssistantEvent> = _events.asSharedFlow()

    init {
        loadRecentApps()
    }

    private fun loadRecentApps() {
        viewModelScope.launch {
            combine(
                dnsLogDao.getRecentBlocked(100),
                appPrefs.vpnSecurity.whitelistedApps
            ) { blockedLogs, whitelistedSet ->
                withContext(Dispatchers.IO) {
                    val pm = getApplication<Application>().packageManager
                    val selfPkg = getApplication<Application>().packageName
                    val grouped = blockedLogs
                        .filter { it.packageName.isNotEmpty() && it.packageName != selfPkg }
                        .groupBy { it.packageName }

                    grouped.entries.take(8).map { (pkg, logs) ->
                        val appName = logs.firstOrNull()?.appName?.takeIf { it.isNotBlank() }
                            ?: runCatching {
                                val info = pm.getApplicationInfo(pkg, 0)
                                pm.getApplicationLabel(info).toString()
                            }.getOrDefault(pkg)

                        val icon = runCatching { pm.getApplicationIcon(pkg) }.getOrNull()
                        val lastDomain = logs.firstOrNull()?.domain.orEmpty()

                        AssistantAppItem(
                            packageName = pkg,
                            appName = appName,
                            blockedCount = logs.size,
                            lastBlockedDomain = lastDomain,
                            isFilteringEnabled = pkg !in whitelistedSet,
                            icon = icon
                        )
                    }
                }
            }.collect { items ->
                _recentApps.value = items
                _isLoading.value = false
            }
        }
    }

    fun toggleAppFiltering(item: AssistantAppItem) {
        viewModelScope.launch {
            appPrefs.vpnSecurity.toggleWhitelistedApp(item.packageName)
            val newEnabled = !item.isFilteringEnabled
            _events.emit(AssistantEvent.AppToggled(item.appName, newEnabled))
            ServiceController.requestRestart(getApplication())
        }
    }

    fun activateElementPicker() {
        viewModelScope.launch {
            val adapter = AdBlockVpnService.activeTunnelAdapter ?: RootProxyService.activeTunnelAdapter
            if (adapter != null) {
                adapter.activateElementPicker(90)
                _events.emit(AssistantEvent.PickerActivated("🎯 Ad picker activated! Open your browser and tap any ad to remove it."))
            } else {
                _events.emit(AssistantEvent.PickerActivated("⚠️ Please make sure BlockAds protection is running."))
            }
        }
    }
}
