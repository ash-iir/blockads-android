package app.pwhs.blockads.service

import android.content.Context
import app.pwhs.blockads.data.datastore.AppPreferences
import kotlinx.coroutines.flow.first

/**
 * One path for the Root WireGuard switches, shared by the Home routing sheet
 * and Settings → Proxy & VPN: store the pref, then restart Root Proxy so the
 * tunnel is (re)built. Never touches HTTPS filtering — MITM stays on in Root mode.
 */
object RootWireGuardSettings {

    suspend fun setEnabled(context: Context, appPrefs: AppPreferences, enabled: Boolean) {
        appPrefs.wireguard.setRootWireGuardEnabled(enabled)
        if (RootProxyService.isRunning) RootProxyService.requestRestart(context)
    }

    suspend fun setKillSwitch(context: Context, appPrefs: AppPreferences, enabled: Boolean) {
        appPrefs.wireguard.setRootWireGuardKillSwitch(enabled)
        if (RootProxyService.isRunning && appPrefs.wireguard.rootWireGuardEnabled.first()) {
            RootProxyService.requestRestart(context)
        }
    }

    /** Active profile changed while the root tunnel is on: rebuild it with the new peer. */
    suspend fun onProfileChanged(context: Context, appPrefs: AppPreferences) {
        if (RootProxyService.isRunning && appPrefs.wireguard.rootWireGuardEnabled.first()) {
            RootProxyService.requestRestart(context)
        }
    }
}
