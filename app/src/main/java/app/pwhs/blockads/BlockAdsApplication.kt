package app.pwhs.blockads

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.UserManager
import app.pwhs.blockads.data.datastore.AppPreferences
import app.pwhs.blockads.di.appModule
import app.pwhs.blockads.worker.DailySummaryScheduler
import app.pwhs.blockads.worker.FilterUpdateScheduler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import org.koin.android.ext.android.inject
import org.koin.android.ext.koin.androidContext
import org.koin.android.ext.koin.androidLogger
import org.koin.core.context.startKoin
import timber.log.Timber
import timber.log.Timber.DebugTree
import app.pwhs.blockads.utils.CrashReportingManager
import app.pwhs.blockads.utils.FileLoggingTree


class BlockAdsApplication : Application() {
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onCreate() {
        super.onCreate()
        startKoin {
            androidLogger()
            androidContext(this@BlockAdsApplication)
            modules(appModule)
        }

        if (BuildConfig.DEBUG) {
            Timber.plant(DebugTree())
        }
        
        // Plant File logging tree for all builds to allow log export
        Timber.plant(FileLoggingTree(this))

        // Schedule auto-update for filter lists after Koin is initialized
        val appPreferences: AppPreferences by inject()

        // Direct boot: BootReceiver (LOCKED_BOOT_COMPLETED) starts this process
        // before the user unlocks. WorkManager and the credential-encrypted
        // DataStore are not usable yet — touching WorkManager here crashed the
        // app on every boot ("WorkManager can't be accessed from direct boot").
        // Defer all CE-storage work until ACTION_USER_UNLOCKED.
        if (!isUserUnlocked()) {
            Timber.d("Direct boot: deferring workers/preferences until user unlock")
            registerReceiver(object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    runCatching { unregisterReceiver(this) }
                    runPostUnlockInit(appPreferences)
                }
            }, IntentFilter(Intent.ACTION_USER_UNLOCKED))
            return
        }

        runPostUnlockInit(appPreferences)
    }

    private fun isUserUnlocked(): Boolean {
        val um = getSystemService(Context.USER_SERVICE) as? UserManager ?: return true
        return um.isUserUnlocked
    }

    private fun runPostUnlockInit(appPreferences: AppPreferences) {
        val geoIpManager: app.pwhs.blockads.data.geoip.GeoIpManager by inject()
        applicationScope.launch {
            // Restore Crash Reporting state dynamically
            val isCrashReportingEnabled = appPreferences.crashReportingEnabled.first()
            CrashReportingManager.toggleSentry(this@BlockAdsApplication, isCrashReportingEnabled)

            // Move v6.3.0 single-config users onto the multi-profile schema.
            appPreferences.migrateLegacyWgConfigIfNeeded()

            FilterUpdateScheduler.scheduleFilterUpdate(this@BlockAdsApplication, appPreferences)
            app.pwhs.blockads.worker.ConfigUpdateScheduler.scheduleConfigUpdate(this@BlockAdsApplication, appPreferences)
            app.pwhs.blockads.ui.browser.rules.BrowserRuleUpdateWorker.schedule(this@BlockAdsApplication)
            app.pwhs.blockads.worker.GeoIpUpdateWorker.schedule(this@BlockAdsApplication)
            app.pwhs.blockads.worker.LogCleanupWorker.syncSchedule(
                this@BlockAdsApplication,
                appPreferences.logRetentionDays.first()
            )

            // Schedule daily summary only if enabled
            if (appPreferences.dailySummaryEnabled.first()) {
                DailySummaryScheduler.scheduleDailySummary(this@BlockAdsApplication)
            }

            // Warm up GeoIP database on IO thread
            app.pwhs.blockads.data.geoip.GeoIpLookup.init(this@BlockAdsApplication)

            // Fetch GeoIP database dynamically on fresh install if not present
            if (!geoIpManager.isDatabaseAvailable()) {
                geoIpManager.checkAndUpdate(force = false)
            }
        }

        // Trusted Wi-Fi networks (#197): auto-pause/resume on SSID change.
        app.pwhs.blockads.service.TrustedNetworkManager(this, appPreferences).start()
    }
}
