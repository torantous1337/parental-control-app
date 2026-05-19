package com.example.parentalcontrol

import android.app.Application
import android.util.Log

/**
 * Application entry point  —  v2
 *
 * Changes: WatchdogWorker.enqueue() removed — the watchdog is now
 * WatchdogService in the :watchdog process, started from
 * ParentalControlVpnService when the VPN comes up.
 */
class ParentalControlApp : Application() {

    companion object {
        private const val TAG = "PCApp"
    }

    override fun onCreate() {
        super.onCreate()

        AppContextHolder.init(this)
        NativeBridge.load()

        val apkPath = applicationInfo.sourceDir
        if (!NativeBridge.verifyDexIntegrity(apkPath)) {
            Log.e(TAG, "INTEGRITY CHECK FAILED — possible APK tampering")
            // Production: revoke session tokens, alert backend, lock UI.
            // Do NOT crash — graceful lockout is harder to bypass than a crash.
        } else {
            Log.i(TAG, "Integrity check passed")
        }
    }
}
