package com.example.parentalcontrol

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * BootReceiver  —  v2
 *
 * Changes: no WorkManager enqueue — the watchdog is started by the
 * VPN service itself via Binder IPC once the VPN is running.
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> {
                Log.i(TAG, "BOOT_COMPLETED")
                val vpnIntent = VpnService.prepare(context)
                if (vpnIntent == null) {
                    context.startForegroundService(
                        Intent(context, ParentalControlVpnService::class.java).apply {
                            action = ParentalControlVpnService.ACTION_START
                        }
                    )
                    Log.i(TAG, "VPN service started after boot")
                } else {
                    Log.w(TAG, "VPN permission not pre-granted — user must open app")
                }
            }
            "android.intent.action.LOCKED_BOOT_COMPLETED" ->
                Log.i(TAG, "LOCKED_BOOT_COMPLETED — deferring until CE storage available")
        }
    }
}
