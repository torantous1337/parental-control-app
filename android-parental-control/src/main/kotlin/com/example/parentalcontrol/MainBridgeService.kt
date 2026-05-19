package com.example.parentalcontrol

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.util.Log

/**
 * MainBridgeService
 *
 * Runs in the main process.  Exposes an IMainBridge.Stub to the :watchdog
 * process so that WatchdogService can reverse-bind and register a
 * DeathRecipient on the main process's Binder token.
 *
 * When the :watchdog process's Binder dies (e.g. OOM killed), the
 * DeathRecipient registered here fires and the main process restarts the
 * WatchdogService.
 *
 * Manifest: android:exported="false"  (only the :watchdog process binds to it)
 */
class MainBridgeService : Service() {

    companion object {
        private const val TAG = "MainBridgeService"

        /** Convenience: start and bind to WatchdogService from the main process. */
        fun bindWatchdog(context: Context, connection: ServiceConnection) {
            val intent = Intent(context, WatchdogService::class.java)
            context.startForegroundService(intent)
            context.bindService(intent, connection, BIND_AUTO_CREATE)
        }
    }

    // -------------------------------------------------------------------------
    // IMainBridge.Stub — exposed to the :watchdog process
    // -------------------------------------------------------------------------

    private val mainBinder = object : IMainBridge.Stub() {

        /**
         * Called by WatchdogService after it reverse-binds.
         * We register a DeathRecipient so we know if the watchdog process dies.
         */
        override fun onWatchdogConnected(watchdogBinder: IBinder?) {
            watchdogBinder ?: return
            Log.i(TAG, "onWatchdogConnected: linking DeathRecipient to :watchdog binder")
            try {
                watchdogBinder.linkToDeath(watchdogDeathRecipient, 0)
                storedWatchdogBinder = watchdogBinder
            } catch (e: Exception) {
                Log.e(TAG, "linkToDeath failed: ${e.message}")
            }
        }

        override fun ping(): Boolean = true
    }

    // -------------------------------------------------------------------------
    // Death recipient for the :watchdog process
    // -------------------------------------------------------------------------

    private var storedWatchdogBinder: IBinder? = null

    private val watchdogDeathRecipient = IBinder.DeathRecipient {
        Log.w(TAG, "WATCHDOG PROCESS DIED — restarting WatchdogService")
        storedWatchdogBinder?.unlinkToDeath(watchdogDeathRecipient, 0)
        storedWatchdogBinder = null
        onWatchdogDied()
    }

    private fun onWatchdogDied() {
        // Re-start and re-bind to WatchdogService.
        // The new :watchdog process will call registerMainProcess() which
        // re-links the death recipient for the next cycle.
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                val watchdog = IWatchdogBridge.Stub.asInterface(service ?: return)
                try {
                    watchdog.registerMainProcess(mainBinder)
                    Log.i(TAG, "onWatchdogDied recovery: re-registered with new :watchdog process")
                } catch (e: Exception) {
                    Log.e(TAG, "onWatchdogDied recovery: ${e.message}")
                }
            }
            override fun onServiceDisconnected(name: ComponentName?) {}
        }
        bindWatchdog(applicationContext, conn)
    }

    // -------------------------------------------------------------------------
    // Service lifecycle
    // -------------------------------------------------------------------------

    override fun onBind(intent: Intent?): IBinder {
        Log.i(TAG, "onBind: :watchdog process connecting")
        return mainBinder
    }

    override fun onDestroy() {
        super.onDestroy()
        storedWatchdogBinder?.unlinkToDeath(watchdogDeathRecipient, 0)
        Log.i(TAG, "onDestroy")
    }
}
