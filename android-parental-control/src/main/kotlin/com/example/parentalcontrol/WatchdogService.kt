package com.example.parentalcontrol

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * WatchdogService
 *
 * Runs in the `:watchdog` process — a completely separate Linux process from
 * the main application process.  Android does not kill all processes of the
 * same package simultaneously; when the main process is killed by the OOM
 * killer or a force-stop, this process remains alive long enough to fire a
 * resurrection.
 *
 * Force-stop caveat
 * ─────────────────
 * On Android 14+ a user force-stop via Settings → App Info kills ALL processes
 * of a package.  This is by design and cannot be worked around from within the
 * app.  The Device Owner policy (AdminReceiver.kt) can disable the force-stop
 * option for supervised devices via setPackagesSuspended / setLockTaskPackages,
 * which is the correct mitigation for a parental-control deployment.
 *
 * Architecture — Mutual Binder DeathRecipient
 * ────────────────────────────────────────────
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │  :main process                                              │
 *   │  ┌───────────────────┐    bindService()   ┌─────────────┐  │
 *   │  │ ParentalControlApp│ ─────────────────► │             │  │
 *   │  │                   │                    │  Watchdog   │  │
 *   │  │  IMainBridge.Stub │ ◄───────────────── │  Service    │  │
 *   │  │  (exposed to wdg) │   reverse bind()   │  :watchdog  │  │
 *   │  └───────┬───────────┘                    └──────┬──────┘  │
 *   │          │ linkToDeath(mainDied)                 │          │
 *   │          │ ◄───────────────────────────────────  │          │
 *   │          │                         linkToDeath   │          │
 *   │          │                         (watchdogDied)│          │
 *   └──────────┼───────────────────────────────────────┼──────────┘
 *              │                                       │
 *              ▼ IBinder.DeathRecipient fires           ▼
 *         watchdog detects                     main detects
 *         main process death                  watchdog death
 *              │                                       │
 *              ▼                                       ▼
 *     startForegroundService              startService(WatchdogService)
 *     (VpnService + WatchdogService)      (re-bind)
 *
 * Both sides hold a DeathRecipient so either death is detected instantly by
 * the surviving process via the kernel's Binder notification mechanism —
 * no polling required.
 *
 * Manifest requirement
 * ────────────────────
 *   <service
 *       android:name=".WatchdogService"
 *       android:process=":watchdog"
 *       android:exported="false"
 *       android:foregroundServiceType="specialUse" />
 */
class WatchdogService : Service() {

    companion object {
        private const val TAG              = "WatchdogService"
        private const val NOTIFICATION_ID  = 2001
        private const val CHANNEL_ID       = "watchdog_channel"

        // Messenger message codes used for the reverse-bind handshake.
        const val MSG_REGISTER_MAIN  = 1
        const val MSG_PING           = 2
        const val MSG_PONG           = 3
        const val MSG_SHUTDOWN        = 99
    }

    // -------------------------------------------------------------------------
    // IWatchdogBridge.Stub — exposed to the main process
    // -------------------------------------------------------------------------

    private val watchdogBinder = object : IWatchdogBridge.Stub() {

        /**
         * Called by the main process immediately after it binds.
         * We register a DeathRecipient on mainBridge.asBinder() so we are
         * notified synchronously the moment the main process dies.
         */
        override fun registerMainProcess(mainBridge: IMainBridge?) {
            mainBridge ?: return
            Log.i(TAG, "registerMainProcess: linking death recipient")
            mainProcessBinder = mainBridge.asBinder()
            try {
                mainProcessBinder?.linkToDeath(mainDeathRecipient, 0)
            } catch (e: Exception) {
                Log.e(TAG, "linkToDeath failed: ${e.message}")
            }
            // Notify the main process that the watchdog is alive (reverse link).
            reverseBindToMain()
        }

        override fun shutdown() {
            Log.i(TAG, "shutdown: received shutdown command from main process")
            mainProcessBinder?.unlinkToDeath(mainDeathRecipient, 0)
            mainProcessBinder = null
            stopSelf()
        }
    }

    // -------------------------------------------------------------------------
    // IMainBridge.Stub — exposed back to the :watchdog process itself when
    // the main process binds in reverse.  Also stored here for the reverse bind.
    // -------------------------------------------------------------------------

    private val mainBridgeForReverseAccess = object : IMainBridge.Stub() {
        override fun onWatchdogConnected(watchdogBinder: IBinder?) {
            // Not used in :watchdog process — this stub exists in :main.
        }
        override fun ping(): Boolean = true
    }

    // -------------------------------------------------------------------------
    // Death recipients
    // -------------------------------------------------------------------------

    /** Fires when the main process IBinder crosses the death boundary. */
    private val mainDeathRecipient = IBinder.DeathRecipient {
        Log.w(TAG, "MAIN PROCESS DIED — triggering resurrection")
        onMainProcessDied()
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private var mainProcessBinder: IBinder? = null
    private val handler = Handler(Looper.getMainLooper())

    // -------------------------------------------------------------------------
    // Service lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate: WatchdogService starting in :watchdog process (pid=${android.os.Process.myPid()})")
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand")
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder {
        Log.i(TAG, "onBind: main process connecting")
        return watchdogBinder
    }

    override fun onDestroy() {
        super.onDestroy()
        mainProcessBinder?.unlinkToDeath(mainDeathRecipient, 0)
        Log.i(TAG, "onDestroy")
    }

    // -------------------------------------------------------------------------
    // Resurrection logic
    // -------------------------------------------------------------------------

    private fun onMainProcessDied() {
        // Unlink to prevent duplicate callbacks.
        try { mainProcessBinder?.unlinkToDeath(mainDeathRecipient, 0) } catch (_: Exception) {}
        mainProcessBinder = null

        // Schedule on main handler; this callback fires on a Binder thread.
        handler.post {
            Log.w(TAG, "Restarting ParentalControlVpnService after main process death")
            restartVpnService()
        }
    }

    private fun restartVpnService() {
        // Restart the VPN service.  The system will also restart the main
        // process (START_STICKY) — the App.onCreate() will re-bind to us.
        val intent = Intent(this, ParentalControlVpnService::class.java).apply {
            action = ParentalControlVpnService.ACTION_START
        }
        try {
            startForegroundService(intent)
            Log.i(TAG, "restartVpnService: startForegroundService sent")
        } catch (e: Exception) {
            Log.e(TAG, "restartVpnService: ${e.message}")
        }
    }

    // -------------------------------------------------------------------------
    // Reverse bind — watchdog binds back to the main process so the main
    // process can also detect watchdog death via its own DeathRecipient.
    // -------------------------------------------------------------------------

    private fun reverseBindToMain() {
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (service == null) return
                Log.i(TAG, "reverseBindToMain: connected to main process bridge")
                val mainBridge = IMainBridge.Stub.asInterface(service)
                try {
                    // Pass our binder to the main process so IT can linkToDeath on us.
                    mainBridge.onWatchdogConnected(watchdogBinder.asBinder())
                } catch (e: Exception) {
                    Log.e(TAG, "reverseBindToMain: ${e.message}")
                }
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                // Main process ServiceConnection dropped — it may have died.
                // The DeathRecipient will handle the formal notification.
                Log.w(TAG, "reverseBindToMain: main process ServiceConnection dropped")
            }
        }

        // Bind to the MainBridgeService exposed by the main process.
        val intent = Intent(this, MainBridgeService::class.java)
        bindService(intent, conn, BIND_AUTO_CREATE)
    }

    // -------------------------------------------------------------------------
    // Notification (required for foreground service)
    // -------------------------------------------------------------------------

    private fun buildNotification(): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Watchdog",
                    NotificationManager.IMPORTANCE_MIN)
            )
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Parental Control Watchdog")
            .setContentText("Monitoring app health")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
    }
}
