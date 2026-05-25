package com.example.parentalcontrol

import android.app.AppOpsManager
import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.util.Log

class ForegroundMonitorService : Service() {

    companion object {
        private const val TAG = "ForegroundMonitor"
        private const val POLL_INTERVAL_MS = 1_500L
        private const val CHANNEL_ID = "monitor_channel"
        private const val NOTIF_ID = 1002

        val BLOCKED_PACKAGES: Set<String> = setOf(
            "com.zhiliaoapp.musically",
            "com.instagram.android",
            "com.snapchat.android",
            "com.discord"
        )
    }

    private lateinit var usageStats: UsageStatsManager
    private val handler = Handler(Looper.getMainLooper())
    private var lastBlockedPackage: String? = null

    private val pollRunnable = object : Runnable {
        override fun run() {
            if (!hasUsageStatsPermission()) {
                Log.e(TAG, "CRITICAL: Usage Stats permission lost! App blocking is blind.")
                handler.postDelayed(this, 10_000L)
                return
            }
            checkForeground()
            handler.postDelayed(this, POLL_INTERVAL_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        usageStats = getSystemService(USAGE_STATS_SERVICE) as UsageStatsManager
        startForeground(NOTIF_ID, NotificationHelper.buildSilentNotification(
            this, CHANNEL_ID, "Parental Control", "Monitoring app usage"
        ))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        handler.post(pollRunnable)
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacks(pollRunnable)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun hasUsageStatsPermission(): Boolean {
        val appOps = getSystemService(APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    private fun foregroundPackage(): String? {
        val now = System.currentTimeMillis()
        val start = now - 10_000L
        val events = usageStats.queryEvents(start, now) ?: return null

        val event = UsageEvents.Event()
        var currentForeground: String? = null

        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            when (event.eventType) {
                UsageEvents.Event.MOVE_TO_FOREGROUND -> currentForeground = event.packageName
                UsageEvents.Event.MOVE_TO_BACKGROUND -> {
                    if (currentForeground == event.packageName) {
                        currentForeground = null
                    }
                }
            }
        }
        return currentForeground
    }

    private fun checkForeground() {
        val pkg = foregroundPackage() ?: return
        if (pkg == packageName) return

        if (pkg in BLOCKED_PACKAGES) {
            if (pkg != lastBlockedPackage) {
                Log.w(TAG, "BLOCKED: $pkg — launching BlockerActivity")
                lastBlockedPackage = pkg
            }
            launchBlocker(pkg)
        } else {
            lastBlockedPackage = null
        }
    }

    private fun launchBlocker(blockedPackage: String) {
        val intent = Intent(this, BlockerActivity::class.java).apply {
            putExtra(BlockerActivity.EXTRA_BLOCKED_PACKAGE, blockedPackage)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        startActivity(intent)
    }
}
