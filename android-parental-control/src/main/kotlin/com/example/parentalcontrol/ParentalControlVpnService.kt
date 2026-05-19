package com.example.parentalcontrol

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * ParentalControlVpnService  —  v2
 *
 * Changes from v1:
 * • Calls NativeBridge.registerVpnService(this) BEFORE startProxyEngine()
 *   so the C++ proxy threads can invoke VpnService.protect(fd) for every
 *   outbound socket they create.  Without this the protect() bridge is
 *   uninitialised and all outbound connections loop back into the tun.
 *
 * • Uses startProxyEngine() instead of the old broken startVpnPacketLoop().
 *
 * • Binds to WatchdogService and registers IMainBridge so the mutual
 *   DeathRecipient loop is established as soon as the VPN starts.
 *
 * • setBlocking(false) is kept — the native engine reads the tun fd with
 *   O_NONBLOCK via epoll, so a blocking fd is not needed.
 */
class ParentalControlVpnService : VpnService() {

    companion object {
        private const val TAG = "PCVpnService"

        const val ACTION_START = "com.example.parentalcontrol.VPN_START"
        const val ACTION_STOP  = "com.example.parentalcontrol.VPN_STOP"

        private const val NOTIFICATION_ID      = 1001
        private const val NOTIFICATION_CHANNEL = "vpn_service_channel"
        private const val VPN_MTU              = 1500
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private var watchdogConnection: ServiceConnection? = null

    // -------------------------------------------------------------------------
    // Service lifecycle
    // -------------------------------------------------------------------------

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_START -> { startVpn(); START_STICKY }
            ACTION_STOP  -> { stopVpn();  START_NOT_STICKY }
            else         -> START_STICKY
        }
    }

    override fun onRevoke() {
        Log.w(TAG, "onRevoke: VPN permission revoked")
        stopVpn()
    }

    override fun onDestroy() {
        super.onDestroy()
        watchdogConnection?.let { unbindService(it) }
        cleanupTun()
        Log.i(TAG, "onDestroy")
    }

    // -------------------------------------------------------------------------
    // VPN setup
    // -------------------------------------------------------------------------

    private fun startVpn() {
        startForeground(
            NOTIFICATION_ID,
            buildNotification(),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            else 0
        )

        val tun = Builder()
            .setSession("ParentalControl")
            .setMtu(VPN_MTU)
            .addAddress("10.10.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00::1", 128)
            .addRoute("::", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("1.0.0.1")
            .addDisallowedApplication(packageName)
            .setBlocking(false)
            .establish() ?: run {
                Log.e(TAG, "startVpn: establish() returned null")
                stopSelf()
                return
            }

        tunInterface = tun
        val fd = tun.fd
        protect(fd)
        Log.i(TAG, "startVpn: tun established (fd=$fd)")

        // ── CRITICAL ORDER ────────────────────────────────────────────────
        // 1. Register VPN service with the JNI protect() bridge FIRST.
        //    The proxy engine will immediately call protect() on new sockets;
        //    if the bridge is uninitialised those sockets loop back into tun.
        NativeBridge.registerVpnService(this)

        // 2. Start the transparent proxy engine.
        NativeBridge.startProxyEngine(fd)

        // 3. Bind to the WatchdogService to establish the Binder death loop.
        bindToWatchdog()
    }

    private fun stopVpn() {
        NativeBridge.stopProxyEngine()
        watchdogConnection?.let { unbindService(it); watchdogConnection = null }
        cleanupTun()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "stopVpn")
    }

    private fun cleanupTun() {
        try { tunInterface?.close() } catch (e: Exception) { Log.w(TAG, e.message) }
        tunInterface = null
    }

    // -------------------------------------------------------------------------
    // Watchdog Binder binding
    // -------------------------------------------------------------------------

    private fun bindToWatchdog() {
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                Log.i(TAG, "bindToWatchdog: connected to WatchdogService")
                val watchdog = IWatchdogBridge.Stub.asInterface(service ?: return)
                // Expose the IMainBridge from MainBridgeService to the watchdog.
                // We bind MainBridgeService first to get its Binder, then hand it over.
                bindMainBridgeAndRegister(watchdog)
            }
            override fun onServiceDisconnected(name: ComponentName?) {
                Log.w(TAG, "bindToWatchdog: watchdog ServiceConnection dropped")
            }
        }
        watchdogConnection = conn
        MainBridgeService.bindWatchdog(this, conn)
    }

    private fun bindMainBridgeAndRegister(watchdog: IWatchdogBridge) {
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                val mainBridge = IMainBridge.Stub.asInterface(service ?: return)
                try {
                    watchdog.registerMainProcess(mainBridge)
                    Log.i(TAG, "bindMainBridgeAndRegister: mutual death loop established")
                } catch (e: Exception) {
                    Log.e(TAG, "registerMainProcess: ${e.message}")
                }
            }
            override fun onServiceDisconnected(name: ComponentName?) {}
        }
        bindService(Intent(this, MainBridgeService::class.java), conn, BIND_AUTO_CREATE)
    }

    // -------------------------------------------------------------------------
    // Notification
    // -------------------------------------------------------------------------

    private fun buildNotification(): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(
                    NOTIFICATION_CHANNEL,
                    "Parental Control VPN",
                    NotificationManager.IMPORTANCE_LOW
                ).apply { description = "Keeps the parental control filter active" }
            )
        }

        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, ParentalControlVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
            .setContentTitle("Parental Control Active")
            .setContentText("Network monitoring is running")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(android.R.drawable.ic_media_pause, "Stop", stopIntent)
            .build()
    }
}
