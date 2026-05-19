package com.example.parentalcontrol

import android.util.Log

/**
 * NativeBridge  —  v2
 *
 * Changes from v1:
 * • registerVpnService() added — must be called before startProxyEngine().
 * • startProxyEngine() / stopProxyEngine() replace the old broken packet loop.
 * • startWatchdog() / stopWatchdog() / sendHeartbeat() removed — the watchdog
 *   is now a Binder IPC service and does not need a native heartbeat.
 * • Three new Kotlin callbacks invoked from C++:
 *     onSniAllowed()   — hostname passed policy
 *     onSniBlocked()   — hostname failed policy
 *     onEchConnection()— ECH detected; only destination IP is available
 */
object NativeBridge {

    private const val TAG = "NativeBridge"

    // -------------------------------------------------------------------------
    // Library bootstrap
    // -------------------------------------------------------------------------

    fun load() {
        System.loadLibrary("parental_control_native")
        Log.i(TAG, "parental_control_native v2 loaded")
    }

    // -------------------------------------------------------------------------
    // VPN Service registration
    //
    // Call from ParentalControlVpnService.onStartCommand() BEFORE
    // startProxyEngine().  Stores a JNI global ref to the service so the
    // C++ proxy threads can call VpnService.protect(fd) on any pthread.
    // -------------------------------------------------------------------------

    /**
     * @param service  The ParentalControlVpnService instance (`this`).
     */
    external fun registerVpnService(service: Any)

    // -------------------------------------------------------------------------
    // Proxy engine JNI surface
    // -------------------------------------------------------------------------

    /**
     * Start the transparent TCP proxy engine.
     *
     * The engine reads raw IP packets from the tun fd, rewrites TCP SYN
     * destinations to a local listener, reassembles TCP streams, inspects the
     * TLS SNI (or detects ECH), and ferries data through a protected outbound
     * socket — the internet connection is never broken.
     *
     * @param vpnFd  The integer file descriptor from
     *               [ParcelFileDescriptor.fd] on the established tun interface.
     */
    external fun startProxyEngine(vpnFd: Int)

    /** Signal the proxy engine to drain all connections and stop cleanly. */
    external fun stopProxyEngine()

    // -------------------------------------------------------------------------
    // Anti-tamper JNI surface  (unchanged)
    // -------------------------------------------------------------------------

    external fun verifyDexIntegrity(apkPath: String): Boolean

    // -------------------------------------------------------------------------
    // Callbacks invoked FROM C++ (called via JNI reflection — do not rename
    // or ProGuard will strip the method IDs and the C++ call will silently fail)
    // -------------------------------------------------------------------------

    /**
     * A TLS SNI hostname was extracted and passed the current blocklist policy.
     * Called from the C++ proxy thread — dispatch to your rules engine here.
     */
    @Suppress("unused")
    fun onSniAllowed(hostname: String) {
        Log.d(TAG, "SNI allowed → $hostname")
        // TODO: forward to audit log / dashboard UI
    }

    /**
     * A TLS SNI hostname matched the blocklist.
     * The C++ ferry has already been started; you should respond by closing
     * the tun-side fd or sending a TCP RST to terminate the connection.
     * For now this logs and records the event for the monitoring UI.
     */
    @Suppress("unused")
    fun onSniBlocked(hostname: String) {
        Log.w(TAG, "SNI BLOCKED → $hostname")
        // TODO:
        //   1. Write a TCP RST packet into the tun fd to terminate the connection
        //   2. Record the block event in Room DB
        //   3. Send a push notification to the parent's device
    }

    /**
     * An Encrypted ClientHello (ECH) connection was detected.
     * The hostname is intentionally hidden; only the destination IP is available.
     * Default policy: allow and log.  Override to block ECH entirely if desired.
     */
    @Suppress("unused")
    fun onEchConnection(destinationIp: String) {
        Log.i(TAG, "ECH connection to $destinationIp (hostname hidden — allowing)")
        // TODO: decide policy:
        //   • Allow (log IP for audit)
        //   • Block (return RST — note this breaks many modern HTTPS sites)
        //   • Prompt parent for override
    }
}
