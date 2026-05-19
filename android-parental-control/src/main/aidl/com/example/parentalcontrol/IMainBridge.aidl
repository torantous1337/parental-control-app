// IMainBridge.aidl
// Exposed by the main process.
// The :watchdog process binds back to this interface and registers its own
// DeathRecipient — if the watchdog dies, the main process restarts it.

package com.example.parentalcontrol;

interface IMainBridge {
    /**
     * Called by the watchdog immediately after reverse-binding to the main
     * process.  The main process stores watchdogBinder.asBinder() and
     * calls linkToDeath(deathRecipient) on it.
     */
    void onWatchdogConnected(IBinder watchdogBinder);

    /** Liveness check — the watchdog pings periodically; main returns true. */
    boolean ping();
}
