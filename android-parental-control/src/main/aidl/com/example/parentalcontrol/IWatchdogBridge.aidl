// IWatchdogBridge.aidl
// Exposed by the :watchdog process.
// The main process binds to this interface so the watchdog knows the main
// process IBinder token — enabling it to register a DeathRecipient.

package com.example.parentalcontrol;

import com.example.parentalcontrol.IMainBridge;

interface IWatchdogBridge {
    /**
     * Called by the main process immediately after it binds to the watchdog.
     * The watchdog stores mainBridge.asBinder() and calls
     * linkToDeath(deathRecipient) on it.  If the main process is killed, the
     * death recipient fires and the watchdog restarts the VPN service.
     */
    void registerMainProcess(IMainBridge mainBridge);

    /** Explicit shutdown — called when the user intentionally disables controls. */
    void shutdown();
}
