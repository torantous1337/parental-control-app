package com.example.parentalcontrol

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * DeviceAdminReceiver — Device Owner (DO) mode
 *
 * Provisioning path (Android 15 / API 35):
 *   adb shell dpm set-device-owner com.example.parentalcontrol/.AdminReceiver
 *
 * Or via QR-code / NFC bump using a DPC extras bundle with
 *   android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME
 *
 * Declare in AndroidManifest.xml inside <receiver>:
 *   android:permission="android.permission.BIND_DEVICE_ADMIN"
 *   <meta-data android:name="android.app.device_admin"
 *              android:resource="@xml/device_admin_policies" />
 */
class AdminReceiver : DeviceAdminReceiver() {

    companion object {
        private const val TAG = "AdminReceiver"

        /** Convenience helper to retrieve the [ComponentName] for policy calls. */
        fun getComponentName(context: Context): ComponentName =
            ComponentName(context.applicationContext, AdminReceiver::class.java)
    }

    // -------------------------------------------------------------------------
    // Lifecycle — Device Owner granted
    // -------------------------------------------------------------------------

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Log.i(TAG, "onEnabled: Device Admin / Device Owner rights granted")

        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE)
                as DevicePolicyManager
        val admin = getComponentName(context)

        applyBaselinePolicy(dpm, admin, context)
    }

    // -------------------------------------------------------------------------
    // Lifecycle — Device Owner revoked / admin deactivated
    // -------------------------------------------------------------------------

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        Log.w(TAG, "onDisabled: Device Admin rights revoked — parental controls inactive")

        // Stop the native watchdog and VPN service gracefully.
        WatchdogWorker.cancelAll(context)
        context.stopService(
            Intent(context, ParentalControlVpnService::class.java)
        )
    }

    // -------------------------------------------------------------------------
    // Optional: handle password / lock callbacks
    // -------------------------------------------------------------------------

    override fun onPasswordChanged(context: Context, intent: Intent) {
        Log.d(TAG, "onPasswordChanged")
    }

    override fun onPasswordFailed(context: Context, intent: Intent) {
        Log.w(TAG, "onPasswordFailed")
    }

    // -------------------------------------------------------------------------
    // Baseline Device Owner policy
    // -------------------------------------------------------------------------

    private fun applyBaselinePolicy(
        dpm: DevicePolicyManager,
        admin: ComponentName,
        context: Context
    ) {
        // Only the Device Owner can invoke these APIs.
        if (!dpm.isDeviceOwnerApp(context.packageName)) {
            Log.w(TAG, "applyBaselinePolicy: not Device Owner — skipping DO-only calls")
            return
        }

        // Prevent the user from uninstalling the app.
        // API 28+; still valid on API 35.
        dpm.setUninstallBlocked(admin, context.packageName, true)

        // Lock the task to prevent the user from closing the VPN service
        // notification or navigating away from the supervised profile.
        // Pair with startLockTask() in the foreground service.
        dpm.setLockTaskPackages(admin, arrayOf(context.packageName))

        // Disable adding/removing accounts (prevents bypassing family link).
        dpm.addUserRestriction(admin, android.os.UserManager.DISALLOW_MODIFY_ACCOUNTS)

        // Disable safe-mode boot (would strip admin privileges).
        dpm.addUserRestriction(admin, android.os.UserManager.DISALLOW_SAFE_BOOT)

        // Disable factory reset from Settings.
        dpm.addUserRestriction(admin, android.os.UserManager.DISALLOW_FACTORY_RESET)

        Log.i(TAG, "applyBaselinePolicy: baseline DO policy applied")
    }
}
