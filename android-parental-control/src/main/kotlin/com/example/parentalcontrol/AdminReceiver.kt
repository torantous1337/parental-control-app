package com.example.parentalcontrol

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log

class AdminReceiver : DeviceAdminReceiver() {

    companion object {
        private const val TAG = "AdminReceiver"
        fun getComponentName(context: Context): ComponentName =
            ComponentName(context.applicationContext, AdminReceiver::class.java)
    }

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Log.i(TAG, "onEnabled: Device Admin rights granted (Decoy Mode)")
        
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        dpm.setPasswordQuality(getComponentName(context), DevicePolicyManager.PASSWORD_QUALITY_NUMERIC)
        
        context.startForegroundService(Intent(context, ForegroundMonitorService::class.java))
    }

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        Log.w(TAG, "onDisabled: Device Admin revoked")
        context.stopService(Intent(context, ParentalControlVpnService::class.java))
        context.stopService(Intent(context, ForegroundMonitorService::class.java))
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        Log.w(TAG, "onDisableRequested: deactivation attempt intercepted")
        return "Parental controls are active. A parent PIN is required."
    }
}
