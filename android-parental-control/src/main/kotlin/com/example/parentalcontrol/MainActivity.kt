package com.example.parentalcontrol

import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.provider.Settings
import android.text.TextUtils
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A simple programmatic layout to avoid needing XML layout files for the prototype
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(64, 64, 64, 64)
        }

        val statusText = TextView(this).apply {
            textSize = 18f
            setPadding(0, 0, 0, 64)
        }
        
        val btnAdmin = Button(this).apply { text = "1. Enable Device Admin (Decoy)" }
        val btnUsage = Button(this).apply { text = "2. Grant Usage Access (Monitor)" }
        val btnAccess = Button(this).apply { text = "3. Enable Accessibility (Bouncer)" }
        val btnVpn = Button(this).apply { text = "4. Start VPN Proxy" }

        layout.addView(statusText)
        layout.addView(btnAdmin)
        layout.addView(btnUsage)
        layout.addView(btnAccess)
        layout.addView(btnVpn)
        setContentView(layout)

        // Update status UI
        val updateUI = {
            statusText.text = """
                Admin Active: ${isAdminActive()}
                Usage Access: ${hasUsageStatsPermission()}
                Accessibility: ${isAccessibilityEnabled()}
            """.trimIndent()
        }
        updateUI()

        // 1. Device Admin Intent
        btnAdmin.setOnClickListener {
            if (!isAdminActive()) {
                val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                    putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, ComponentName(this@MainActivity, AdminReceiver::class.java))
                    putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "Required to secure parental controls.")
                }
                startActivity(intent)
            }
        }

        // 2. Usage Stats Intent
        btnUsage.setOnClickListener {
            if (!hasUsageStatsPermission()) {
                startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
            }
        }

        // 3. Accessibility Intent
        btnAccess.setOnClickListener {
            if (!isAccessibilityEnabled()) {
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
        }

        // 4. VPN Start
        btnVpn.setOnClickListener {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                // If it asks for permission, our AccessibilityService will auto-click it!
                startActivityForResult(vpnIntent, 0)
            } else {
                startService(Intent(this, ParentalControlVpnService::class.java))
                startService(Intent(this, WatchdogService::class.java))
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Refresh UI when coming back from settings
        recreate() 
    }

    private fun isAdminActive(): Boolean {
        val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        return dpm.isAdminActive(ComponentName(this, AdminReceiver::class.java))
    }

    private fun hasUsageStatsPermission(): Boolean {
        val appOps = getSystemService(APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        } else {
            appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    private fun isAccessibilityEnabled(): Boolean {
        val expectedId = "$packageName/${DefensiveAccessibilityService::class.java.canonicalName}"
        val enabledServices = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        return !TextUtils.isEmpty(enabledServices) && enabledServices.contains(expectedId)
    }
}
