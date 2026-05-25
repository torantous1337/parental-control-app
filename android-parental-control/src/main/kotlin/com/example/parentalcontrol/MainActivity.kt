package com.example.parentalcontrol

import android.Manifest
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.os.Process
import android.provider.Settings
import android.text.TextUtils
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    // Runtime Permission Launcher for Android 13+ Notifications
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (!isGranted) {
            Toast.makeText(this, "Notifications are required for background stability.", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(64, 64, 64, 64)
        }

        val statusText = TextView(this).apply {
            textSize = 16f
            setPadding(0, 0, 0, 48)
        }
        
        val btnBattery = Button(this).apply { text = "1. Ignore Battery Optimizations" }
        val btnAdmin = Button(this).apply { text = "2. Enable Device Admin (Decoy)" }
        val btnUsage = Button(this).apply { text = "3. Grant Usage Access (Monitor)" }
        val btnAccess = Button(this).apply { text = "4. Enable Accessibility (Bouncer)" }
        val btnVpn = Button(this).apply { text = "5. Start VPN Proxy & Services" }

        layout.addView(statusText)
        layout.addView(btnBattery)
        layout.addView(btnAdmin)
        layout.addView(btnUsage)
        layout.addView(btnAccess)
        layout.addView(btnVpn)
        setContentView(layout)

        // ── Step 0: Ask for Post Notifications (Android 13+) automatically ──
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Update status UI
        val updateUI = {
            statusText.text = """
                Battery Exempt: ${isIgnoringBatteryOptimizations()}
                Admin Active: ${isAdminActive()}
                Usage Access: ${hasUsageStatsPermission()}
                Accessibility: ${isAccessibilityEnabled()}
            """.trimIndent()
        }
        updateUI()

        // 1. Battery Optimization Intent
        btnBattery.setOnClickListener {
            if (!isIgnoringBatteryOptimizations()) {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            }
        }

        // 2. Device Admin Intent
        btnAdmin.setOnClickListener {
            if (!isAdminActive()) {
                val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                    putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, ComponentName(this@MainActivity, AdminReceiver::class.java))
                    putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "Required to secure parental controls.")
                }
                startActivity(intent)
            }
        }

        // 3. Usage Stats Intent
        btnUsage.setOnClickListener {
            if (!hasUsageStatsPermission()) {
                startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
            }
        }

        // 4. Accessibility Intent
        btnAccess.setOnClickListener {
            if (!isAccessibilityEnabled()) {
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
        }

        // 5. VPN Start
        btnVpn.setOnClickListener {
            // Verify notification permissions before starting Foreground Services
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && 
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(this, "Grant Notification Permission First!", Toast.LENGTH_SHORT).show()
                requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return@setOnClickListener
            }

            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                // The AccessibilityService will auto-click "OK" on this dialog
                startActivityForResult(vpnIntent, 0)
            } else {
                startService(Intent(this, ParentalControlVpnService::class.java))
                startService(Intent(this, WatchdogService::class.java))
                Toast.makeText(this, "Services Started Successfully", Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        recreate() // Refresh UI state variables when coming back from settings
    }

    private fun isIgnoringBatteryOptimizations(): Boolean {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        return pm.isIgnoringBatteryOptimizations(packageName)
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
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    private fun isAccessibilityEnabled(): Boolean {
        val expectedId = "$packageName/${DefensiveAccessibilityService::class.java.canonicalName}"
        val enabledServices = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        return !TextUtils.isEmpty(enabledServices) && enabledServices.contains(expectedId)
    }
}package com.example.parentalcontrol

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
        val btnOverlay = Button(this).apply { text = "1.5 Grant Overlay Permission (Required for Blocking)" }
        layout.addView(statusText)
        layout.addView(btnAdmin)
        layout.addView(btnUsage)
        layout.addView(btnOverlay, 2)
        layout.addView(btnAccess)
        layout.addView(btnVpn)
        setContentView(layout)

        // Update status UI
        val updateUI = {
            statusText.text = """
                Battery Exempt: ${isIgnoringBatteryOptimizations()}
                Overlay Granted: ${canDrawOverlays()}
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
        btnOverlay.setOnClickListener {
            if (!canDrawOverlays()) {
                val intent = Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:$packageName")
                )
                startActivity(intent)
            } else {
                Toast.makeText(this, "Overlay already granted!", Toast.LENGTH_SHORT).show()
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
    private fun canDrawOverlays(): Boolean {
        return Settings.canDrawOverlays(this)
    }
}
