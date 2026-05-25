package com.example.parentalcontrol

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

class DefensiveAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "DefensiveAccess"
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        val packageName = event.packageName?.toString() ?: ""
        val rootNode = rootInActiveWindow ?: return

        try {
            if (findText(rootNode, "Do you want to uninstall") ||
                findText(rootNode, "Uninstall this app")) {
                Log.w(TAG, "OEM Uninstall dialog detected. Ejecting.")
                performGlobalAction(GLOBAL_ACTION_HOME)
                return
            }

            if (packageName == "com.android.settings" || packageName == "com.google.android.packageinstaller") {
                if (findText(rootNode, "Force stop") ||
                    findText(rootNode, "Uninstall") ||
                    findText(rootNode, "Usage access") ||
                    findText(rootNode, "Accessibility") ||
                    findText(rootNode, "Always-on VPN") ||
                    findText(rootNode, "Parental Control")) {

                    Log.w(TAG, "Hostile UI interaction detected. Ejecting user.")
                    performGlobalAction(GLOBAL_ACTION_HOME)
                    return
                }

                if (findText(rootNode, "Deactivate this device admin app") ||
                    findText(rootNode, "Remove work profile")) {

                    Log.w(TAG, "Device Admin deactivation attempted. Launching PIN lock.")
                    val pinIntent = Intent(this, PinLockActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                        putExtra(PinLockActivity.EXTRA_REASON, PinLockActivity.REASON_ADMIN_DISABLE)
                    }
                    startActivity(pinIntent)
                    return
                }
            }

            if (packageName == "com.android.vpndialogs") {
                if (clickNodeByText(rootNode, "OK") || clickNodeByText(rootNode, "Allow")) {
                    Log.i(TAG, "VPN Dialog automatically accepted.")
                }
            }
        } finally {
            rootNode.recycle()
        }
    }

    private fun findText(node: AccessibilityNodeInfo, text: String): Boolean {
        if (node.text?.contains(text, ignoreCase = true) == true) return true
        if (node.contentDescription?.contains(text, ignoreCase = true) == true) return true
        for (i in 0 until node.childCount) {
            val child = node.getChild(i)
            if (child != null && findText(child, text)) {
                child.recycle()
                return true
            }
            child?.recycle()
        }
        return false
    }

    private fun clickNodeByText(node: AccessibilityNodeInfo, text: String): Boolean {
        if (node.text?.equals(text, ignoreCase = true) == true && node.isClickable) {
            node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
            return true
        }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i)
            if (child != null && clickNodeByText(child, text)) {
                child.recycle()
                return true
            }
            child?.recycle()
        }
        return false
    }

    override fun onInterrupt() {
        Log.w(TAG, "Accessibility Service interrupted.")
    }
}
