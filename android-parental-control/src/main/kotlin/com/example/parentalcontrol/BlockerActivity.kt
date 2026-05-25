package com.example.parentalcontrol

import android.os.Bundle
import android.view.Gravity
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class BlockerActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_BLOCKED_PACKAGE = "extra_blocked_package"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val blockedPackage = intent.getStringExtra(EXTRA_BLOCKED_PACKAGE) ?: ""
        val view = TextView(this).apply {
            text = if (blockedPackage.isNotBlank()) {
                "Blocked app: $blockedPackage"
            } else {
                "This app is blocked."
            }
            textSize = 18f
            gravity = Gravity.CENTER
        }
        setContentView(view)
    }
}
