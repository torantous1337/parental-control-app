package com.example.parentalcontrol

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class BlockerActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_BLOCKED_PACKAGE = "blocked_package"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        val blockedApp = intent.getStringExtra(EXTRA_BLOCKED_PACKAGE) ?: "Unknown App"

        val layout = android.widget.LinearLayout(this).apply {
            setBackgroundColor(android.graphics.Color.RED)
            gravity = android.view.Gravity.CENTER
            orientation = android.widget.LinearLayout.VERTICAL
        }

        val text = TextView(this).apply {
            text = "ACCESS DENIED\n\n$blockedApp is blocked by Parental Controls."
            textSize = 24f
            setTextColor(android.graphics.Color.WHITE)
            gravity = android.view.Gravity.CENTER
            setPadding(64, 64, 64, 64)
        }

        layout.addView(text)
        setContentView(layout)
    }

    // Disable the back button so they can't sneak under the overlay
    override fun onBackPressed() {
        // Do nothing. Brick wall stands.
    }
}
