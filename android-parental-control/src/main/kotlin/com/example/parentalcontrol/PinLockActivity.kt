package com.example.parentalcontrol

import android.os.Bundle
import android.view.Gravity
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class PinLockActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_REASON = "extra_reason"
        const val REASON_ADMIN_DISABLE = "reason_admin_disable"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val reason = intent.getStringExtra(EXTRA_REASON)
        val view = TextView(this).apply {
            text = if (reason == REASON_ADMIN_DISABLE) {
                "Enter parent PIN to disable admin."
            } else {
                "Enter parent PIN."
            }
            textSize = 18f
            gravity = Gravity.CENTER
        }
        setContentView(view)
    }
}
