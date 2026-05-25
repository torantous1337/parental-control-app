package com.example.parentalcontrol

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class PinLockActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_REASON = "reason"
        const val REASON_ADMIN_DISABLE = "admin_disable"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            gravity = android.view.Gravity.CENTER
            setPadding(64, 64, 64, 64)
            setBackgroundColor(android.graphics.Color.DKGRAY)
        }

        val input = EditText(this).apply {
            hint = "Enter Parent PIN"
            setTextColor(android.graphics.Color.WHITE)
            setHintTextColor(android.graphics.Color.LTGRAY)
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
        }

        val submitBtn = Button(this).apply {
            text = "Unlock"
        }

        layout.addView(input)
        layout.addView(submitBtn)
        setContentView(layout)

        submitBtn.setOnClickListener {
            // Hardcoded for testing. In production, check against a hashed PIN in SharedPreferences.
            if (input.text.toString() == "1234") {
                Toast.makeText(this, "Access Granted", Toast.LENGTH_SHORT).show()
                finish() // Let them proceed to deactivate
            } else {
                Toast.makeText(this, "Incorrect PIN", Toast.LENGTH_SHORT).show()
                // Eject them back to the home screen
                val homeIntent = android.content.Intent(android.content.Intent.ACTION_MAIN).apply {
                    addCategory(android.content.Intent.CATEGORY_HOME)
                    flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                }
                startActivity(homeIntent)
                finish()
            }
        }
    }

    override fun onBackPressed() {
        // Eject to home screen if they try to back out
        val homeIntent = android.content.Intent(android.content.Intent.ACTION_MAIN).apply {
            addCategory(android.content.Intent.CATEGORY_HOME)
            flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(homeIntent)
        finish()
    }
}
