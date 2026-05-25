package com.example.parentalcontrol

import android.os.Bundle
import android.view.Gravity
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val view = TextView(this).apply {
            text = "Parental Control"
            textSize = 20f
            gravity = Gravity.CENTER
        }
        setContentView(view)
    }
}
