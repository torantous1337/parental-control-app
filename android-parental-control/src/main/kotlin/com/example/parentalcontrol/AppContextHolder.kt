package com.example.parentalcontrol

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context

/**
 * AppContextHolder
 *
 * Stores the Application context so it can be retrieved from static JNI
 * callbacks (e.g. WatchdogWorker.onNativeRequestRestart) that do not have
 * a natural Context parameter available.
 *
 * Initialise in your [Application] subclass:
 *
 *   class App : Application() {
 *       override fun onCreate() {
 *           super.onCreate()
 *           AppContextHolder.init(this)
 *           NativeBridge.load()
 *           ...
 *       }
 *   }
 */
@SuppressLint("StaticFieldLeak")   // deliberately holding ApplicationContext — safe
object AppContextHolder {

    @Volatile
    private var appContext: Context? = null

    fun init(application: Application) {
        appContext = application.applicationContext
    }

    fun get(): Context? = appContext
}
