#pragma once

#include <jni.h>
#include <string>

/**
 * Configuration for the native watchdog.
 */
struct WatchdogConfig {
    std::string socket_name;           ///< Abstract Unix socket name (no leading '\0')
    int         heartbeat_interval_ms; ///< How long to wait for a heartbeat
    int         missed_beats_limit;    ///< Consecutive misses before restart is requested
};

/**
 * Start the watchdog listener thread.
 *
 * @param jvm  The JVM, stored for use when calling back into Kotlin.
 * @param cfg  Watchdog configuration.
 * @return 0 on success, -1 on failure (check errno).
 */
int watchdog_start(JavaVM* jvm, const WatchdogConfig& cfg);

/**
 * Stop the watchdog listener thread.
 * Safe to call even if the watchdog was never started.
 */
void watchdog_stop();

/**
 * Send a heartbeat frame from the Java/Kotlin side.
 * Must be called from the Java thread that owns the connected socket.
 * Thread-safe.
 */
void watchdog_send_heartbeat();
