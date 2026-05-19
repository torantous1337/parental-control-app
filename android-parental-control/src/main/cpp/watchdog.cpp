/**
 * watchdog.cpp
 *
 * Native watchdog service.
 *
 * Architecture
 * ────────────
 * A dedicated pthread listens on an Android Abstract Unix Domain Socket.
 * The Kotlin ForegroundService / WorkManager sends periodic heartbeat frames
 * over this socket.  If the native side stops receiving heartbeats within
 * `heartbeat_interval_ms × missed_beats_limit` milliseconds it assumes the
 * Java process has been killed and calls back into Java via a stored JVM
 * reference to request a restart.
 *
 * The Java side also watches the native PID with a FileObserver on /proc,
 * creating a mutual-resurrection loop that survives:
 *   • OOM kills of the foreground service
 *   • App force-stop (pid namespace still exists for a brief window)
 *   • Battery-optimisation-induced process deaths
 *
 * Socket protocol (tiny, fixed-width):
 *   [0]   0xAB — magic
 *   [1]   0x01 — HEARTBEAT  |  0x02 — SHUTDOWN
 *   [2–3] sequence (uint16 big-endian, wraps)
 */

#include "include/watchdog.h"

#include <android/log.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <string>

#define LOG_TAG "Watchdog"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Frame constants
// ---------------------------------------------------------------------------
static constexpr uint8_t MAGIC            = 0xAB;
static constexpr uint8_t MSG_HEARTBEAT    = 0x01;
static constexpr uint8_t MSG_SHUTDOWN     = 0x02;
static constexpr size_t  FRAME_LEN        = 4;  // magic + type + seq(2)

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------
static std::atomic<bool> g_running{false};
static pthread_t          g_thread;
static WatchdogConfig     g_cfg;
static JavaVM*            g_jvm = nullptr;

// Client fd used by watchdog_send_heartbeat() called from the Java thread.
static int                g_client_fd   = -1;
static std::atomic<uint16_t> g_seq{0};
static pthread_mutex_t    g_fd_mutex    = PTHREAD_MUTEX_INITIALIZER;

// ---------------------------------------------------------------------------
// Internal: bind the abstract UDS server socket
// ---------------------------------------------------------------------------
static int bind_server_socket(const char* name) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        LOGE("socket: %s", strerror(errno));
        return -1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    // Abstract namespace: first byte is '\0', rest is the name.
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, name, sizeof(addr.sun_path) - 2);
    socklen_t addrlen = offsetof(sockaddr_un, sun_path) + 1 + strlen(name);

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), addrlen) < 0) {
        LOGE("bind: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 1) < 0) {
        LOGE("listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

// ---------------------------------------------------------------------------
// Internal: notify Kotlin to (re)start the ForegroundService
// ---------------------------------------------------------------------------
static void notify_java_restart() {
    if (!g_jvm) return;

    JNIEnv* env = nullptr;
    bool attached = false;

    if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6)
            == JNI_EDETACHED) {
        g_jvm->AttachCurrentThread(&env, nullptr);
        attached = true;
    }

    if (env) {
        jclass cls = env->FindClass(
            "com/example/parentalcontrol/WatchdogWorker");
        if (cls) {
            jmethodID mid = env->GetStaticMethodID(
                cls, "onNativeRequestRestart", "()V");
            if (mid) {
                env->CallStaticVoidMethod(cls, mid);
                LOGI("notify_java_restart: called WatchdogWorker.onNativeRequestRestart");
            }
            env->DeleteLocalRef(cls);
        }
    }

    if (attached) {
        g_jvm->DetachCurrentThread();
    }
}

// ---------------------------------------------------------------------------
// Watchdog server thread
// ---------------------------------------------------------------------------
static void* watchdog_thread_fn(void* /*arg*/) {
    LOGI("watchdog_thread_fn: binding on abstract socket '%s'",
         g_cfg.socket_name.c_str());

    int server_fd = bind_server_socket(g_cfg.socket_name.c_str());
    if (server_fd < 0) {
        LOGE("watchdog_thread_fn: failed to bind, aborting");
        g_running.store(false);
        return nullptr;
    }

    while (g_running.load()) {
        // Accept connection from the Java side (ForegroundService or WorkManager).
        pollfd pfd{ server_fd, POLLIN, 0 };
        int pr = poll(&pfd, 1, 2000 /* 2 s accept timeout */);
        if (!g_running.load()) break;
        if (pr <= 0) continue;  // timeout or signal — keep waiting

        int client = accept4(server_fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            LOGE("accept4: %s", strerror(errno));
            continue;
        }

        LOGI("watchdog_thread_fn: Java side connected");

        // Store for heartbeat_send calls originating from JNI on the Java thread.
        {
            pthread_mutex_lock(&g_fd_mutex);
            if (g_client_fd >= 0) close(g_client_fd);
            g_client_fd = client;
            pthread_mutex_unlock(&g_fd_mutex);
        }

        int missed = 0;
        while (g_running.load()) {
            pollfd cfd{ client, POLLIN, 0 };
            int r = poll(&cfd, 1,
                         static_cast<int>(g_cfg.heartbeat_interval_ms));

            if (!g_running.load()) break;

            if (r < 0) {
                LOGE("poll: %s", strerror(errno));
                break;
            }

            if (r == 0) {
                // Timeout — missed heartbeat.
                ++missed;
                LOGW("watchdog: missed heartbeat %d/%d",
                     missed, g_cfg.missed_beats_limit);
                if (missed >= g_cfg.missed_beats_limit) {
                    LOGW("watchdog: Java side unresponsive — requesting restart");
                    notify_java_restart();
                    missed = 0;
                }
                continue;
            }

            // Data available.
            uint8_t frame[FRAME_LEN + 1]{};
            ssize_t n = recv(client, frame, FRAME_LEN, MSG_DONTWAIT);
            if (n <= 0) break;  // disconnected

            if (n < 2 || frame[0] != MAGIC) {
                LOGW("watchdog: malformed frame, ignoring");
                continue;
            }

            if (frame[1] == MSG_HEARTBEAT) {
                missed = 0;
                LOGI("watchdog: heartbeat OK (seq=%u)",
                     static_cast<uint16_t>((frame[2] << 8) | frame[3]));
            } else if (frame[1] == MSG_SHUTDOWN) {
                LOGI("watchdog: received SHUTDOWN from Java side");
                g_running.store(false);
                break;
            }
        }

        pthread_mutex_lock(&g_fd_mutex);
        close(g_client_fd);
        g_client_fd = -1;
        pthread_mutex_unlock(&g_fd_mutex);
    }

    close(server_fd);
    LOGI("watchdog_thread_fn: exited");
    return nullptr;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

int watchdog_start(JavaVM* jvm, const WatchdogConfig& cfg) {
    if (g_running.exchange(true)) return 0;  // already running

    g_jvm = jvm;
    g_cfg = cfg;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&g_thread, &attr, watchdog_thread_fn, nullptr);
    pthread_attr_destroy(&attr);

    if (rc != 0) {
        LOGE("pthread_create: %s", strerror(rc));
        g_running.store(false);
        return -1;
    }

    return 0;
}

void watchdog_stop() {
    if (!g_running.exchange(false)) return;

    // Best-effort: try sending SHUTDOWN frame.
    pthread_mutex_lock(&g_fd_mutex);
    if (g_client_fd >= 0) {
        uint8_t frame[FRAME_LEN] = { MAGIC, MSG_SHUTDOWN, 0, 0 };
        send(g_client_fd, frame, FRAME_LEN, MSG_DONTWAIT);
    }
    pthread_mutex_unlock(&g_fd_mutex);
}

void watchdog_send_heartbeat() {
    pthread_mutex_lock(&g_fd_mutex);
    if (g_client_fd >= 0) {
        uint16_t seq = g_seq.fetch_add(1);
        uint8_t frame[FRAME_LEN] = {
            MAGIC,
            MSG_HEARTBEAT,
            static_cast<uint8_t>(seq >> 8),
            static_cast<uint8_t>(seq & 0xFF)
        };
        send(g_client_fd, frame, FRAME_LEN, MSG_DONTWAIT);
    }
    pthread_mutex_unlock(&g_fd_mutex);
}
