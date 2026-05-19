/**
 * native-lib.cpp  —  v2
 *
 * JNI entry point.  Changes from v1:
 *
 * • registerVpnService() — stores a global ref to the VpnService instance and
 *   initialises the protect() bridge used by the proxy engine to exempt
 *   outbound sockets from VPN routing.  Required before startProxyEngine().
 *
 * • startProxyEngine() / stopProxyEngine() replace the old broken
 *   startVpnPacketLoop / stopVpnPacketLoop.  The new engine does not drop
 *   packets; it transparently proxies every TCP connection.
 *
 * • sendHeartbeat() / startWatchdog() / stopWatchdog() are removed.
 *   The watchdog is now a Binder IPC service (WatchdogService.kt) and does
 *   not require a native heartbeat loop.
 *
 * • verifyDexIntegrity() is unchanged.
 */

#include <jni.h>
#include <android/log.h>

#include <cstring>
#include <string>

#include "include/sni_parser.h"
#include "include/anti_tamper.h"

#define LOG_TAG "PCNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Module-level JVM reference
// ---------------------------------------------------------------------------

static JavaVM* g_jvm = nullptr;

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    g_jvm = vm;
    LOGI("JNI_OnLoad: parental_control_native v2 loaded");
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNI_OnUnload(JavaVM* /*vm*/, void* /*reserved*/) {
    proxy_engine_stop();
    LOGI("JNI_OnUnload");
}

// ---------------------------------------------------------------------------
// VPN Service registration — must be called before startProxyEngine()
//
// Stores a GlobalRef to the ParentalControlVpnService instance so the C++
// proxy threads can call VpnService.protect(fd) from any pthread.
// ---------------------------------------------------------------------------

extern "C"
JNIEXPORT void JNICALL
Java_com_example_parentalcontrol_NativeBridge_registerVpnService(
        JNIEnv* env,
        jobject /* thiz */,
        jobject service) {

    if (!service) {
        LOGE("registerVpnService: null service reference");
        return;
    }

    // protect_bridge_init takes a GLOBAL ref — create it here.
    jobject global_ref = env->NewGlobalRef(service);
    protect_bridge_init(g_jvm, global_ref);
    LOGI("registerVpnService: protect() bridge initialised");
}

// ---------------------------------------------------------------------------
// Proxy engine start
//
// Hands the tun fd to the C++ transparent proxy engine.  The engine:
//   1. Reads raw IP packets from the tun fd.
//   2. For each TCP SYN, rewrites the destination to a local listener.
//   3. Accepts the redirected connection, inspects the SNI, and ferries
//      bytes through a protected outbound socket.
//
// The NativeBridge jobject is stored for the on_sni_allowed / on_sni_blocked
// / on_ech callbacks so Kotlin can act on filtering decisions.
// ---------------------------------------------------------------------------

// Global ref held for the lifetime of the engine (released on stop).
static jobject g_bridge_global = nullptr;

extern "C"
JNIEXPORT void JNICALL
Java_com_example_parentalcontrol_NativeBridge_startProxyEngine(
        JNIEnv* env,
        jobject thiz,
        jint    vpnFd) {

    if (g_bridge_global) {
        env->DeleteGlobalRef(g_bridge_global);
    }
    g_bridge_global = env->NewGlobalRef(thiz);

    ProxyEngineConfig cfg{};
    cfg.tun_fd     = vpnFd;
    cfg.jvm        = g_jvm;
    cfg.bridge_obj = g_bridge_global;

    // on_sni_allowed: a hostname passed policy — log and allow.
    cfg.on_sni_allowed = [](const std::string& host) {
        JNIEnv* e = nullptr; bool att = false;
        if (g_jvm->GetEnv(reinterpret_cast<void**>(&e), JNI_VERSION_1_6)
                == JNI_EDETACHED) {
            g_jvm->AttachCurrentThread(&e, nullptr); att = true;
        }
        if (e && g_bridge_global) {
            jclass    cls = e->GetObjectClass(g_bridge_global);
            jmethodID mid = e->GetMethodID(cls, "onSniAllowed", "(Ljava/lang/String;)V");
            if (mid) {
                jstring jh = e->NewStringUTF(host.c_str());
                e->CallVoidMethod(g_bridge_global, mid, jh);
                e->DeleteLocalRef(jh);
            }
            e->DeleteLocalRef(cls);
        }
        if (att) g_jvm->DetachCurrentThread();
    };

    // on_sni_blocked: hostname failed policy — caller should RST the connection.
    cfg.on_sni_blocked = [](const std::string& host) {
        JNIEnv* e = nullptr; bool att = false;
        if (g_jvm->GetEnv(reinterpret_cast<void**>(&e), JNI_VERSION_1_6)
                == JNI_EDETACHED) {
            g_jvm->AttachCurrentThread(&e, nullptr); att = true;
        }
        if (e && g_bridge_global) {
            jclass    cls = e->GetObjectClass(g_bridge_global);
            jmethodID mid = e->GetMethodID(cls, "onSniBlocked", "(Ljava/lang/String;)V");
            if (mid) {
                jstring jh = e->NewStringUTF(host.c_str());
                e->CallVoidMethod(g_bridge_global, mid, jh);
                e->DeleteLocalRef(jh);
            }
            e->DeleteLocalRef(cls);
        }
        if (att) g_jvm->DetachCurrentThread();
    };

    // on_ech: encrypted ClientHello — log destination IP, allow by default.
    cfg.on_ech = [](const std::string& ip) {
        JNIEnv* e = nullptr; bool att = false;
        if (g_jvm->GetEnv(reinterpret_cast<void**>(&e), JNI_VERSION_1_6)
                == JNI_EDETACHED) {
            g_jvm->AttachCurrentThread(&e, nullptr); att = true;
        }
        if (e && g_bridge_global) {
            jclass    cls = e->GetObjectClass(g_bridge_global);
            jmethodID mid = e->GetMethodID(cls, "onEchConnection", "(Ljava/lang/String;)V");
            if (mid) {
                jstring ji = e->NewStringUTF(ip.c_str());
                e->CallVoidMethod(g_bridge_global, mid, ji);
                e->DeleteLocalRef(ji);
            }
            e->DeleteLocalRef(cls);
        }
        if (att) g_jvm->DetachCurrentThread();
    };

    proxy_engine_start(cfg);
    LOGI("startProxyEngine: engine started (tun_fd=%d)", vpnFd);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_parentalcontrol_NativeBridge_stopProxyEngine(
        JNIEnv* env,
        jobject /* thiz */) {
    proxy_engine_stop();

    if (g_bridge_global) {
        env->DeleteGlobalRef(g_bridge_global);
        g_bridge_global = nullptr;
    }
    LOGI("stopProxyEngine: engine stopped");
}

// ---------------------------------------------------------------------------
// Anti-tamper — unchanged from v1
// ---------------------------------------------------------------------------

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_parentalcontrol_NativeBridge_verifyDexIntegrity(
        JNIEnv* env,
        jobject /* thiz */,
        jstring apkPath) {

    const char* path = env->GetStringUTFChars(apkPath, nullptr);
    if (!path) return JNI_FALSE;

    bool ok = verify_dex_crc32(path);
    env->ReleaseStringUTFChars(apkPath, path);

    if (!ok) {
        LOGE("verifyDexIntegrity: CRC32 MISMATCH — tampering detected");
    }
    return ok ? JNI_TRUE : JNI_FALSE;
}
