#pragma once

#include <jni.h>
#include <cstdint>
#include <functional>
#include <string>

// ---------------------------------------------------------------------------
// SNI parse result
// ---------------------------------------------------------------------------

enum class SniResult {
    FOUND,        ///< Hostname extracted successfully
    NOT_YET,      ///< Not enough data reassembled — keep buffering
    NOT_TLS,      ///< Not a TLS ClientHello
    ECH,          ///< Encrypted ClientHello — hostname is intentionally hidden
    MALFORMED,    ///< Parse error — treat as opaque stream
};

/**
 * Attempt to parse a TLS ClientHello from a reassembled byte stream.
 *
 * Memory-safe: every pointer dereference is guarded by a strict < end_ptr
 * check immediately before the access.
 *
 * @param data      Pointer to the start of the TLS record (ContentType byte).
 * @param len       Number of valid bytes available.
 * @param out_host  Receives the SNI hostname if result == FOUND.
 * @param out_ip    Receives the destination IP string if result == ECH
 *                  (for logging purposes).
 * @return          One of the SniResult values above.
 */
SniResult parse_sni(const uint8_t* data, size_t len,
                    std::string& out_host, std::string& out_ip);

// ---------------------------------------------------------------------------
// JNI protect() bridge — called from C++ proxy threads
// ---------------------------------------------------------------------------

/**
 * Initialise the protect() bridge.  Called once from JNI_OnLoad or from the
 * registerVpnService JNI function.
 *
 * @param jvm      The JavaVM (stored for cross-thread use).
 * @param svc_ref  Global JNI reference to the ParentalControlVpnService
 *                 instance.  Must already be a global ref.
 */
void protect_bridge_init(JavaVM* jvm, jobject svc_ref);

/**
 * Call VpnService.protect(fd) from any thread.
 * Thread-safe; attaches/detaches the current thread as needed.
 *
 * @return true if the socket was successfully exempted from VPN routing.
 */
bool jni_protect_socket(int fd);

// ---------------------------------------------------------------------------
// Transparent TCP proxy engine
// ---------------------------------------------------------------------------

struct ProxyEngineConfig {
    int      tun_fd        = -1;      ///< VPN tun file descriptor
    JavaVM*  jvm           = nullptr;
    jobject  bridge_obj    = nullptr; ///< Global ref to NativeBridge (for SNI callback)
    std::function<void(const std::string& host)> on_sni_allowed;
    std::function<void(const std::string& host)> on_sni_blocked;
    std::function<void(const std::string& ip)>   on_ech;
};

/**
 * Start the transparent TCP proxy engine on a background thread.
 * Non-blocking; returns immediately.
 */
void proxy_engine_start(const ProxyEngineConfig& cfg);

/** Signal the proxy engine to drain connections and stop. */
void proxy_engine_stop();
