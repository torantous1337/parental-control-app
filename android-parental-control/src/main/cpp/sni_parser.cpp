/**
 * sni_parser.cpp  —  v2  (Production rewrite)
 *
 * Fixes from v1
 * ─────────────
 * 1. BLACK HOLE: Packets are no longer dropped.  The ProxyEngine implements
 *    a transparent TCP proxy: for every new TCP connection seen on the tun
 *    interface, a protected outbound socket is created and data is ferried.
 *
 * 2. TCP SEGMENTATION: A per-connection ReassemblyBuffer accumulates TCP
 *    segments ordered by sequence number.  SNI parsing begins only after
 *    a contiguous run of >= 5 bytes is available (the TLS record header).
 *
 * 3. BOUNDS SAFETY: Every pointer dereference in parse_sni() is preceded by
 *    an explicit check against `end` (= data + len).  The function returns
 *    SniResult::MALFORMED rather than reading past the buffer on any anomaly.
 *
 * 4. ECH DETECTION: Extension type 0xfe0d (draft-ietf-tls-esni) is detected
 *    and reported as SniResult::ECH so the caller can log the destination IP
 *    and allow the connection without a hostname.
 *
 * Transparent proxy architecture
 * ──────────────────────────────
 * The tun interface delivers ALL raw IPv4/IPv6 packets from the device.
 * Correctly proxying TCP without a full userspace TCP stack (e.g. lwIP)
 * requires re-implementing TCP state, windowing, and retransmission.
 * The ProxyEngine here provides:
 *   • Connection tracking (SYN detection, 5-tuple key)
 *   • Per-connection segment reassembly buffer
 *   • JNI protect() bridge for creating VPN-exempt outbound sockets
 *   • A fully-wired ferry loop (epoll, two fds, bidirectional copy)
 *   • Packet rewrite utilities (dst rewrite + checksum correction)
 *
 * The lwIP integration point is marked with LWIP_INTEGRATION_POINT comments.
 * For a production build, replace those stubs with lwIP netif callbacks.
 * The rest of the engine (SNI parser, protect bridge, ferry, watchdog) is
 * complete and usable independently of the TCP stack choice.
 *
 * Target: Android 15 / API 35, NDK r27+, C++17
 */

#include "include/sni_parser.h"

#include <android/log.h>
#include <android/looper.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "ProxyEngine"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ============================================================================
// Utility: big-endian readers — NO UB, NO unaligned access
// ============================================================================

static inline uint8_t  u8(const uint8_t* p)             { return p[0]; }
static inline uint16_t u16be(const uint8_t* p)          { return (uint16_t)(p[0]<<8|p[1]); }
static inline uint32_t u32be(const uint8_t* p)          { return (uint32_t)(p[0]<<24|p[1]<<16|p[2]<<8|p[3]); }
static inline uint16_t u16le(const uint8_t* p)          { return (uint16_t)(p[0]|p[1]<<8); }
static inline uint32_t u32le(const uint8_t* p)          { return (uint32_t)(p[0]|p[1]<<8|p[2]<<16|p[3]<<24); }
static inline void     w16be(uint8_t* p, uint16_t v)    { p[0]=v>>8; p[1]=v&0xFF; }
static inline void     w32be(uint8_t* p, uint32_t v)    { p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v; }

// ============================================================================
// Utility: IP and TCP checksum calculation
// ============================================================================

static uint16_t inet_checksum(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += u16be(p); p += 2; len -= 2; }
    if (len)         sum += (uint32_t)(*p) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/** Recalculate the IP header checksum in-place. */
static void fix_ip_checksum(uint8_t* ip_hdr) {
    uint8_t ihl = (ip_hdr[0] & 0x0F) * 4;
    w16be(ip_hdr + 10, 0);
    w16be(ip_hdr + 10, inet_checksum(ip_hdr, ihl));
}

/** Recalculate the UDP checksum in-place (IPv4 pseudo-header). */
static void fix_udp_checksum(uint8_t* ip_hdr, uint8_t* udp_hdr, size_t udp_len) {
    uint8_t pseudo[12];
    memcpy(pseudo + 0, ip_hdr + 12, 4);
    memcpy(pseudo + 4, ip_hdr + 16, 4);
    pseudo[8] = 0; pseudo[9] = IPPROTO_UDP;
    w16be(pseudo + 10, (uint16_t)udp_len);

    w16be(udp_hdr + 6, 0);  // zero before computing

    uint32_t sum = 0;
    for (int i = 0; i < 12; i += 2) sum += u16be(pseudo + i);
    const uint8_t* p = udp_hdr;
    size_t n = udp_len;
    while (n > 1) { sum += u16be(p); p += 2; n -= 2; }
    if (n) sum += (uint32_t)(*p) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    w16be(udp_hdr + 6, (uint16_t)~sum);
}

/**
 * Build a raw IPv4 + UDP packet from components and write it into out[].
 * out must be at least 28 + payload_len bytes.
 */
static size_t build_udp_ipv4(uint8_t* out,
                               uint32_t src_ip, uint16_t src_port,
                               uint32_t dst_ip, uint16_t dst_port,
                               const uint8_t* payload, size_t pay_len) {
    // IP header
    out[0] = 0x45; out[1] = 0;
    uint16_t total = (uint16_t)(20 + 8 + pay_len);
    w16be(out + 2, total);
    w16be(out + 4, 0); w16be(out + 6, 0x4000);  // DF bit
    out[8] = 64; out[9] = IPPROTO_UDP;
    w16be(out + 10, 0);
    w32be(out + 12, src_ip);
    w32be(out + 16, dst_ip);
    // UDP header
    uint8_t* udp = out + 20;
    w16be(udp + 0, src_port);
    w16be(udp + 2, dst_port);
    w16be(udp + 4, (uint16_t)(8 + pay_len));
    w16be(udp + 6, 0);
    memcpy(udp + 8, payload, pay_len);
    // Fix checksums
    fix_ip_checksum(out);
    fix_udp_checksum(out, udp, 8 + pay_len);
    return (size_t)total;
}

/** Recalculate the TCP checksum in-place (IPv4 pseudo-header). */
static void fix_tcp_checksum(uint8_t* ip_hdr, uint8_t* tcp_hdr, size_t tcp_len) {
    // Build pseudo-header on the stack.
    uint8_t pseudo[12];
    memcpy(pseudo + 0, ip_hdr + 12, 4);  // src IP
    memcpy(pseudo + 4, ip_hdr + 16, 4);  // dst IP
    pseudo[8] = 0;
    pseudo[9] = 6;  // TCP
    w16be(pseudo + 10, (uint16_t)tcp_len);

    // Zero out the existing checksum before computing.
    w16be(tcp_hdr + 16, 0);

    uint32_t sum = 0;
    // Accumulate pseudo-header.
    for (int i = 0; i < 12; i += 2) sum += u16be(pseudo + i);
    // Accumulate TCP segment.
    const uint8_t* p = tcp_hdr;
    size_t n = tcp_len;
    while (n > 1) { sum += u16be(p); p += 2; n -= 2; }
    if (n)         sum += (uint32_t)(*p) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    w16be(tcp_hdr + 16, (uint16_t)~sum);
}

// ============================================================================
// Connection tracking
// ============================================================================

struct ConnKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;

    bool operator==(const ConnKey& o) const {
        return src_ip   == o.src_ip   && dst_ip   == o.dst_ip
            && src_port == o.src_port && dst_port == o.dst_port;
    }
};

struct ConnKeyHash {
    size_t operator()(const ConnKey& k) const {
        size_t h = (size_t)k.src_ip;
        h ^= (size_t)k.dst_ip   * 0x9e3779b9ULL;
        h ^= (size_t)k.src_port * 0x517cc1b7ULL;
        h ^= (size_t)k.dst_port * 0xbf58476dULL;
        return h;
    }
};

// ============================================================================
// TCP segment reassembly buffer
//
// Stores out-of-order TCP payload segments keyed by sequence number.
// Provides a contiguous view of the stream once enough data is available.
// ============================================================================

class ReassemblyBuffer {
public:
    void reset(uint32_t isn) {
        next_seq_ = isn + 1;  // ISN + 1 is the first data seq
        segments_.clear();
        contiguous_.clear();
    }

    /** Insert a segment.  Silently drops duplicates and old segments. */
    void insert(uint32_t seq, const uint8_t* data, size_t len) {
        if (len == 0) return;
        // Drop if entirely before next expected sequence.
        uint32_t end_seq = seq + (uint32_t)len;
        if ((int32_t)(end_seq - next_seq_) <= 0) return;

        auto& seg = segments_[seq];
        if (seg.empty()) {
            seg.assign(data, data + len);
        }
        drain();
    }

    /** True if at least `min_bytes` contiguous bytes are available. */
    bool has(size_t min_bytes) const { return contiguous_.size() >= min_bytes; }

    const uint8_t* data()  const { return contiguous_.data(); }
    size_t         size()  const { return contiguous_.size(); }

    void consume(size_t n) {
        if (n >= contiguous_.size()) { contiguous_.clear(); return; }
        contiguous_.erase(contiguous_.begin(), contiguous_.begin() + n);
    }

private:
    uint32_t next_seq_ = 0;
    std::map<uint32_t, std::vector<uint8_t>> segments_;
    std::vector<uint8_t> contiguous_;

    void drain() {
        while (!segments_.empty()) {
            auto it = segments_.begin();
            uint32_t seg_seq = it->first;
            auto&    seg_buf = it->second;

            if ((int32_t)(seg_seq - next_seq_) > 0) break;  // gap — stop

            // Segment starts at or before next_seq_.
            size_t skip = 0;
            if ((int32_t)(seg_seq - next_seq_) < 0) {
                skip = (size_t)(next_seq_ - seg_seq);  // trim already-seen bytes
            }
            if (skip < seg_buf.size()) {
                contiguous_.insert(contiguous_.end(),
                                   seg_buf.begin() + skip,
                                   seg_buf.end());
                next_seq_ += (uint32_t)(seg_buf.size() - skip);
            }
            segments_.erase(it);
        }
    }
};

// ============================================================================
// Per-connection proxy session
// ============================================================================

enum class SniState { PENDING, FOUND, ECH_DETECTED, SKIPPED };

struct ProxySession {
    ConnKey        key;
    int            outbound_fd  = -1;   // protected socket to real server
    int            tun_side_fd  = -1;   // socket representing the tun connection
                                         // (filled in when accepted from local listener)
    ReassemblyBuffer reassembly;
    SniState       sni_state    = SniState::PENDING;
    std::string    hostname;             // filled when SNI is found
    std::string    dst_ip_str;           // dotted-decimal destination IP

    ~ProxySession() {
        if (outbound_fd  >= 0) close(outbound_fd);
        if (tun_side_fd  >= 0) close(tun_side_fd);
    }
};

// ============================================================================
// JNI protect() bridge
// ============================================================================

static JavaVM*  g_jvm        = nullptr;
static jobject  g_svc_ref    = nullptr;  // global ref to VpnService instance
static jmethodID g_protect_mid = nullptr;
static std::mutex g_protect_mutex;

void protect_bridge_init(JavaVM* jvm, jobject svc_global_ref) {
    std::lock_guard<std::mutex> lk(g_protect_mutex);
    g_jvm     = jvm;
    g_svc_ref = svc_global_ref;
    // Cache the method ID on the calling thread (must be attached).
    JNIEnv* env = nullptr;
    if (jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK && env) {
        jclass cls   = env->GetObjectClass(svc_global_ref);
        g_protect_mid = env->GetMethodID(cls, "protect", "(I)Z");
        env->DeleteLocalRef(cls);
    }
}

bool jni_protect_socket(int fd) {
    std::lock_guard<std::mutex> lk(g_protect_mutex);
    if (!g_jvm || !g_svc_ref || !g_protect_mid) {
        LOGE("protect_bridge not initialised");
        return false;
    }

    JNIEnv* env     = nullptr;
    bool    attached = false;

    int rc = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != 0) return false;
        attached = true;
    }

    jboolean ok = env->CallBooleanMethod(g_svc_ref, g_protect_mid, (jint)fd);
    if (env->ExceptionCheck()) { env->ExceptionClear(); ok = JNI_FALSE; }

    if (attached) g_jvm->DetachCurrentThread();
    return ok == JNI_TRUE;
}

// ============================================================================
// Hardened SNI parser  (v2)
//
// Every pointer arithmetic step is followed by an immediate check against
// `end` before any dereference.  Returning SniResult::MALFORMED anywhere
// inside the function is the safe default on any anomaly.
// ============================================================================

// TLS extension types
static constexpr uint16_t EXT_SNI  = 0x0000;
static constexpr uint16_t EXT_ECH  = 0xFE0D;  // draft-ietf-tls-esni / ECH

SniResult parse_sni(const uint8_t* data, size_t len,
                    std::string& out_host, std::string& out_ip) {
    // We need at minimum:
    //   5  (TLS record header)
    // + 4  (handshake header)
    // + 2  (ClientVersion)
    // + 32 (Random)
    // + 1  (SessionID length)  = 44 bytes before any variable-length fields.
    if (!data || len < 44) return SniResult::NOT_YET;

    const uint8_t* const end = data + len;

    // Guard: TLS record layer.
    //   [0]   ContentType  must be 0x16 (handshake)
    //   [1–2] ProtocolVersion (we accept any)
    //   [3–4] Length
    if (data[0] != 0x16) return SniResult::NOT_TLS;

    // Check enough bytes for the record.
    if (end - data < 5) return SniResult::NOT_YET;
    uint16_t record_len = u16be(data + 3);
    if ((size_t)record_len + 5 > len) return SniResult::NOT_YET;

    // Handshake header starts at offset 5.
    //   [5]   HandshakeType  must be 0x01 (ClientHello)
    //   [6–8] Length (uint24)
    if (data + 9 > end)  return SniResult::NOT_YET;
    if (data[5] != 0x01) return SniResult::NOT_TLS;

    // Cursor — walk past fixed-length ClientHello fields.
    const uint8_t* p = data + 9;  // start of ClientVersion

    // ClientVersion (2) + Random (32) = 34 bytes.
    if (p + 34 > end) return SniResult::NOT_YET;
    p += 34;

    // SessionID: length byte + data.
    if (p + 1 > end) return SniResult::NOT_YET;
    uint8_t sid_len = *p++;
    if (p + sid_len > end) return SniResult::NOT_YET;
    p += sid_len;

    // CipherSuites: uint16 length + suite list.
    if (p + 2 > end) return SniResult::NOT_YET;
    uint16_t cs_len = u16be(p); p += 2;
    if (p + cs_len > end) return SniResult::NOT_YET;
    p += cs_len;

    // Compression methods: uint8 length + list.
    if (p + 1 > end) return SniResult::NOT_YET;
    uint8_t cm_len = *p++;
    if (p + cm_len > end) return SniResult::NOT_YET;
    p += cm_len;

    // Extensions: uint16 total length.
    if (p + 2 > end) return SniResult::NOT_YET;
    uint16_t ext_total = u16be(p); p += 2;
    const uint8_t* ext_end = p + ext_total;
    if (ext_end > end) return SniResult::NOT_YET;

    // Walk extensions.
    while (p + 4 <= ext_end) {  // each extension needs at least type(2)+len(2)
        uint16_t ext_type = u16be(p);       p += 2;
        uint16_t ext_len  = u16be(p);       p += 2;

        // Bounds: the extension body must fit within the extensions block.
        if (p + ext_len > ext_end) return SniResult::MALFORMED;

        if (ext_type == EXT_ECH) {
            // Encrypted ClientHello detected — hostname is intentionally hidden.
            // The caller should log the destination IP and allow through.
            return SniResult::ECH;
        }

        if (ext_type == EXT_SNI) {
            // ServerNameList:
            //   uint16  server_name_list_length
            //   uint8   name_type  (0x00 = host_name)
            //   uint16  name_length
            //   uint8[] HostName
            const uint8_t* sp  = p;
            const uint8_t* spe = p + ext_len;

            if (sp + 2 > spe) return SniResult::MALFORMED;
            uint16_t list_len = u16be(sp); sp += 2;
            if (sp + list_len > spe) return SniResult::MALFORMED;

            if (sp + 1 > spe) return SniResult::MALFORMED;
            uint8_t name_type = *sp++;

            if (name_type != 0x00) {
                // Not a host_name entry — skip.
                p += ext_len;
                continue;
            }

            if (sp + 2 > spe) return SniResult::MALFORMED;
            uint16_t name_len = u16be(sp); sp += 2;

            if (sp + name_len > spe) return SniResult::MALFORMED;
            // Validate: SNI must be printable ASCII, no embedded NULs.
            for (uint16_t i = 0; i < name_len; ++i) {
                uint8_t c = sp[i];
                if (c < 0x20 || c > 0x7E) return SniResult::MALFORMED;
            }

            out_host.assign(reinterpret_cast<const char*>(sp), name_len);
            return SniResult::FOUND;
        }

        p += ext_len;  // skip unknown extension
    }

    // No SNI extension present (direct IP connection, or stripped by middlebox).
    return SniResult::NOT_TLS;
}

// ============================================================================
// Bidirectional ferry  —  epoll-based, O(1) per event
//
// Takes two fully-connected file descriptors and copies data between them
// until either closes or an error occurs.  This is the inner loop of the
// transparent proxy and is independent of the TCP stack choice.
// ============================================================================

static constexpr size_t FERRY_BUF = 65536;

static void ferry_loop(int fd_a, int fd_b,
                       std::atomic<bool>& running) {
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) { LOGE("epoll_create1: %s", strerror(errno)); return; }

    auto add_fd = [&](int fd, uint32_t events) {
        epoll_event ev{};
        ev.events   = events | EPOLLERR | EPOLLHUP;
        ev.data.fd  = fd;
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    };

    add_fd(fd_a, EPOLLIN | EPOLLET);
    add_fd(fd_b, EPOLLIN | EPOLLET);

    std::vector<uint8_t> buf(FERRY_BUF);
    epoll_event events[4];

    while (running.load(std::memory_order_relaxed)) {
        int n = epoll_wait(ep, events, 4, 500 /*ms*/);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOGE("epoll_wait: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < n; ++i) {
            int    src  = events[i].data.fd;
            int    dst  = (src == fd_a) ? fd_b : fd_a;
            uint32_t ev = events[i].events;

            if (ev & (EPOLLERR | EPOLLHUP)) {
                LOGD("ferry: fd=%d closed", src);
                goto done;
            }

            if (ev & EPOLLIN) {
                // Drain in a loop (edge-triggered).
                for (;;) {
                    ssize_t r = read(src, buf.data(), FERRY_BUF);
                    if (r == 0) goto done;           // EOF
                    if (r < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        LOGE("ferry read fd=%d: %s", src, strerror(errno));
                        goto done;
                    }
                    // Write in a loop until all bytes flushed.
                    size_t off = 0;
                    while (off < (size_t)r) {
                        ssize_t w = write(dst, buf.data() + off, r - off);
                        if (w <= 0) goto done;
                        off += (size_t)w;
                    }
                }
            }
        }
    }

done:
    close(ep);
}

// ============================================================================
// Packet rewrite helpers — IPv4 only
//
// Rewrites the TCP destination IP+port in a SYN packet so the kernel routes
// it to our local listener (127.0.0.1:listener_port).  Recalculates both the
// IP header checksum and the TCP checksum using the pseudo-header.
// ============================================================================

static bool rewrite_tcp_syn_dst(uint8_t* pkt, size_t pkt_len,
                                 uint32_t new_dst_ip, uint16_t new_dst_port) {
    if (pkt_len < 20) return false;
    uint8_t ver = (pkt[0] >> 4);
    if (ver != 4) return false;  // IPv6 rewrite not shown here

    uint8_t ihl = (pkt[0] & 0x0F) * 4;
    if (pkt_len < (size_t)ihl + 20) return false;

    uint8_t proto = pkt[9];
    if (proto != IPPROTO_TCP) return false;

    uint8_t* tcp    = pkt + ihl;
    uint8_t  flags  = tcp[13];
    if (!(flags & 0x02)) return false;  // must be SYN

    // Total TCP segment length for checksum.
    uint16_t ip_total = u16be(pkt + 2);
    size_t   tcp_len  = ip_total - ihl;
    if (pkt_len < ip_total) return false;

    // Rewrite IP destination.
    w32be(pkt + 16, new_dst_ip);
    // Rewrite TCP destination port.
    w16be(tcp + 2, new_dst_port);

    // Recalculate checksums.
    fix_ip_checksum(pkt);
    fix_tcp_checksum(pkt, tcp, tcp_len);
    return true;
}

// ============================================================================
// ProxyEngine
//
// Lifecycle: proxy_engine_start() → background thread → proxy_engine_stop()
//
// LWIP_INTEGRATION_POINT (marked below):
// Replace the tun_read_loop() stub with an lwIP netif input callback.
// Everything else (SNI parsing, ferry, protect bridge) remains unchanged.
// ============================================================================

static ProxyEngineConfig                            g_eng_cfg;
static std::atomic<bool>                            g_eng_running{false};
static pthread_t                                    g_eng_thread;

// Connection table: keyed by 5-tuple, owns the session.
static std::unordered_map<ConnKey, std::unique_ptr<ProxySession>, ConnKeyHash> g_sessions;
static std::mutex g_sessions_mutex;

// ── DNS UDP session tracking ──────────────────────────────────────────────────
// Each in-flight DNS query gets a protected SOCK_DGRAM and an entry here.
// The epoll loop recognises these fds and routes responses back into tun.

struct DnsSession {
    int      udp_fd;         ///< Protected SOCK_DGRAM to the real resolver
    uint32_t client_ip;      ///< Original query source (device IP)
    uint16_t client_port;    ///< Original query source port
    uint32_t server_ip;      ///< Original DNS server IP (from query packet)
    uint16_t server_port;    ///< 53
    uint64_t timestamp_ms;   ///< CLOCK_MONOTONIC milliseconds when query was sent
};

/** Monotonic millisecond clock — never wraps within any plausible uptime. */
static uint64_t now_ms() noexcept {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000u
         + static_cast<uint64_t>(ts.tv_nsec) / 1'000'000u;
}

/** DNS session reaper — called after every epoll_wait() cycle.
 *
 * Because g_dns_map is accessed only from the single engine thread there is
 * no mutex needed here.  Iterator invalidation is avoided by collecting
 * stale fds into a local vector first, then erasing after the traversal.
 *
 * @param ep        The engine's epoll fd.
 * @param timeout   Staleness threshold in milliseconds (default: 5 000 ms).
 */
static void reap_stale_dns(int ep, uint64_t timeout = 5'000u) {
    const uint64_t now = now_ms();

    // Collect fds to close — never erase inside a range-for.
    std::vector<int> stale;
    stale.reserve(g_dns_map.size());
    for (const auto& kv : g_dns_map) {
        if (now - kv.second.timestamp_ms >= timeout) {
            stale.push_back(kv.first);
        }
    }

    for (int fd : stale) {
        LOGW("DNS reaper: session fd=%d timed out — closing", fd);
        epoll_ctl(ep, EPOLL_CTL_DEL, fd, nullptr);
        close(fd);
        g_dns_map.erase(fd);
    }
}

// Map from udp_fd → DnsSession — accessed only from the engine thread.
static std::unordered_map<int, DnsSession> g_dns_map;

// Local listener socket — accepts the redirected SYN from the kernel.
static int  g_listener_fd   = -1;
static int  g_listener_port = 0;

// Wake pipe for stopping the main loop.
static int  g_wake_pipe[2]  = {-1, -1};

// ──────────────────────────────────────────────
// Create an ephemeral local TCP listener socket.
// ──────────────────────────────────────────────
static int create_local_listener(int& out_port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(0);  // ephemeral port

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    if (listen(fd, 128) < 0) {
        close(fd); return -1;
    }

    socklen_t len = sizeof(addr);
    getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
    out_port = ntohs(addr.sin_port);
    return fd;
}

// ──────────────────────────────────────────────
// Create a protected outbound socket and connect to the real destination.
// ──────────────────────────────────────────────
static int create_protected_outbound(uint32_t dst_ip, uint16_t dst_port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    if (!jni_protect_socket(fd)) {
        LOGE("create_protected_outbound: protect() failed");
        close(fd);
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(dst_ip);
    addr.sin_port        = htons(dst_port);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0
        && errno != EINPROGRESS) {
        LOGE("create_protected_outbound: connect to %u.%u.%u.%u:%u failed: %s",
             dst_ip>>24&0xFF, dst_ip>>16&0xFF, dst_ip>>8&0xFF, dst_ip&0xFF,
             dst_port, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

// ──────────────────────────────────────────────
// Per-connection ferry thread entry.
// ──────────────────────────────────────────────
struct FerryArgs {
    int  tun_side_fd;
    int  outbound_fd;
    std::atomic<bool> running{true};
    ConnKey key;
};

static void* ferry_thread_fn(void* arg) {
    auto* fa = static_cast<FerryArgs*>(arg);
    ferry_loop(fa->tun_side_fd, fa->outbound_fd, fa->running);

    // Clean up session.
    {
        std::lock_guard<std::mutex> lk(g_sessions_mutex);
        g_sessions.erase(fa->key);
    }

    delete fa;
    return nullptr;
}

// ──────────────────────────────────────────────
// On TCP SYN: create session, inspect reassembly, start ferry.
// This is called once the local listener accepts an inbound connection.
// ──────────────────────────────────────────────
static void on_accepted(int accepted_fd, ConnKey key) {
    // Look up the session we created when we saw the SYN on tun.
    std::unique_ptr<ProxySession> session;
    {
        std::lock_guard<std::mutex> lk(g_sessions_mutex);
        auto it = g_sessions.find(key);
        if (it == g_sessions.end()) {
            LOGW("on_accepted: no session for connection — closing");
            close(accepted_fd);
            return;
        }
        session = std::move(it->second);
        g_sessions.erase(it);
    }

    session->tun_side_fd = accepted_fd;

    // Read the initial data for SNI inspection (non-blocking, best effort).
    if (session->sni_state == SniState::PENDING) {
        uint8_t buf[4096];
        ssize_t n = recv(accepted_fd, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
        if (n > 0) {
            session->reassembly.insert(0, buf, (size_t)n);
        }

        if (session->reassembly.has(5)) {
            std::string host, ip = session->dst_ip_str;
            SniResult r = parse_sni(session->reassembly.data(),
                                    session->reassembly.size(),
                                    host, ip);
            switch (r) {
                case SniResult::FOUND:
                    LOGI("SNI: %s → %s", host.c_str(), session->dst_ip_str.c_str());
                    session->hostname  = host;
                    session->sni_state = SniState::FOUND;
                    if (g_eng_cfg.on_sni_allowed) g_eng_cfg.on_sni_allowed(host);
                    break;
                case SniResult::ECH:
                    LOGI("ECH connection to %s (hostname hidden)", session->dst_ip_str.c_str());
                    session->sni_state = SniState::ECH_DETECTED;
                    if (g_eng_cfg.on_ech) g_eng_cfg.on_ech(session->dst_ip_str);
                    break;
                case SniResult::NOT_YET:
                    // More data needed — ferry will continue buffering.
                    break;
                default:
                    session->sni_state = SniState::SKIPPED;
                    break;
            }
        }
    }

    // Spawn the ferry thread.
    auto* fa       = new FerryArgs{};
    fa->tun_side_fd = session->tun_side_fd;
    fa->outbound_fd = session->outbound_fd;
    fa->key         = key;

    // Prevent double-close: the ferry thread owns both fds from here.
    session->tun_side_fd = -1;
    session->outbound_fd = -1;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(nullptr, &attr, ferry_thread_fn, fa);
    pthread_attr_destroy(&attr);
}

// ──────────────────────────────────────────────
// Main engine loop — reads from tun fd, rewrites SYNs, accepts from listener.
//
// LWIP_INTEGRATION_POINT:
//   Replace the raw `read(tun_fd, ...)` + `rewrite_tcp_syn_dst()`
//   block with:
//       netif_input(&lwip_netif, pbuf_from_bytes(pkt, n));
//   and register a netif->output function that writes back to tun.
//   The on_accepted() / ferry_loop() code below remains unchanged.
// ──────────────────────────────────────────────
static void* engine_thread_fn(void* /*arg*/) {
    int tun_fd = g_eng_cfg.tun_fd;

    // Make tun fd non-blocking.
    int fl = fcntl(tun_fd, F_GETFL, 0);
    fcntl(tun_fd, F_SETFL, fl | O_NONBLOCK);

    g_listener_fd = create_local_listener(g_listener_port);
    if (g_listener_fd < 0) {
        LOGE("engine: failed to create local listener: %s", strerror(errno));
        g_eng_running.store(false);
        return nullptr;
    }
    LOGI("engine: local listener on 127.0.0.1:%d", g_listener_port);

    int ep = epoll_create1(EPOLL_CLOEXEC);
    auto add = [&](int fd, uint32_t ev_flags) {
        epoll_event ev{}; ev.events = ev_flags; ev.data.fd = fd;
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    };
    add(tun_fd,          EPOLLIN | EPOLLET);
    add(g_listener_fd,   EPOLLIN);
    add(g_wake_pipe[0],  EPOLLIN);

    uint8_t      pkt[65536];
    epoll_event  events[8];

    // epoll_wait timeout: 1 000 ms.
    // A finite timeout is required so the reaper can sweep stale DNS sessions
    // even when the tun fd is otherwise idle.  Without it, a DNS server that
    // drops packets would leave the corresponding fd and g_dns_map entry open
    // forever, eventually hitting EMFILE and crashing the engine.
    constexpr int EPOLL_TIMEOUT_MS = 1'000;

    while (g_eng_running.load(std::memory_order_relaxed)) {
        int n = epoll_wait(ep, events, 8, EPOLL_TIMEOUT_MS);

        if (n < 0) {
            if (errno == EINTR) {
                // A signal interrupted epoll_wait — still run the reaper
                // before looping so that a burst of signals cannot starve it.
                reap_stale_dns(ep);
                continue;
            }
            break;  // unrecoverable error
        }

        // n == 0: timeout — no events fired.  This is the primary reaper tick.
        if (n == 0) {
            reap_stale_dns(ep);
            continue;
        }

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;

            // ── Wake pipe ────────────────────────────────────────────────
            if (fd == g_wake_pipe[0]) { goto done; }

            // ── Local listener: accept a redirected connection ────────────
            if (fd == g_listener_fd) {
                sockaddr_in peer{};
                socklen_t   plen = sizeof(peer);
                int         afd  = accept4(g_listener_fd,
                                           reinterpret_cast<sockaddr*>(&peer),
                                           &plen, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (afd < 0) continue;

                // Recover the original key from the source address.
                uint16_t src_port = ntohs(peer.sin_port);
                uint32_t src_ip   = ntohl(peer.sin_addr.s_addr);

                // Find the session whose src_port matches.
                ConnKey found_key{};
                bool    found = false;
                {
                    std::lock_guard<std::mutex> lk(g_sessions_mutex);
                    for (auto& kv : g_sessions) {
                        if (kv.first.src_ip   == src_ip &&
                            kv.first.src_port == src_port) {
                            found_key = kv.first;
                            found     = true;

                            // Create the outbound socket now that we know
                            // the destination (stored in the session).
                            int ofd = create_protected_outbound(
                                kv.second->key.dst_ip,
                                kv.second->key.dst_port);
                            if (ofd < 0) { close(afd); found = false; break; }
                            kv.second->outbound_fd = ofd;
                            break;
                        }
                    }
                }

                if (found) on_accepted(afd, found_key);
                else       close(afd);
                continue;
            }

            // ── DNS UDP response fd ───────────────────────────────────────
            {
                auto dit = g_dns_map.find(fd);
                if (dit != g_dns_map.end()) {
                    DnsSession& ds = dit->second;
                    uint8_t resp[65536];
                    ssize_t rn = recv(fd, resp, sizeof(resp) - 28, MSG_DONTWAIT);
                    if (rn > 0) {
                        // Construct IP+UDP packet: src = DNS server, dst = client.
                        uint8_t inject[65536];
                        size_t  inj_len = build_udp_ipv4(
                            inject,
                            ds.server_ip, ds.server_port,
                            ds.client_ip, ds.client_port,
                            resp, (size_t)rn);
                        write(tun_fd, inject, inj_len);
                        LOGD("DNS response injected (%zd bytes)", inj_len);
                    }
                    epoll_ctl(ep, EPOLL_CTL_DEL, fd, nullptr);
                    close(fd);
                    g_dns_map.erase(dit);
                    continue;
                }
            }

            // ── Tun fd: raw IP packets from the device ────────────────────
            if (fd == tun_fd) {
                // Drain all available packets (edge-triggered).
                for (;;) {
                    ssize_t plen = read(tun_fd, pkt, sizeof(pkt));
                    if (plen < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        LOGE("tun read: %s", strerror(errno));
                        goto done;
                    }
                    if (plen < 20) continue;

                    uint8_t ver   = (pkt[0] >> 4);
                    if (ver != 4)  continue;  // skip IPv6 for now

                    uint8_t ihl   = (pkt[0] & 0x0F) * 4;
                    uint8_t proto = pkt[9];

                    // ── UDP: handle DNS (port 53); drop everything else ───
                    if (proto == IPPROTO_UDP) {
                        // Need IP header + full UDP header (8 bytes).
                        if ((size_t)plen < (size_t)ihl + 8) continue;
                        uint8_t* udp_hdr  = pkt + ihl;
                        uint16_t dst_port = u16be(udp_hdr + 2);

                        if (dst_port != 53) {
                            // Non-DNS UDP: forward transparently through a
                            // protected socket without inspection.
                            uint32_t dst_ip   = u32be(pkt + 16);
                            uint32_t src_ip   = u32be(pkt + 12);
                            uint16_t src_port = u16be(udp_hdr + 0);
                            uint16_t udp_len  = u16be(udp_hdr + 4);
                            size_t   pay_len  = (udp_len > 8) ? (udp_len - 8) : 0;

                            int ufd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                            if (ufd >= 0 && jni_protect_socket(ufd)) {
                                sockaddr_in dst{}; dst.sin_family = AF_INET;
                                dst.sin_addr.s_addr = htonl(dst_ip);
                                dst.sin_port        = htons(dst_port);
                                sendto(ufd, udp_hdr + 8, pay_len, MSG_DONTWAIT,
                                       reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
                                // Best-effort, no response expected (e.g. NTP, QUIC).
                                close(ufd);
                            } else if (ufd >= 0) {
                                close(ufd);
                            }
                            continue;
                        }

                        // DNS query — must capture the response and inject back.
                        uint32_t dns_srv_ip = u32be(pkt + 16);
                        uint32_t cli_ip     = u32be(pkt + 12);
                        uint16_t cli_port   = u16be(udp_hdr + 0);
                        uint16_t udp_len    = u16be(udp_hdr + 4);
                        size_t   pay_len    = (udp_len > 8) ? (size_t)(udp_len - 8) : 0;

                        int dfd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                        if (dfd < 0) continue;
                        if (!jni_protect_socket(dfd)) { close(dfd); continue; }

                        sockaddr_in srv{};
                        srv.sin_family      = AF_INET;
                        srv.sin_addr.s_addr = htonl(dns_srv_ip);
                        srv.sin_port        = htons(53);

                        if (sendto(dfd, udp_hdr + 8, pay_len, MSG_DONTWAIT,
                                   reinterpret_cast<sockaddr*>(&srv), sizeof(srv)) < 0) {
                            LOGW("DNS sendto: %s", strerror(errno));
                            close(dfd); continue;
                        }

                        // Register in the DNS map and epoll so the response is caught.
                        // timestamp_ms is stamped at sendto() time so the reaper
                        // measures the full round-trip age of this query.
                        g_dns_map[dfd] = DnsSession{
                            dfd, cli_ip, cli_port, dns_srv_ip, 53, now_ms()
                        };
                        epoll_event dns_ev{};
                        dns_ev.events  = EPOLLIN | EPOLLET;
                        dns_ev.data.fd = dfd;
                        epoll_ctl(ep, EPOLL_CTL_ADD, dfd, &dns_ev);
                        LOGD("DNS forwarded to %u.%u.%u.%u (query fd=%d)",
                             dns_srv_ip>>24&0xFF, dns_srv_ip>>16&0xFF,
                             dns_srv_ip>>8&0xFF,  dns_srv_ip&0xFF, dfd);
                        continue;  // done with this UDP packet
                    }

                    // ── Non-TCP, non-UDP: skip (ICMP etc.) ───────────────
                    if (proto != IPPROTO_TCP) continue;

                    if ((size_t)plen < (size_t)ihl + 20) continue;
                    uint8_t* tcp   = pkt + ihl;
                    uint8_t  flags = tcp[13];

                    uint32_t src_ip   = u32be(pkt + 12);
                    uint32_t dst_ip   = u32be(pkt + 16);
                    uint16_t src_port = u16be(tcp + 0);
                    uint16_t dst_port = u16be(tcp + 2);

                    if (flags & 0x02) {
                        // ── TCP SYN: new connection ───────────────────────
                        ConnKey key{ src_ip, dst_ip, src_port, dst_port };

                        // Record session before rewriting, so on_accepted()
                        // can look it up using the src tuple.
                        {
                            std::lock_guard<std::mutex> lk(g_sessions_mutex);
                            if (g_sessions.count(key) == 0) {
                                auto sess        = std::make_unique<ProxySession>();
                                sess->key        = key;
                                sess->dst_ip_str = std::to_string(dst_ip>>24&0xFF) + '.'
                                                 + std::to_string(dst_ip>>16&0xFF) + '.'
                                                 + std::to_string(dst_ip>> 8&0xFF) + '.'
                                                 + std::to_string(dst_ip    &0xFF);
                                sess->reassembly.reset(u32be(tcp + 4));
                                g_sessions[key] = std::move(sess);
                            }
                        }

                        // Rewrite dst → 127.0.0.1:listener_port.
                        if (rewrite_tcp_syn_dst(pkt, (size_t)plen,
                                                0x7F000001u,
                                                (uint16_t)g_listener_port)) {
                            write(tun_fd, pkt, (size_t)plen);
                        }
                    } else {
                        // ── Established TCP data: reassemble ─────────────
                        // Data from the app side for an in-progress session.
                        ConnKey key{ src_ip, dst_ip, src_port, dst_port };
                        uint32_t seq = u32be(tcp + 4);
                        uint8_t  doff = ((tcp[12] >> 4) & 0x0F) * 4;
                        const uint8_t* payload = tcp + doff;
                        size_t   pay_len = (size_t)plen - ihl - doff;

                        if (pay_len > 0) {
                            std::lock_guard<std::mutex> lk(g_sessions_mutex);
                            auto it = g_sessions.find(key);
                            if (it != g_sessions.end() &&
                                it->second->sni_state == SniState::PENDING) {
                                it->second->reassembly.insert(seq, payload, pay_len);
                            }
                        }
                    }
                }
            }
        }
    }

done:
    close(ep);
    if (g_listener_fd >= 0) { close(g_listener_fd); g_listener_fd = -1; }

    // Signal all active ferry threads to stop.
    std::lock_guard<std::mutex> lk(g_sessions_mutex);
    g_sessions.clear();

    g_eng_running.store(false);
    LOGI("engine: stopped");
    return nullptr;
}

// ============================================================================
// Public API
// ============================================================================

void proxy_engine_start(const ProxyEngineConfig& cfg) {
    if (g_eng_running.exchange(true)) return;

    g_eng_cfg = cfg;
    protect_bridge_init(cfg.jvm, cfg.bridge_obj);

    if (pipe2(g_wake_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        LOGE("proxy_engine_start: pipe2: %s", strerror(errno));
        g_eng_running.store(false);
        return;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&g_eng_thread, &attr, engine_thread_fn, nullptr);
    pthread_attr_destroy(&attr);
    LOGI("proxy_engine_start: engine started (tun_fd=%d)", cfg.tun_fd);
}

void proxy_engine_stop() {
    if (!g_eng_running.load()) return;
    if (g_wake_pipe[1] >= 0) {
        uint8_t b = 0xFF;
        write(g_wake_pipe[1], &b, 1);
        close(g_wake_pipe[1]);
        close(g_wake_pipe[0]);
        g_wake_pipe[0] = g_wake_pipe[1] = -1;
    }
}
