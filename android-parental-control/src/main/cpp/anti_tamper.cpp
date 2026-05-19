/**
 * anti_tamper.cpp  —  v2
 *
 * Replaces the CRC-32 central-directory check with a SHA-256 hash of the
 * raw classes.dex bytes as stored inside the APK.
 *
 * Why SHA-256 over CRC-32
 * ────────────────────────
 * CRC-32 is a linear code: an attacker can compute a 4-byte suffix to append
 * to a modified classes.dex that produces exactly the original CRC — a trivial
 * collision.  SHA-256 has no known practical collision attack; forging a
 * matching hash requires ~2¹²⁸ operations under current cryptanalysis.
 *
 * What is hashed
 * ──────────────
 * The bytes of the "classes.dex" local file entry as stored in the ZIP
 * (compressed or STORED, depending on the build toolchain).  This is the
 * same byte range that APK Signature Scheme v2/v3 covers, so any
 * unauthorised modification to the bytecode will change the hash.
 *
 * Embedded SHA-256
 * ─────────────────
 * A self-contained, pure-C++ SHA-256 implementation is included below —
 * no OpenSSL, no Bouncy Castle, no external dependency of any kind.
 * The algorithm follows FIPS PUB 180-4.
 *
 * Usage
 * ─────
 * After building a release APK, extract the expected hash:
 *
 *   python3 - <<'EOF'
 *   import hashlib, zipfile, sys
 *   with zipfile.ZipFile(sys.argv[1]) as z:
 *       data = z.read('classes.dex')
 *   print(hashlib.sha256(data).hexdigest())
 *   EOF release.apk
 *
 * Copy the hex output, split into 8 × uint32_t words (big-endian), and
 * replace EXPECTED_DEX_SHA256 below.  Rebuild and re-sign the APK before
 * extracting the hash for production — the signing process may alter DEX
 * alignment.
 *
 * Target: Android 15 / NDK r27+, C++17, no exceptions.
 */

#include "include/anti_tamper.h"

#include <android/log.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>

#define LOG_TAG "AntiTamper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

// ============================================================================
// Embedded SHA-256  (FIPS 180-4, no external dependencies)
// ============================================================================

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t SHA256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

struct Sha256Ctx {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t total_bits;
    uint32_t buf_used;
};

static void sha256_init(Sha256Ctx* ctx) {
    memcpy(ctx->h, SHA256_H0, sizeof(SHA256_H0));
    ctx->total_bits = 0;
    ctx->buf_used   = 0;
}

static void sha256_process_block(Sha256Ctx* ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i*4+0] << 24)
             | ((uint32_t)block[i*4+1] << 16)
             | ((uint32_t)block[i*4+2] <<  8)
             | ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i- 2], 17) ^ rotr32(w[i- 2], 19) ^ (w[i- 2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a=ctx->h[0], b=ctx->h[1], c=ctx->h[2], d=ctx->h[3],
             e=ctx->h[4], f=ctx->h[5], g=ctx->h[6], h=ctx->h[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1    = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch    = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0    = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h=g; g=f; f=e; e=d+temp1;
        d=c; c=b; b=a; a=temp1+temp2;
    }

    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d;
    ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}

static void sha256_update(Sha256Ctx* ctx, const uint8_t* data, size_t len) {
    ctx->total_bits += (uint64_t)len * 8;
    while (len > 0) {
        uint32_t space = 64 - ctx->buf_used;
        uint32_t take  = (len < space) ? (uint32_t)len : space;
        memcpy(ctx->buf + ctx->buf_used, data, take);
        ctx->buf_used += take;
        data          += take;
        len           -= take;
        if (ctx->buf_used == 64) {
            sha256_process_block(ctx, ctx->buf);
            ctx->buf_used = 0;
        }
    }
}

static void sha256_final(Sha256Ctx* ctx, uint8_t out[32]) {
    // Append 0x80 bit.
    ctx->buf[ctx->buf_used++] = 0x80;
    if (ctx->buf_used > 56) {
        memset(ctx->buf + ctx->buf_used, 0, 64 - ctx->buf_used);
        sha256_process_block(ctx, ctx->buf);
        ctx->buf_used = 0;
    }
    memset(ctx->buf + ctx->buf_used, 0, 56 - ctx->buf_used);
    // Append 64-bit big-endian bit count.
    uint64_t tb = ctx->total_bits;
    for (int i = 7; i >= 0; --i) { ctx->buf[56 + i] = (uint8_t)(tb & 0xFF); tb >>= 8; }
    sha256_process_block(ctx, ctx->buf);
    // Output in big-endian.
    for (int i = 0; i < 8; ++i) {
        out[i*4+0] = (uint8_t)(ctx->h[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->h[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->h[i] >>  8);
        out[i*4+3] = (uint8_t)(ctx->h[i]       );
    }
}

/** Hash an arbitrary byte buffer and store 32 digest bytes in out[]. */
static void sha256_buffer(const uint8_t* data, size_t len, uint8_t out[32]) {
    Sha256Ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/** Stream-hash a file section without loading it entirely into RAM. */
static bool sha256_file_section(FILE* f, long offset, size_t len, uint8_t out[32]) {
    if (fseek(f, offset, SEEK_SET) != 0) return false;

    Sha256Ctx ctx;
    sha256_init(&ctx);

    uint8_t  chunk[8192];
    size_t   remaining = len;
    while (remaining > 0) {
        size_t  n = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
        if (fread(chunk, 1, n, f) != n) return false;
        sha256_update(&ctx, chunk, n);
        remaining -= n;
    }
    sha256_final(&ctx, out);
    return true;
}

// ============================================================================
// *** REPLACE THIS WITH THE REAL VALUE FROM YOUR RELEASE BUILD ***
//
// python3 - <<'EOF'
// import hashlib, zipfile, sys
// with zipfile.ZipFile(sys.argv[1]) as z:
//     data = z.read('classes.dex')
// digest = hashlib.sha256(data).digest()
// words  = [int.from_bytes(digest[i:i+4],'big') for i in range(0,32,4)]
// print(','.join(f'0x{w:08x}' for w in words))
// EOF release.apk
// ============================================================================
static const uint32_t EXPECTED_DEX_SHA256[8] = {
    0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF,
    0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF
};

// ============================================================================
// ZIP parsing helpers (needed to locate classes.dex inside the APK)
// ============================================================================

static inline uint16_t le16(const uint8_t* p) { return (uint16_t)(p[0] | p[1]<<8); }
static inline uint32_t le32(const uint8_t* p) { return (uint32_t)(p[0]|p[1]<<8|p[2]<<16|p[3]<<24); }

static constexpr uint32_t EOCD_SIG        = 0x06054b50;
static constexpr uint32_t CD_SIG          = 0x02014b50;
static constexpr uint32_t LOCAL_HDR_SIG   = 0x04034b50;

static bool find_eocd(FILE* f, uint32_t& cd_offset, uint32_t& cd_size) {
    if (fseek(f, 0, SEEK_END) != 0) return false;
    long file_size = ftell(f);
    if (file_size < 22) return false;

    long search_start = file_size - 22 - 65535;
    if (search_start < 0) search_start = 0;
    long search_len = file_size - search_start;

    std::vector<uint8_t> buf((size_t)search_len);
    fseek(f, search_start, SEEK_SET);
    if (fread(buf.data(), 1, buf.size(), f) != buf.size()) return false;

    for (long i = (long)buf.size() - 22; i >= 0; --i) {
        if (le32(buf.data() + i) == EOCD_SIG) {
            cd_size   = le32(buf.data() + i + 12);
            cd_offset = le32(buf.data() + i + 16);
            return true;
        }
    }
    return false;
}

/** Find classes.dex in the central directory.
 *  Returns true and populates local_hdr_off + compressed_size on success. */
static bool find_dex_entry(FILE* f, uint32_t cd_offset, uint32_t cd_size,
                            uint32_t& local_hdr_off, uint32_t& comp_size) {
    static const char* TARGET = "classes.dex";
    const size_t TARGET_LEN   = strlen(TARGET);

    if (fseek(f, (long)cd_offset, SEEK_SET) != 0) return false;
    std::vector<uint8_t> cd(cd_size);
    if (fread(cd.data(), 1, cd_size, f) != cd_size) return false;

    size_t pos = 0;
    while (pos + 46 <= cd_size) {
        if (le32(cd.data() + pos) != CD_SIG) break;

        uint16_t name_len  = le16(cd.data() + pos + 28);
        uint16_t extra_len = le16(cd.data() + pos + 30);
        uint16_t comm_len  = le16(cd.data() + pos + 32);
        uint32_t entry_cs  = le32(cd.data() + pos + 20);  // compressed size
        uint32_t lhdr_off  = le32(cd.data() + pos + 42);

        if (pos + 46 + name_len <= cd_size
            && name_len == TARGET_LEN
            && memcmp(cd.data() + pos + 46, TARGET, TARGET_LEN) == 0) {
            comp_size     = entry_cs;
            local_hdr_off = lhdr_off;
            (void)entry_cs;
            return true;
        }

        pos += 46 + name_len + extra_len + comm_len;
    }
    return false;
}

/** Resolve the absolute file offset of the data section for a local entry. */
static bool resolve_data_offset(FILE* f, uint32_t local_hdr_off, long& data_offset) {
    if (fseek(f, (long)local_hdr_off, SEEK_SET) != 0) return false;

    uint8_t hdr[30];
    if (fread(hdr, 1, 30, f) != 30) return false;
    if (le32(hdr) != LOCAL_HDR_SIG) return false;

    uint16_t name_len  = le16(hdr + 26);
    uint16_t extra_len = le16(hdr + 28);
    data_offset = (long)local_hdr_off + 30 + name_len + extra_len;
    return true;
}

// ============================================================================
// Public API
// ============================================================================

bool verify_dex_crc32(const char* apk_path) {
    // Function name kept for ABI compatibility with anti_tamper.h.
    // Internally it now computes SHA-256 over the classes.dex data bytes.

    if (!apk_path || apk_path[0] == '\0') {
        LOGE("verify_dex_integrity: null apk_path");
        return false;
    }

    FILE* f = fopen(apk_path, "rb");
    if (!f) {
        LOGE("verify_dex_integrity: fopen('%s'): %s", apk_path, strerror(errno));
        return false;
    }

    uint32_t cd_offset = 0, cd_size = 0;
    if (!find_eocd(f, cd_offset, cd_size)) {
        LOGE("verify_dex_integrity: EOCD not found");
        fclose(f); return false;
    }

    uint32_t local_hdr_off = 0, comp_size = 0;
    if (!find_dex_entry(f, cd_offset, cd_size, local_hdr_off, comp_size)) {
        LOGE("verify_dex_integrity: 'classes.dex' not found in APK");
        fclose(f); return false;
    }

    long data_offset = 0;
    if (!resolve_data_offset(f, local_hdr_off, data_offset)) {
        LOGE("verify_dex_integrity: could not resolve local header");
        fclose(f); return false;
    }

    // Stream-hash the classes.dex bytes (compressed or STORED).
    uint8_t actual[32];
    if (!sha256_file_section(f, data_offset, comp_size, actual)) {
        LOGE("verify_dex_integrity: hash I/O error");
        fclose(f); return false;
    }
    fclose(f);

    // Reconstruct expected digest from the 8 × uint32_t constant.
    uint8_t expected[32];
    for (int i = 0; i < 8; ++i) {
        expected[i*4+0] = (uint8_t)(EXPECTED_DEX_SHA256[i] >> 24);
        expected[i*4+1] = (uint8_t)(EXPECTED_DEX_SHA256[i] >> 16);
        expected[i*4+2] = (uint8_t)(EXPECTED_DEX_SHA256[i] >>  8);
        expected[i*4+3] = (uint8_t)(EXPECTED_DEX_SHA256[i]      );
    }

    // Constant-time comparison — prevents timing oracle on the digest.
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= actual[i] ^ expected[i];

    if (diff != 0) {
        LOGW("verify_dex_integrity: SHA-256 MISMATCH — tampering detected");
        char actual_hex[65];
        for (int i = 0; i < 32; ++i)
            snprintf(actual_hex + i*2, 3, "%02x", actual[i]);
        LOGW("verify_dex_integrity: actual   = %s", actual_hex);
        return false;
    }

    LOGI("verify_dex_integrity: SHA-256 OK");
    return true;
}
