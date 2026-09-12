#ifndef FASTPARSE_SIMD_H
#define FASTPARSE_SIMD_H

#include <emmintrin.h>  // for SSE2 intrinsics (__m128i, _mm_cmple_epi8, etc.)
#include "pulsar.h"

/* ------------------------------------------------------------------
 * Request-line layout constants.
 * ------------------------------------------------------------------ */

/** Minimum bytes required for the smallest valid request line, "GET / HTTP/1.1\r\n". */
#define MIN_REQUEST_LINE_LEN 16u

/** Length of "HTTP/1.x\r\n" (protocol token + CRLF), verified after the URL. */
#define PROTOCOL_SUFFIX_LEN 10u

/** SIMD scan width: SSE2 processes 16 bytes per compare. */
#define SIMD_CHUNK_BYTES 16

/* ------------------------------------------------------------------
 * Little-endian byte-string signatures used for branch-free method and
 * protocol matching. Each name encodes the literal bytes it matches and,
 * where relevant, the mask applied before comparison.
 * ------------------------------------------------------------------ */

/** First 8 bytes of "GET / HT" — the GET-root-path superfast-path prefix. */
#define SIG_GET_ROOT_PREFIX_8 UINT64_C(0x5448202F20544547)

/** Bytes 8-15 of "GET / HTTP/1.1\r\n" — "TP/1.1\r\n". */
#define SIG_GET_ROOT_SUFFIX_8 UINT64_C(0x0A0D312E312F5054)

/** "GET " as a 32-bit little-endian word. */
#define SIG_METHOD_GET_4 UINT32_C(0x20544547)

/** req->method payload for GET: "GET\0" packed into 4 bytes. */
#define METHOD_BYTES_GET_4 UINT32_C(0x00544547)

/** Mask isolating the low 5 bytes of a 64-bit word (for 5-byte method + space). */
#define MASK_LOW_5_BYTES UINT64_C(0xFFFFFFFFFF)

/** "POST " masked to 5 bytes, as a 64-bit little-endian word. */
#define SIG_METHOD_POST_5 UINT64_C(0x2054534F50)

/** req->method payload for POST: "POST\0\0\0\0" packed into 8 bytes. */
#define METHOD_BYTES_POST_8 UINT64_C(0x00000054534F50)

/** "HEAD " masked to 5 bytes, as a 64-bit little-endian word. */
#define SIG_METHOD_HEAD_5 UINT64_C(0x2044414548)

/** req->method payload for HEAD: "HEAD\0\0\0\0" packed into 8 bytes. */
#define METHOD_BYTES_HEAD_8 UINT64_C(0x00000044414548)

/** "PUT " as a 32-bit little-endian word. */
#define SIG_METHOD_PUT_4 UINT32_C(0x20545550)

/** req->method payload for PUT: "PUT\0" packed into 4 bytes. */
#define METHOD_BYTES_PUT_4 UINT32_C(0x00545550)

/** Mask isolating the low 7 bytes of a 64-bit word (for 7-byte method + space). */
#define MASK_LOW_7_BYTES UINT64_C(0x00FFFFFFFFFFFFFF)

/** "DELETE " masked to 7 bytes, as a 64-bit little-endian word. */
#define SIG_METHOD_DELETE_7 UINT64_C(0x00204554454C4544)

/** req->method payload for DELETE: "DELETE\0" packed into 8 bytes. */
#define METHOD_BYTES_DELETE_8 UINT64_C(0x004554454C4544)

/** "OPTIONS " as a full 64-bit little-endian word (8 significant bytes). */
#define SIG_METHOD_OPTIONS_8 UINT64_C(0x20534E4F4954504F)

/** req->method payload for OPTIONS: "OPTIONS\0" literal (8 bytes incl. NUL). */
#define METHOD_BYTES_OPTIONS_8 "OPTIONS\0"

/** "HTTP/1." + '1' — first 8 bytes of the HTTP/1.1 protocol token. */
#define SIG_PROTO_HTTP_1_1_8 UINT64_C(0x312E312F50545448)

/** "HTTP/1." + '0' — first 8 bytes of the HTTP/1.0 protocol token. */
#define SIG_PROTO_HTTP_1_0_8 UINT64_C(0x302E312F50545448)

/** Trailing "\r\n" as a 16-bit little-endian word. */
#define SIG_CRLF_2 UINT16_C(0x0A0D)

/** memchr search window for the fallback (unrecognized) method name. */
#define UNKNOWN_METHOD_SEARCH_WINDOW 8

/**
 * Scans forward from ptr (which may run past `end`) for the first byte
 * that is <= ' ' (space or a control character), using 16-byte SSE2
 * compares instead of a scalar byte loop.
 *
 * @param ptr Start of the scan region. Caller guarantees it is safe to
 *            read up to 15 bytes past the true end (the caller's buffer
 *            must have that slack, e.g. a fixed-size read buffer).
 * @param end Logical end of valid input; the returned pointer is clamped
 *            to be <= end.
 * @return Pointer to the first byte <= ' ', or `end` if none was found
 *         within the buffer.
 */
static inline const char* simd_scan_url_end(const char* ptr, const char* end) {
    /* Bias trick: bytes <= ' ' (0x20) map to a value <= 0 after subtracting
     * 0x21 in signed 8-bit arithmetic wraps large, so instead we compare
     * unsigned by biasing into signed range. Simpler: use the standard
     * "find first byte <= threshold" idiom via saturated unsigned min. */
    const __m128i threshold = _mm_set1_epi8(' '); /* Broadcast ' ' (0x20). */
    const char* p = ptr;

    while (p + SIMD_CHUNK_BYTES <= end) {
        __m128i chunk = _mm_loadu_si128((const __m128i*)p);
        /* _mm_min_epu8 gives, per byte, min(chunk, threshold). Where
         * chunk[i] <= ' ', the min equals chunk[i]; otherwise it equals
         * threshold. XOR against threshold yields zero exactly where
         * chunk[i] <= ' ' (space or control char), nonzero elsewhere. */
        __m128i m = _mm_min_epu8(chunk, threshold);
        __m128i eq = _mm_cmpeq_epi8(m, chunk);
        int mask = _mm_movemask_epi8(eq);
        if (mask != 0) {
            int idx = __builtin_ctz((unsigned)mask);
            const char* found = p + idx;
            return found < end ? found : end;
        }
        p += SIMD_CHUNK_BYTES;
    }

    /* Scalar tail for the remaining < 16 bytes. */
    while (p < end && (unsigned char)*p > ' ') {
        p++;
    }
    return p;
}

/**
 * Variant of parse_request_line that replaces the scalar URL-terminator
 * scan with an SSE2 16-byte-at-a-time scan. All other logic (method
 * dispatch, GET / superfast path, protocol check) is unchanged.
 *
 * @warning The input buffer must have at least 15 bytes of readable slack past
 *          input_len (true of any fixed-size recv() buffer with room
 *          to spare, but not of a tightly-sized heap allocation).
 */
INLINE int parse_request_line_simd(const char* input, size_t input_len, request_t* req,
                                   const char** url_ptr, size_t* url_len, const char** line_end) {
    if (unlikely(input_len < MIN_REQUEST_LINE_LEN)) return -1;

    uint64_t w0, w1;
    memcpy(&w0, input, 8);
    memcpy(&w1, input + 8, 8);
    if (likely(w0 == SIG_GET_ROOT_PREFIX_8 && w1 == SIG_GET_ROOT_SUFFIX_8)) {
        req->method_type = HTTP_GET;
        *(uint32_t*)req->method = METHOD_BYTES_GET_4;
        *url_ptr = input + 4;
        *url_len = 1;
        *line_end = input + MIN_REQUEST_LINE_LEN;
        return 1;
    }

    uint64_t m8 = w0;
    const char* ptr;

    if (likely((uint32_t)m8 == SIG_METHOD_GET_4)) {
        req->method_type = HTTP_GET;
        *(uint32_t*)req->method = METHOD_BYTES_GET_4;
        ptr = input + 4;
    } else if (likely((m8 & MASK_LOW_5_BYTES) == SIG_METHOD_POST_5)) {
        req->method_type = HTTP_POST;
        *(uint64_t*)req->method = METHOD_BYTES_POST_8;
        ptr = input + 5;
    } else if ((m8 & MASK_LOW_5_BYTES) == SIG_METHOD_HEAD_5) {
        req->method_type = HTTP_HEAD;
        *(uint64_t*)req->method = METHOD_BYTES_HEAD_8;
        ptr = input + 5;
    } else if ((uint32_t)m8 == SIG_METHOD_PUT_4) {
        req->method_type = HTTP_PUT;
        *(uint32_t*)req->method = METHOD_BYTES_PUT_4;
        ptr = input + 4;
    } else if ((m8 & MASK_LOW_7_BYTES) == SIG_METHOD_DELETE_7) {
        req->method_type = HTTP_DELETE;
        *(uint64_t*)req->method = METHOD_BYTES_DELETE_8;
        ptr = input + 7;
    } else if (m8 == SIG_METHOD_OPTIONS_8) {
        req->method_type = HTTP_OPTIONS;
        memcpy(req->method, METHOD_BYTES_OPTIONS_8, 8);
        ptr = input + 8;
    } else {
        const char* sp = (const char*)memchr(input, ' ', UNKNOWN_METHOD_SEARCH_WINDOW);
        if (!sp) return -1;
        size_t mlen = (size_t)(sp - input);
        if (mlen >= sizeof(req->method)) return -1;
        memcpy(req->method, input, mlen);
        req->method[mlen] = '\0';
        req->method_type = http_method_from_string(req->method, mlen);
        ptr = sp + 1;
    }

    const char* const end = input + input_len;

    if (likely(ptr[0] == '/' && ptr[1] == ' ')) {
        const char* proto = ptr + 2;
        if (unlikely((size_t)(end - proto) < PROTOCOL_SUFFIX_LEN)) return -1;

        uint64_t h1;
        uint16_t h2;
        memcpy(&h1, proto, 8);
        memcpy(&h2, proto + 8, 2);

        if (likely(h1 == SIG_PROTO_HTTP_1_1_8 && h2 == SIG_CRLF_2)) {
            *url_ptr = ptr;
            *url_len = 1;
            *line_end = proto + PROTOCOL_SUFFIX_LEN;
            return 0;
        }
    }

    /* SIMD scan replaces the scalar while-loop here. */
    const char* sp = simd_scan_url_end(ptr, end);

    if (unlikely(sp >= end || *sp != ' ')) return -1;

    *url_ptr = ptr;
    *url_len = (size_t)(sp - ptr);

    const char* proto = sp + 1;
    if (unlikely((size_t)(end - proto) < PROTOCOL_SUFFIX_LEN)) return -1;

    uint64_t h1;
    uint16_t h2;
    memcpy(&h1, proto, 8);
    memcpy(&h2, proto + 8, 2);

    if (likely(h1 == SIG_PROTO_HTTP_1_1_8 && h2 == SIG_CRLF_2)) {
        *line_end = proto + PROTOCOL_SUFFIX_LEN;
        return 0;
    }

    if (unlikely(h1 == SIG_PROTO_HTTP_1_0_8 && h2 == SIG_CRLF_2)) {
        *line_end = proto + PROTOCOL_SUFFIX_LEN;
        return 0;
    }

    return -1;
}

// percent-decode the URL into destination buffer.
INLINE size_t decode_path_fast(const char* restrict url, size_t url_len, char* restrict dest,
                               size_t dest_cap) {
    if (url_len >= dest_cap) url_len = dest_cap - 1;
    size_t i = 0;
    for (; i < url_len; i++) {
        const char c = url[i];
        if (c == '%' || c == '+') break;
    }
    if (i == url_len) {
        memcpy(dest, url, url_len);
        dest[url_len] = '\0';
        return url_len;
    }
    return url_percent_decode(url, dest, url_len, dest_cap);
}

#ifndef FIND_HEADERS_END_H
#define FIND_HEADERS_END_H

#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint32_t, UINT32_C
#include <string.h>  // for memcpy

#if defined(__AVX2__)
#include <immintrin.h>  // for __m256i AVX2 intrinsics
#elif defined(__SSE2__)
#include <emmintrin.h>  // for __m128i SSE2 intrinsics
#endif

#ifndef INLINE
#define INLINE static inline
#endif
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/** Terminating sequence "\r\n\r\n" packed little-endian into a 32-bit word. */
#define HEADERS_END_PATTERN UINT32_C(0x0a0d0a0d)

/** Minimum bytes needed to hold "\r\n\r\n" itself. */
#define HEADERS_END_PATTERN_LEN 4u

/** AVX2 scan width: 32 bytes per compare. */
#define SIMD_CHUNK_BYTES_AVX2 32
/** SSE2 scan width: 16 bytes per compare. */
#define SIMD_CHUNK_BYTES_SSE2 16

/*
 * Finds the FIRST occurrence of "\r\n\r\n" (0x0a0d0a0d in LE).
 * Returns pointer to the start of "\r\n\r\n", or NULL if not found.
 * Uses inlined vector operations (AVX2 where available, else SSE2) to
 * eliminate libc memchr call overhead and PLT dispatch on small HTTP
 * header blocks.
 *
 * @param buf Buffer to search. Only bytes [0, len) are read; no overread
 *            past `len` occurs (each candidate is bounds-checked against
 *            `end` before its verifying 4-byte read).
 * @param len Number of valid bytes in buf.
 * @return Pointer to the start of "\r\n\r\n" within buf, or NULL if the
 *         full 4-byte sequence does not occur.
 */
INLINE const char* find_headers_end_simd(const char* buf, size_t len) {
    if (unlikely(len < HEADERS_END_PATTERN_LEN)) return NULL;
    const char* const end = buf + len - (HEADERS_END_PATTERN_LEN - 1);
    const char* p = buf;

#if defined(__AVX2__)
    const __m256i cr32 = _mm256_set1_epi8('\r');
    while (p + SIMD_CHUNK_BYTES_AVX2 <= buf + len) {
        __m256i chunk = _mm256_loadu_si256((const __m256i*)p);
        __m256i cmp = _mm256_cmpeq_epi8(chunk, cr32);
        unsigned int mask = (unsigned int)_mm256_movemask_epi8(cmp);

        while (mask) {
            int idx = __builtin_ctz(mask);
            const char* cand = p + idx;
            if (cand < end) {
                uint32_t v;
                memcpy(&v, cand, HEADERS_END_PATTERN_LEN);
                if (v == HEADERS_END_PATTERN) return cand;
            }
            mask &= mask - 1;
        }
        p += SIMD_CHUNK_BYTES_AVX2;
    }
#endif

#if defined(__SSE2__)
    const __m128i cr16 = _mm_set1_epi8('\r');
    while (p + SIMD_CHUNK_BYTES_SSE2 <= buf + len) {
        __m128i chunk = _mm_loadu_si128((const __m128i*)p);
        __m128i cmp = _mm_cmpeq_epi8(chunk, cr16);
        unsigned int mask = (unsigned int)_mm_movemask_epi8(cmp);

        while (mask) {
            int idx = __builtin_ctz(mask);
            const char* cand = p + idx;
            if (cand < end) {
                uint32_t v;
                memcpy(&v, cand, HEADERS_END_PATTERN_LEN);
                if (v == HEADERS_END_PATTERN) return cand;
            }
            mask &= mask - 1;
        }
        p += SIMD_CHUNK_BYTES_SSE2;
    }
#endif

    while (p < end) {
        if (*p == '\r') {
            uint32_t v;
            memcpy(&v, p, HEADERS_END_PATTERN_LEN);
            if (v == HEADERS_END_PATTERN) return p;
        }
        p++;
    }

    return NULL;
}

#endif

// ================ Fast ascii to integer parser =======================

static const uint64_t POW10_V2[9] = {
    1ULL, 10ULL, 100ULL, 1000ULL, 10000ULL, 100000ULL, 1000000ULL, 10000000ULL, 100000000ULL,
};

INLINE uint64_t parse_up_to_8_digits_v2(uint64_t v, int k) {
    v -= 0x3030303030303030ULL;
    v <<= (8 - k) * 8;
    v = (v * 10) + (v >> 8);
    uint64_t t = v & 0x00FF00FF00FF00FFULL;
    v = (t * 100) + (t >> 16);
    v &= 0x0000FFFF0000FFFFULL;
    v = (v * 10000) + (v >> 32);
    return (uint32_t)v;
}

/*
 * Safely loads up to 8 bytes from str into a little-endian uint64_t,
 * without calling memcpy for the boundary case. When len >= 8 this is a
 * single load; when len < 8, it loads 8 bytes starting from a position
 * that is guaranteed in-bounds for any buffer with the input's tail
 * still readable up to the previous 8-byte-aligned read, OR falls back
 * to a masked byte-by-byte build for len < 8 without any function call.
 *
 * We use the branch-free masked-shift approach: read individual bytes
 * with a jump table-free switch is still branchy, so instead we accept
 * a small unrolled load using an 8-byte "safe window" trick common in
 * SIMD-JSON-style parsers: read the last possible aligned 8 bytes and
 * shift. This requires the caller's buffer to have at least 8 bytes of
 * *any* readable memory from `str` (true for typical arena/recv buffers
 * with slack) OR we fall back to per-byte loop for small, tight buffers.
 *
 * For a general-purpose library function (unknown buffer slack), we use
 * the safest option: an unrolled switch that reads exactly `len` bytes
 * with no function call and no over-read.
 */
INLINE uint64_t load_le_bytes_safe(const char* str, size_t len) {
    uint64_t v = 0;
    switch (len) {
        case 7:
            v |= (uint64_t)(uint8_t)str[6] << 48; /* fallthrough */
        case 6:
            v |= (uint64_t)(uint8_t)str[5] << 40; /* fallthrough */
        case 5:
            v |= (uint64_t)(uint8_t)str[4] << 32; /* fallthrough */
        case 4:
            v |= (uint64_t)(uint8_t)str[3] << 24; /* fallthrough */
        case 3:
            v |= (uint64_t)(uint8_t)str[2] << 16; /* fallthrough */
        case 2:
            v |= (uint64_t)(uint8_t)str[1] << 8; /* fallthrough */
        case 1:
            v |= (uint64_t)(uint8_t)str[0]; /* fallthrough */
        case 0:
            break;
    }
    return v;
}

/*
 * Fast ASCII to Uint64 parser.
 */
INLINE uint64_t fast_atou64(const char* str, size_t len) {
    uint64_t val = 0;
    int first = 1;

    while (len > 0) {
        uint64_t v;

        if (likely(len >= 8)) {
            memcpy(&v, str, 8);
        } else {
            v = load_le_bytes_safe(str, len);
        }

        uint64_t t1 = v - 0x3030303030303030ULL;
        uint64_t t2 = v + 0x4646464646464646ULL;
        uint64_t mask = (t1 | t2) & 0x8080808080808080ULL;

        int digits = mask ? (__builtin_ctzll(mask) >> 3) : 8;
        if (digits > (int)len) digits = (int)len;

        if (unlikely(digits == 0)) break;

        uint64_t chunk = parse_up_to_8_digits_v2(v, digits);

        /* Skip the multiply-by-POW10 entirely on the first chunk: since
         * val is still 0, val*POW10[digits]+chunk == chunk. This is the
         * common case for any number <= 8 digits (ports, small IDs,
         * short counters), which covers the overwhelming majority of
         * real-world integer fields. */
        if (likely(first)) {
            val = chunk;
            first = 0;
        } else {
            val = val * POW10_V2[digits] + chunk;
        }

        if (digits < 8) break;

        str += 8;
        len -= 8;
    }

    return val;
}

// ===================== Parsing request headers ======================
INLINE bool match_connection(const char* s) {
    uint64_t a;
    uint16_t b;
    memcpy(&a, s, 8);
    memcpy(&b, s + 8, 2);
    return ((a | UINT64_C(0x2020202020202020)) == UINT64_C(0x697463656e6e6f63)) &&
           ((uint16_t)(b | UINT16_C(0x2020)) == UINT16_C(0x6e6f));
}

INLINE bool match_content_length(const char* s) {
    uint64_t a, b = 0;
    memcpy(&a, s, 8);
    memcpy(&b, s + 8, 6);
    return ((a | UINT64_C(0x2020202020202020)) == UINT64_C(0x2d746e65746e6f63)) &&
           (((b | UINT64_C(0x2020202020202020)) & UINT64_C(0x0000ffffffffffff)) ==
            UINT64_C(0x00006874676e656c));
}

INLINE http_status parse_request_headers(PulsarConn* conn, const char* hdrs, HttpMethod method,
                                         size_t headers_len) {
    const char* ptr = hdrs;
    const char* const end = ptr + headers_len;
    const bool is_safe = SAFE_METHOD(method);
    request_t* req = &conn->request;
    conn->keep_alive = true;
    uint8_t flags = 0;

    while (ptr < end) {
        /* Instant check for final empty line (\r\n) */
        if (unlikely(ptr[0] == '\r')) {
            if (likely(ptr + 1 < end && ptr[1] == '\n')) ptr += 2;
            break;
        }

        /* Fast inline scan for ':'
         * HTTP header names cannot contain whitespace or control chars.
         * Almost all header names finish in under 16 bytes. */
        const char* colon = ptr;
        while (colon < end && (unsigned char)*colon > ' ' && *colon != ':') {
            colon++;
        }

        if (unlikely(colon >= end || *colon != ':')) {
            /* Malformed header line: skip using memchr */
            const char* eol = (const char*)memchr(ptr, '\r', (size_t)(end - ptr));
            if (!eol || eol + 1 >= end || eol[1] != '\n') break;
            ptr = eol + 2;
            continue;
        }

        const size_t name_len = (size_t)(colon - ptr);
        if (unlikely(name_len == 0)) return StatusBadRequest;

        /* ONLY ONE memchr per line: scan for \r in the value */
        const char* const eol = (const char*)memchr(colon + 1, '\r', (size_t)(end - (colon + 1)));
        if (unlikely(!eol || eol + 1 >= end || eol[1] != '\n')) break;

        /* Value extraction & trimming */
        const char* value_start = colon + 1;
        while (value_start < eol && (*value_start == ' ' || *value_start == '\t')) value_start++;

        const char* value_end = eol;
        while (value_end > value_start && (value_end[-1] == ' ' || value_end[-1] == '\t'))
            value_end--;
        const size_t value_len = (size_t)(value_end - value_start);

        /* Push header */
        if (!headers_push(&req->headers, (StrSlice){.data = ptr, .len = name_len},
                          (StrSlice){.data = value_start, .len = value_len})) {
            return StatusRequestHeaderFieldsTooLarge;
        }

        /* Header matching (unchanged) */
        const char fc = (char)(ptr[0] | 0x20);

        if (fc == 'r' && name_len == 5 && req->range_hdr.data == NULL) {
            uint64_t w = 0;
            memcpy(&w, ptr, 5);
            if (((w | UINT64_C(0x2020202020202020)) & UINT64_C(0x000000ffffffffff)) ==
                UINT64_C(0x00000065676e6172)) {
                req->range_hdr = (StrSlice){.data = value_start, .len = value_len};
            }
        }

        if (fc == 'c') {
            if (!is_safe && name_len == 14 && !(flags & 1)) {
                if (match_content_length(ptr)) {
                    req->content_length = (size_t)fast_atou64(value_start, value_len);
                    flags |= 1;
                }
            } else if (name_len == 10 && !(flags & 2)) {
                if (match_connection(ptr)) {
                    uint64_t w = 0;
                    if (value_len == 5) memcpy(&w, value_start, 5);
                    conn->keep_alive =
                        !((value_len == 5) &&
                          (((w | UINT64_C(0x2020202020202020)) & UINT64_C(0x000000ffffffffff)) ==
                           UINT64_C(0x00000065736f6c63)));
                    flags |= 2;
                }
            }
        }

        ptr = eol + 2;
    }

    return StatusOK;
}

//  =============== Parsing Query Params ==========================
INLINE http_status parse_query_params(PulsarConn* conn, size_t* path_len) {
    ASSERT(conn && path_len);

    char* const path = conn->request.path;
    const size_t orig_len = *path_len;
    char* const query = memchr(path, '?', orig_len);

    // No Query Params (not an error)
    if (!query) {
        return StatusOK;
    }

    // Trim '?' from URL to get clean path and update path_len
    *query = '\0';
    *path_len = (size_t)(query - path);

    const char* ptr = query + 1;
    const char* const end = path + orig_len;

    while (ptr < end) {
        // Scan Key (stops at '=' or '&' or end)
        const char* const key_start = ptr;
        while (ptr < end && *ptr != '=' && *ptr != '&') {
            ptr++;
        }
        StrSlice key = {.data = key_start, .len = (size_t)(ptr - key_start)};
        StrSlice value = {.data = ptr, .len = 0};

        // Scan Value (if '=' is present)
        if (ptr < end && *ptr == '=') {
            ptr++;  // Skip '='
            const char* const val_start = ptr;
            while (ptr < end && *ptr != '&') {
                ptr++;
            }
            value = (StrSlice){.data = val_start, .len = (size_t)(ptr - val_start)};
        }

        // Skip '&' delimiter if we stopped at one
        if (ptr < end) {
            ptr++;
        }

        // Ignore empty keys (e.g. "?&", "&&", or "?=val")
        if (key.len == 0) {
            continue;
        }

        if (!headers_push(&conn->request.query_params, key, value)) {
            return StatusRequestHeaderFieldsTooLarge;
        }
    }

    return StatusOK;
}

// ================== Parsing Keep-Alive Header ===============================
static inline bool is_connection_header(const char* s) {
    uint64_t a;
    uint16_t b;
    memcpy(&a, s, sizeof(a));
    memcpy(&b, s + sizeof(a), sizeof(b));

    return ((a | UINT64_C(0x2020202020202020)) == UINT64_C(0x697463656e6e6f63)) &&
           ((uint16_t)(b | UINT16_C(0x2020)) == UINT16_C(0x6e6f));
}

static inline bool is_close_value(const char* s, size_t len) {
    if (len != 5) return false;
    uint64_t w = 0;
    memcpy(&w, s, 5);
    return (w | UINT64_C(0x2020202020)) == UINT64_C(0x65736f6c63);
}

/**
 * Minimal fast-path header scanner for safe methods / non-static routes.
 *
 * Extracts ONLY the keep-alive state without populating header tables, parsing
 * Content-Length/Range, or trimming non-Connection lines.
 *
 * Validation mirrors parse_request_headers exactly:
 *  - Defaults to keep-alive enabled (HTTP/1.1).
 *  - First 'Connection' header takes precedence.
 *  - Disabled ONLY if the OWS-trimmed value is case-insensitively "close" (5 bytes).
 *  - Empty header field names return 400 (StatusBadRequest).
 *  - Enforces max header count (HEADERS_CAPACITY) returning 431
 * (StatusRequestHeaderFieldsTooLarge).
 */
INLINE http_status scan_keepalive_only(PulsarConn* conn, const char* hdrs, size_t headers_len) {
    conn->keep_alive = true;
    const char* ptr = hdrs;
    const char* const end = ptr + headers_len;
    size_t count = 0;

    while (ptr < end) {
        // Fast-exit at terminating empty line ("\r\n") without calling memchr
        if (unlikely(ptr[0] == '\r')) {
            if (likely(ptr + 1 < end && ptr[1] == '\n')) break;
        }

        // O(1) empty name check (replaces memchr for colon)
        if (unlikely(*ptr == ':')) {
            return StatusBadRequest;
        }

        // Find end of line (the ONLY memchr in the loop)
        const char* const eol = (const char*)memchr(ptr, '\r', (size_t)(end - ptr));
        if (unlikely(!eol || eol + 1 >= end || eol[1] != '\n')) {
            break;
        }

        if (unlikely(++count > HEADERS_CAPACITY)) {
            return StatusRequestHeaderFieldsTooLarge;
        }

        // Inspect line ONLY if it starts with 'c' or 'C'
        if (((ptr[0] | 0x20) == 'c')) {
            // "Connection:" is 11 chars. Colon MUST be at index 10.
            if ((size_t)(eol - ptr) >= 11 && ptr[10] == ':' && is_connection_header(ptr)) {
                // Trim OWS around value
                const char* vs = ptr + 11;
                while (vs < eol && (*vs == ' ' || *vs == '\t')) vs++;

                const char* ve = eol;
                while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;

                if (is_close_value(vs, (size_t)(ve - vs))) {
                    conn->keep_alive = false;
                }
                return StatusOK;
            }
        }

        ptr = eol + 2;
    }

    return StatusOK;
}

#endif  // FASTPARSE_SIMD_H
