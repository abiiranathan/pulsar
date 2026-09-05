#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "macros.h"

/* Fast malicious path check – single pass, no strstr */
INLINE bool is_malicious_path(const char* path) {
    if (!path) return false;

    const unsigned char* p = (const unsigned char*)path;
    unsigned char c, prev = 0;

    while ((c = *p++)) {
        /* quick reject of common dangerous sequences */
        if (c == '.' && prev == '.') {
            /* "../" or "..\" or end-of-string after ".." */
            unsigned char n = *p;
            if (n == '/' || n == '\\' || n == 0) return true;
        }
        if (c == '/' || c == '\\') {
            if (prev == '/' || prev == '\\') return true; /* // or \\ */
            if (prev == '.' && p[0] == '/') return true;  /* /./  (already covered partly) */
            if (*p == '~') return true;                   /* /~ or \~ */
        }
        if (c == '%' && p[0] == '2' && (p[1] | 32) == 'e' && p[2] == '%' && p[3] == '2' &&
            (p[4] | 32) == 'e') {
            return true; /* %2e%2e / %2E%2E */
        }
        if (c == '\\' && (p[0] | 32) == 'x') return true; /* \x */
        prev = c;
    }
    return false;
}

/* 256-byte tables – keep them in the same cache line if possible */
static const uint8_t hex_decode_table[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,  ['6'] = 6,  ['7'] = 7,
    ['8'] = 8,  ['9'] = 9,  ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15};

static const uint8_t hex_valid_table[256] = {
    ['0'] = 1, ['1'] = 1, ['2'] = 1, ['3'] = 1, ['4'] = 1, ['5'] = 1, ['6'] = 1, ['7'] = 1,
    ['8'] = 1, ['9'] = 1, ['A'] = 1, ['B'] = 1, ['C'] = 1, ['D'] = 1, ['E'] = 1, ['F'] = 1,
    ['a'] = 1, ['b'] = 1, ['c'] = 1, ['d'] = 1, ['e'] = 1, ['f'] = 1};

/* Highly optimised percent-decoder.
 * - bulk memcpy of runs of ordinary characters
 * - branch-light hex decode
 * - respects both src_len and dst_size
 * - never reads past src_end
 */
static inline size_t url_percent_decode(const char* restrict src, char* restrict dst,
                                        size_t src_len, size_t dst_size) {
    if (dst_size == 0) return 0;

    char* const dst_start = dst;
    char* const dst_end = dst + dst_size - 1; /* room for '\0' */
    const char* const src_end = src + src_len;

    while (src < src_end && dst < dst_end) {
        /* ---- fast path: copy consecutive ordinary characters ---- */
        const char* run = src;
        while (src < src_end) {
            unsigned char c = (unsigned char)*src;
            if (c == '%' || c == '+') break;
            ++src;
        }
        size_t run_len = (size_t)(src - run);
        if (run_len) {
            size_t space = (size_t)(dst_end - dst);
            size_t n = run_len < space ? run_len : space;
            memcpy(dst, run, n);
            dst += n;
            if (n < run_len) break; /* dst full */
        }

        if (src >= src_end || dst >= dst_end) break;

        /* ---- special character ---- */
        if (*src == '+') {
            *dst++ = ' ';
            ++src;
        } else { /* '%' */
            if (src + 2 < src_end) {
                unsigned char h1 = (unsigned char)src[1];
                unsigned char h2 = (unsigned char)src[2];
                if (hex_valid_table[h1] & hex_valid_table[h2]) {
                    *dst++ = (char)((hex_decode_table[h1] << 4) | hex_decode_table[h2]);
                    src += 3;
                    continue;
                }
            }
            /* invalid or truncated %XX → copy the '%' literally */
            *dst++ = *src++;
        }
    }

    *dst = '\0';
    return (size_t)(dst - dst_start);
}

#ifdef __cplusplus
}
#endif

#endif /* UTILS_H */
