#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "macros.h"

// Fast memmem implementation
// Uses AVX intrinsics for better performance on x86/x86_64.
#include "memmem.h"

INLINE bool is_malicious_path(const char* path) {
    // List of dangerous patterns
    static const char* patterns[] = {"../", "/./", "//", "/~", "%2e%2e", NULL};
    for (int i = 0; patterns[i]; i++) {
        if (strstr(path, patterns[i])) {
            return true;
        }
    }
    // Check for URL-encoded characters(\\x).
    if (strstr(path, "\\x")) {
        return true;
    }
    return false;
}

// Precomputed lookup table for hex digit conversion
static const uint8_t hex_decode_table[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,  ['6'] = 6,  ['7'] = 7,
    ['8'] = 8,  ['9'] = 9,  ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15,
};

// Validity table - 1 for valid hex digits, 0 for invalid
static const uint8_t hex_valid_table[256] = {
    ['0'] = 1, ['1'] = 1, ['2'] = 1, ['3'] = 1, ['4'] = 1, ['5'] = 1, ['6'] = 1, ['7'] = 1,
    ['8'] = 1, ['9'] = 1, ['A'] = 1, ['B'] = 1, ['C'] = 1, ['D'] = 1, ['E'] = 1, ['F'] = 1,
    ['a'] = 1, ['b'] = 1, ['c'] = 1, ['d'] = 1, ['e'] = 1, ['f'] = 1,
};

INLINE void url_percent_decode(const char* src, char* dst, size_t src_len, size_t dst_size) {
    const char* dst_end = dst + dst_size - 1;  // reserve space for '\0';
    const char* src_end = src + src_len;       // avoids NULL termination assumption

    // Find runs of normal characters and copy them in bulk
    while (src < src_end && dst < dst_end) {
        const char* run_start = src;

        // Find the next special character or end of string
        while (*src && *src != '%' && *src != '+') {
            src++;
        }

        // Copy the run of normal characters
        size_t run_length = (size_t)(src - run_start);
        if (run_length > 0) {
            size_t space_left  = (size_t)(dst_end - dst);
            size_t copy_length = run_length < space_left ? run_length : space_left;

            memcpy(dst, run_start, copy_length);
            dst += copy_length;

            if (copy_length < run_length) {
                // Out of space
                break;
            }
        }

        // Process special character if any
        if (*src && dst < dst_end) {
            if (*src == '+') {
                *dst++ = ' ';
                src++;
            } else if (*src == '%' && src[1] && src[2]) {
                unsigned char h1 = (unsigned char)src[1];
                unsigned char h2 = (unsigned char)src[2];
                if (hex_valid_table[h1] & hex_valid_table[h2]) {
                    *dst++ = (hex_decode_table[h1] << 4) | hex_decode_table[h2];
                    src += 3;
                } else {
                    *dst++ = *src++;
                }
            } else if (*src == '%') {
                *dst++ = *src++;
            }
        }
    }

    *dst = '\0';
}

#ifdef __cplusplus
}
#endif

#endif  // UTILS_H
