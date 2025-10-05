#ifndef UTILS_H
#define UTILS_H

#include <pthread.h>
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

// Lookup tables for hex digit conversion
static uint8_t hex_decode_table[256];
static uint8_t hex_valid_table[256];

/** Initializes hex lookup tables.
 */
INLINE void init_hex_tables_impl(void) {
    memset(hex_decode_table, 0, sizeof(hex_decode_table));
    memset(hex_valid_table, 0, sizeof(hex_valid_table));

    // Initialize decode table for '0'-'9'
    for (int i = '0'; i <= '9'; i++) {
        hex_decode_table[i] = i - '0';
    }
    // Initialize decode table for 'A'-'F'
    for (int i = 'A'; i <= 'F'; i++) {
        hex_decode_table[i] = i - 'A' + 10;
    }
    // Initialize decode table for 'a'-'f'
    for (int i = 'a'; i <= 'f'; i++) {
        hex_decode_table[i] = i - 'a' + 10;
    }

    // Initialize validity table for '0'-'9'
    for (int i = '0'; i <= '9'; i++) {
        hex_valid_table[i] = 1;
    }
    // Initialize validity table for 'A'-'F'
    for (int i = 'A'; i <= 'F'; i++) {
        hex_valid_table[i] = 1;
    }
    // Initialize validity table for 'a'-'f'
    for (int i = 'a'; i <= 'f'; i++) {
        hex_valid_table[i] = 1;
    }
}

static pthread_once_t hex_tables_once = PTHREAD_ONCE_INIT;

INLINE void init_hex_tables(void) {
    pthread_once(&hex_tables_once, init_hex_tables_impl);
}

INLINE void url_percent_decode(const char* src, char* dst, size_t src_len, size_t dst_size) {
    init_hex_tables();

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
                    *dst++ = (char)((hex_decode_table[h1] << 4) | hex_decode_table[h2]);
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
