#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <ctype.h>
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

INLINE unsigned long parse_ulong(const char* value, bool* valid) {
    assert(valid && "NULL pointer for bool *valid");

    *valid        = false;
    char* endptr  = NULL;
    errno         = 0;
    uintmax_t num = strtoumax(value, &endptr, 10);

    // Overflow or underflow.
    if ((num > ULONG_MAX) || (errno == ERANGE && (num == 0 || num == UINTMAX_MAX))) {
        return 0;
    }

    // Invalid value.
    if (*endptr != '\0' || endptr == value) {
        return 0;
    }

    *valid = true;
    return num;
}

/**
 * Check if path is a directory
 * Returns true if path exists AND is a directory, false otherwise
 */
INLINE bool is_dir(const char* path) {
    if (!path || !*path) {  // Handle NULL or empty string
        errno = EINVAL;
        return false;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return false;  // stat failed (errno is set)
    }
    return S_ISDIR(st.st_mode);
}

/**
 * Check if a path exists (file or directory)
 * Returns true if path exists, false otherwise (and sets errno)
 */
INLINE bool path_exists(const char* path) {
    if (!path || !*path) {
        return false;
    }
    return access(path, F_OK) == 0;
}

INLINE void url_percent_decode(const char* src, char* dst, size_t dst_size) {
    char a, b;
    size_t written = 0;
    size_t src_len = strlen(src);

    while (*src && written + 1 < dst_size) {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
            written++;
        } else if ((*src == '%') && (src_len >= 2) && ((a = src[1]) && (b = src[2])) &&
                   (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A')
                a -= 'A' - 10;
            else
                a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A')
                b -= 'A' - 10;
            else
                b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
            written++;
        } else {
            *dst++ = *src++;
            written++;
        }
    }

    // Null-terminate the destination buffer
    *dst = '\0';
}

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

#ifdef __cplusplus
}
#endif

#endif  // UTILS_H
