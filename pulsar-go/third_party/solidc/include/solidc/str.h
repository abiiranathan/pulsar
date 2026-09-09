/**
 * @file str.h
 * @brief High-performance, header-only string utility library for C11.
 *
 * All functions operate on ordinary NUL-terminated C strings (`char*`).
 *
 * Functions fall into two main categories:
 *  - In-place: Modifies caller-supplied string buffers directly (`char*`).
 *  - Allocating: Returns newly `malloc`'d memory. Caller is responsible for
 *    releasing returned memory via `free()`.
 *
 * Thread Safety:
 *  Functions operating purely on read-only inputs (`const char*`) or distinct
 *  buffers are safe for concurrent use across multiple threads. Functions
 *  modifying shared buffers in-place require external synchronization.
 */

#ifndef __STR_H__
#define __STR_H__

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Internal Fast Search
 * ======================================================================= */

/**
 * @brief Internal fast substring search implementation using first/last byte matching and SIMD `memchr`.
 *
 * @param[in] hs    Haystack string buffer to search within.
 * @param[in] hlen  Length of haystack buffer in bytes.
 * @param[in] nd    Needle substring to locate.
 * @param[in] nlen  Length of needle substring in bytes.
 *
 * @return Pointer to the first occurrence of needle in haystack, or NULL if not found.
 *
 * @note Thread-safe.
 */
static inline const char* str_search_impl(const char* hs, size_t hlen, const char* nd, size_t nlen) {
    if (nlen == 0) return hs;
    if (hlen < nlen) return NULL;

    /* Optimized fast path for single-character search using vectorized system memchr */
    if (nlen == 1) return (const char*)memchr(hs, (unsigned char)nd[0], hlen);

    const char* cur = hs;
    const char* end = hs + hlen - nlen;
    unsigned char first = (unsigned char)nd[0];
    unsigned char last = (unsigned char)nd[nlen - 1];

    /* Slotted window search: scan for first byte, verify last byte, then compare inner bytes */
    while (cur <= end) {
        /* Rapidly skip non-matching characters using memchr */
        cur = (const char*)memchr(cur, first, (size_t)(end - cur + 1));
        if (!cur) return NULL;

        /* Filter false positives early by testing the last byte of needle */
        if ((unsigned char)cur[nlen - 1] == last) {
            if (nlen <= 9) {
                /* Unrolled manual loop for short needles to avoid call overhead of memcmp */
                size_t i = 0;
                for (; i < nlen - 2; i++) {
                    if (cur[1 + i] != nd[1 + i]) goto next_iter;
                }
                return cur;
            } else {
                /* Bulk comparison for larger needle payloads */
                if (memcmp(cur + 1, nd + 1, nlen - 2) == 0) return cur;
            }
        }
    next_iter:
        cur++;
    }
    return NULL;
}

/* =========================================================================
 * Predicates
 * ======================================================================= */

/**
 * @brief Checks whether a string is NULL or empty (zero length).
 *
 * @param[in] str The string to evaluate.
 * @return `true` if NULL or empty string `""`, `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_is_empty(const char* str) { return !str || str[0] == '\0'; }

/**
 * @brief Checks whether a string is NULL, empty, or consists solely of white-space characters.
 *
 * @param[in] str The string to evaluate.
 * @return `true` if NULL, empty, or whitespace-only; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_is_blank(const char* str) {
    if (!str) return true;
    for (; *str; str++) {
        if (!isspace((unsigned char)*str)) return false;
    }
    return true;
}

/**
 * @brief Checks whether a string contains exclusively alphabetic ASCII characters (`a-z`, `A-Z`).
 *
 * @param[in] str The string to evaluate.
 * @return `true` if non-NULL, non-empty, and entirely alphabetic; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_is_alpha(const char* str) {
    if (!str || !*str) return false;
    for (; *str; str++) {
        if (!isalpha((unsigned char)*str)) return false;
    }
    return true;
}

/**
 * @brief Checks whether a string contains exclusively decimal digit ASCII characters (`0-9`).
 *
 * @param[in] str The string to evaluate.
 * @return `true` if non-NULL, non-empty, and entirely digits; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_is_digit(const char* str) {
    if (!str || !*str) return false;
    for (; *str; str++) {
        if (!isdigit((unsigned char)*str)) return false;
    }
    return true;
}

/**
 * @brief Checks whether a string contains exclusively alphanumeric ASCII characters (`a-z`, `A-Z`, `0-9`).
 *
 * @param[in] str The string to evaluate.
 * @return `true` if non-NULL, non-empty, and entirely alphanumeric; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_is_alnum(const char* str) {
    if (!str || !*str) return false;
    for (; *str; str++) {
        if (!isalnum((unsigned char)*str)) return false;
    }
    return true;
}

/**
 * @brief Checks whether a string represents a valid signed decimal integer (optional leading '+' or '-').
 *
 * @param[in] str The string to evaluate.
 * @return `true` if valid integer representation; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_is_numeric(const char* str) {
    if (!str || !*str) return false;
    if (*str == '+' || *str == '-') str++;
    if (!*str) return false;
    for (; *str; str++) {
        if (!isdigit((unsigned char)*str)) return false;
    }
    return true;
}

/**
 * @brief Checks whether a string represents a valid floating-point number.
 *
 * Uses `strtod` internally to parse float format without modifying global errno state unexpectedly.
 *
 * @param[in] str The string to evaluate.
 * @return `true` if full string parses as floating-point; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_is_float(const char* str) {
    if (!str || !*str) return false;
    char* end;
    errno = 0;
    (void)strtod(str, &end);
    return *end == '\0' && end != str;
}

/**
 * @brief Performs case-sensitive equality comparison of two strings.
 *
 * @param[in] a First string operand.
 * @param[in] b Second string operand.
 * @return `true` if both strings are byte-for-byte identical or both NULL; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_equals(const char* a, const char* b) {
    if (a == b) return true;
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

/**
 * @brief Performs case-insensitive ASCII equality comparison of two strings.
 *
 * @param[in] a First string operand.
 * @param[in] b Second string operand.
 * @return `true` if strings match case-insensitively or both NULL; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_iequals(const char* a, const char* b) {
    if (a == b) return true;
    if (!a || !b) return false;
    for (; *a && *b; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
    }
    return *a == '\0' && *b == '\0';
}

/**
 * @brief Tests whether a haystack string contains a substring payload.
 *
 * @param[in] str     Haystack string to search.
 * @param[in] substr  Needle substring to query.
 * @return `true` if substring exists in haystack; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_contains(const char* str, const char* substr) {
    if (!str || !substr) return false;
    size_t hlen = strlen(str);
    size_t nlen = strlen(substr);
    return str_search_impl(str, hlen, substr, nlen) != NULL;
}

/**
 * @brief Checks whether a string begins with a given prefix.
 *
 * @param[in] str     String to check.
 * @param[in] prefix  Expected prefix substring.
 * @return `true` if `str` starts with `prefix` or if `prefix` is empty; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_starts_with(const char* str, const char* prefix) {
    if (!str || !prefix) return false;
    size_t plen = strlen(prefix);
    if (plen == 0) return true;
    return strncmp(str, prefix, plen) == 0;
}

/**
 * @brief Checks whether a string ends with a given suffix.
 *
 * @param[in] str     String to check.
 * @param[in] suffix  Expected suffix substring.
 * @return `true` if `str` ends with `suffix` or if `suffix` is empty; `false` otherwise.
 * @note Safe for concurrent use.
 */
static inline bool str_ends_with(const char* str, const char* suffix) {
    if (!str || !suffix) return false;
    size_t slen = strlen(suffix);
    if (slen == 0) return true;
    size_t len = strlen(str);
    if (slen > len) return false;
    return memcmp(str + len - slen, suffix, slen) == 0;
}

/* =========================================================================
 * Search & Position
 * ======================================================================= */

/**
 * @brief Finds the zero-based index of the first match of a substring in a haystack string.
 *
 * @param[in] str     Haystack string.
 * @param[in] substr  Needle substring to locate.
 * @return Zero-based character index where match starts, or -1 if NULL or not found.
 * @note Safe for concurrent use.
 */
static inline int str_find(const char* str, const char* substr) {
    if (!str || !substr) return -1;
    size_t hlen = strlen(str);
    size_t nlen = strlen(substr);
    const char* found = str_search_impl(str, hlen, substr, nlen);
    return found ? (int)(found - str) : -1;
}

/**
 * @brief Finds the zero-based index of the last match of a substring in a haystack string.
 *
 * @param[in] str     Haystack string.
 * @param[in] substr  Needle substring to locate.
 * @return Zero-based index of last match occurrence, or -1 if NULL, empty needle, or not found.
 * @note Safe for concurrent use.
 */
static inline int str_rfind(const char* str, const char* substr) {
    if (!str || !substr) return -1;
    size_t hlen = strlen(str);
    size_t nlen = strlen(substr);
    if (nlen == 0 || nlen > hlen) return -1;

    const char* last = NULL;
    const char* p = str;

    /* Iteratively scan forward keeping track of the latest match pointer */
    while ((p = str_search_impl(p, hlen - (size_t)(p - str), substr, nlen)) != NULL) {
        last = p++;
        if ((size_t)(p - str) + nlen > hlen) break;
    }
    return last ? (int)(last - str) : -1;
}

/**
 * @brief Counts non-overlapping occurrences of a substring in a string.
 *
 * @param[in] str     String to search.
 * @param[in] substr  Substring to search for.
 * @return Count of non-overlapping occurrences found.
 * @note Safe for concurrent use.
 */
static inline size_t str_count_substr(const char* str, const char* substr) {
    if (!str || !substr) return 0;
    size_t nlen = strlen(substr);
    size_t hlen = strlen(str);
    if (nlen == 0 || nlen > hlen) return 0;

    /* Fast-path: single character using SIMD memchr */
    if (nlen == 1) {
        size_t count = 0;
        const char* p = str;
        size_t rem = hlen;
        unsigned char target = (unsigned char)substr[0];

        while ((p = (const char*)memchr(p, target, rem)) != NULL) {
            count++;
            p++;
            rem = hlen - (size_t)(p - str);
        }
        return count;
    }

    size_t count = 0;
    const char* p = str;
    size_t rem = hlen;

    while ((p = str_search_impl(p, rem, substr, nlen)) != NULL) {
        count++;
        p += nlen; /* Advance pointer past current match to ensure non-overlapping count */
        rem = hlen - (size_t)(p - str);
        if (rem < nlen) break;
    }
    return count;
}

/**
 * @brief Counts whitespace-delimited words in a string.
 *
 * @param[in] str String to scan.
 * @return Total number of whitespace-delimited tokens/words.
 * @note Safe for concurrent use.
 */
static inline size_t str_word_count(const char* str) {
    if (!str) return 0;
    size_t count = 0;
    bool in_word = false;
    for (; *str; str++) {
        if (isspace((unsigned char)*str)) {
            in_word = false;
        } else if (!in_word) {
            in_word = true;
            count++;
        }
    }
    return count;
}

/* =========================================================================
 * In-place Case Conversion (SWAR Optimized)
 * ======================================================================= */

/**
 * @brief Converts all uppercase ASCII characters in a string to lowercase in-place.
 *
 * Delegates to simd_ascii_lower(): true SIMD lanes classify ASCII letters
 * exactly and never modify bytes >= 0x80, so UTF-8 text passes through
 * untouched.  (The previous GPR-SWAR implementation corrupted non-ASCII
 * bytes >= 0xC1 via cross-byte carry propagation.)
 *
 * @param[in,out] str Null-terminated string buffer to mutate in-place.
 */
static inline void str_lower(char* str) {
    if (!str) return;
    simd_ascii_lower(str, strlen(str));
}

/**
 * @brief Converts all lowercase ASCII characters in a string to uppercase in-place.
 *
 * Delegates to simd_ascii_upper(); UTF-8 safe.  See str_lower().
 *
 * @param[in,out] str Null-terminated string buffer to mutate in-place.
 */
static inline void str_upper(char* str) {
    if (!str) return;
    simd_ascii_upper(str, strlen(str));
}

/**
 * @brief Capitalizes the first character of a string and converts remaining characters to lowercase in-place.
 *
 * @param[in,out] str Buffer to mutate in-place.
 */
static inline void str_capitalize(char* str) {
    if (!str || !*str) return;
    *str = (char)toupper((unsigned char)*str);
    str_lower(str + 1);
}

/**
 * @brief Helper internal predicate to check if a character acts as a word separator ('_', '-', or whitespace).
 *
 * @param[in] c Character byte to check.
 * @return `true` if separator character; `false` otherwise.
 */
static inline bool str_is_sep(unsigned char c) { return c == '_' || c == '-' || isspace(c); }

/**
 * @brief Converts a string to camelCase in-place (e.g. "hello_world" -> "helloWorld").
 *
 * Strips leading/intermittent separators ('_', '-', space) and upper-cases word boundaries.
 *
 * @param[in,out] str Buffer to mutate in-place.
 */
static inline void str_camelcase(char* str) {
    if (!str || !*str) return;

    size_t r = 0;
    size_t w = 0;
    size_t len = strlen(str);

    /* Strip leading separator characters */
    while (r < len && str_is_sep((unsigned char)str[r])) r++;

    /* First word starts lowercase */
    if (r < len) {
        unsigned char c = (unsigned char)str[r++];
        str[w++] = (char)((unsigned)(c - 'A') <= 25u ? (c | 0x20u) : c);
    }

    bool cap = false;
    while (r < len) {
        unsigned char c = (unsigned char)str[r++];
        if (str_is_sep(c)) {
            cap = true;
        } else if (cap) {
            str[w++] = (char)((unsigned)(c - 'a') <= 25u ? (c & ~0x20u) : c);
            cap = false;
        } else {
            str[w++] = (char)((unsigned)(c - 'A') <= 25u ? (c | 0x20u) : c);
        }
    }
    str[w] = '\0';
}

/**
 * @brief Converts a string to PascalCase in-place (e.g. "hello_world" -> "HelloWorld").
 *
 * Strips separators and capitalizes the start of every word including the first word.
 *
 * @param[in,out] str Buffer to mutate in-place.
 */
static inline void str_pascalcase(char* str) {
    if (!str || !*str) return;

    size_t r = 0;
    size_t w = 0;
    size_t len = strlen(str);

    /* Strip leading separators */
    while (r < len && str_is_sep((unsigned char)str[r])) r++;

    bool new_word = true;
    while (r < len) {
        unsigned char c = (unsigned char)str[r++];
        if (str_is_sep(c)) {
            new_word = true;
        } else if (new_word) {
            str[w++] = (char)((unsigned)(c - 'a') <= 25u ? (c & ~0x20u) : c);
            new_word = false;
        } else {
            str[w++] = (char)((unsigned)(c - 'A') <= 25u ? (c | 0x20u) : c);
        }
    }
    str[w] = '\0';
}

/**
 * @brief Converts a string to Title Case in-place (e.g. "hello world" -> "Hello World").
 *
 * Capitalizes first letter of every word separated by spaces/underscores/dashes, leaving separators intact.
 *
 * @param[in,out] str Buffer to mutate in-place.
 */
static inline void str_titlecase(char* str) {
    if (!str) return;
    bool cap = true;
    for (; *str; str++) {
        unsigned char c = (unsigned char)*str;
        if (str_is_sep(c)) {
            cap = true;
        } else if (cap) {
            *str = (char)((unsigned)(c - 'a') <= 25u ? (c & ~0x20u) : c);
            cap = false;
        } else {
            *str = (char)((unsigned)(c - 'A') <= 25u ? (c | 0x20u) : c);
        }
    }
}

/* =========================================================================
 * In-place Trimming, Reversal, Removal & Security
 * ======================================================================= */

/**
 * @brief Trims leading white-space characters from a string in-place.
 *
 * @param[in,out] str Buffer to mutate in-place.
 */
static inline void str_ltrim(char* str) {
    if (!str || !*str) return;
    size_t len = strlen(str);
    size_t start = 0;
    while (start < len && isspace((unsigned char)str[start])) start++;
    if (start == 0) return;
    memmove(str, str + start, len - start + 1);
}

/**
 * @brief Trims trailing white-space characters from a string in-place.
 *
 * @param[in,out] str Buffer to mutate in-place.
 */
static inline void str_rtrim(char* str) {
    if (!str || !*str) return;
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) len--;
    str[len] = '\0';
}

/**
 * @brief Trims both leading and trailing white-space characters from a string in-place.
 *
 * @param[in,out] str Buffer to mutate in-place.
 */
static inline void str_trim(char* str) {
    if (!str || !*str) return;
    str_rtrim(str);
    str_ltrim(str);
}

/**
 * @brief Trims leading and trailing occurrences of any characters specified in `chars` set in-place.
 *
 * @param[in,out] str    Buffer to mutate in-place.
 * @param[in]     chars  Null-terminated set of character bytes to trim.
 */
static inline void str_trim_chars(char* str, const char* chars) {
    if (!str || !chars || !*chars) return;
    size_t len = strlen(str);
    size_t start = 0;

    while (start < len && str[start] != '\0' && strchr(chars, str[start])) start++;
    if (start == len) {
        str[0] = '\0';
        return;
    }

    size_t end = len - 1;
    while (end > start && str[end] != '\0' && strchr(chars, str[end])) end--;

    size_t new_len = end - start + 1;
    if (start) memmove(str, str + start, new_len);
    str[new_len] = '\0';
}

/**
 * @brief Truncates a string buffer in-place if its length exceeds `max_len`.
 *
 * @param[in,out] str      Buffer to truncate.
 * @param[in]     max_len  Maximum permitted length in bytes.
 */
static inline void str_truncate(char* str, size_t max_len) {
    if (!str) return;
    size_t len = strlen(str);
    if (len > max_len) str[max_len] = '\0';
}

/**
 * @brief Reverses a string buffer in-place.
 *
 * @param[in,out] str Buffer to mutate in-place.
 */
static inline void str_reverse(char* str) {
    if (!str) return;
    size_t len = strlen(str);
    if (len < 2) return;
    for (size_t i = 0, j = len - 1; i < j; i++, j--) {
        char t = str[i];
        str[i] = str[j];
        str[j] = t;
    }
}

/**
 * @brief Vectorized removal of all occurrences of a single target character byte in-place.
 *
 * Leverages system SIMD `memchr` to skip non-matching chunks and `memmove` to collapse matching byte regions.
 *
 * @param[in,out] str  Buffer to mutate in-place.
 * @param[in]     c    Target byte character to purge.
 */
static inline void str_remove_char(char* str, char c) {
    if (!str || !*str) return;

    char* read_ptr = str;
    char* write_ptr = str;
    size_t rem = strlen(str);

    while (rem > 0) {
        /* Vectorized search for next matching instance */
        char* match = (char*)memchr(read_ptr, (unsigned char)c, rem);
        if (!match) {
            if (write_ptr != read_ptr) {
                memmove(write_ptr, read_ptr, rem);
            }
            write_ptr += rem;
            break;
        }

        /* Copy chunk between last read position and match position */
        size_t chunk_len = (size_t)(match - read_ptr);
        if (chunk_len > 0) {
            if (write_ptr != read_ptr) {
                memmove(write_ptr, read_ptr, chunk_len);
            }
            write_ptr += chunk_len;
        }

        read_ptr = match + 1;
        rem -= (chunk_len + 1);
    }

    *write_ptr = '\0';
}

/**
 * @brief Removes all instances of a target substring in-place.
 *
 * @param[in,out] str     Buffer to mutate in-place.
 * @param[in]     substr  Target substring to purge.
 * @return Number of occurrences removed.
 */
static inline size_t str_remove_all(char* str, const char* substr) {
    if (!str || !substr || !*substr) return 0;
    size_t sub_len = strlen(substr);
    char* w = str;
    char* r = str;
    size_t count = 0;

    while (*r) {
        if (strncmp(r, substr, sub_len) == 0) {
            r += sub_len;
            count++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
    return count;
}

/**
 * @brief Removes a sub-range from a string in-place given a start index and length.
 *
 * @param[in,out] str    Buffer to mutate in-place.
 * @param[in]     start  Zero-based start position index.
 * @param[in]     slen   Number of bytes to strip.
 */
static inline void str_remove_substr(char* str, size_t start, size_t slen) {
    if (!str || slen == 0) return;
    size_t len = strlen(str);
    if (start >= len) return;
    if (slen > len - start) slen = len - start;

    size_t tail = len - start - slen;
    if (tail > 0)
        memmove(str + start, str + start + slen, tail + 1);
    else
        str[start] = '\0';
}

/**
 * @brief Secure memory zeroization guaranteed not to be optimized away by compiler optimizations.
 *
 * Uses volatile pointer access to safely wipe sensitive credentials (passwords, tokens, key bytes)
 * before releasing string buffers.
 *
 * @param[in,out] str Null-terminated string buffer to clear.
 */
static inline void str_wipe(char* str) {
    if (!str) return;
    size_t len = strlen(str);
    volatile char* p = (volatile char*)str;
    while (len--) {
        *p++ = '\0';
    }
}

/* =========================================================================
 * Allocating Helpers
 * ======================================================================= */

/**
 * @brief Duplicates a string by allocating heap memory using `malloc`.
 *
 * @param[in] str String to duplicate.
 * @return Newly allocated copy of string, or NULL on allocation failure or if input is NULL.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_dup(const char* str) {
    if (!str) return NULL;
    size_t len = strlen(str) + 1;
    char* r = (char*)malloc(len);
    if (r) memcpy(r, str, len);
    return r;
}

/**
 * @brief Duplicates up to `n` characters of a string into a newly allocated NUL-terminated heap buffer.
 *
 * @param[in] str String to duplicate.
 * @param[in] n   Maximum number of bytes to copy.
 * @return Newly allocated string duplicate, or NULL on failure/NULL input.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_ndup(const char* str, size_t n) {
    if (!str) return NULL;
    size_t len = strlen(str);
    if (n < len) len = n;
    char* r = (char*)malloc(len + 1);
    if (!r) return NULL;
    memcpy(r, str, len);
    r[len] = '\0';
    return r;
}

/**
 * @brief Creates a newly allocated slice substring from a source string.
 *
 * @param[in] str     Source string.
 * @param[in] start   Zero-based start position index.
 * @param[in] length  Maximum length of slice to extract.
 * @return Newly allocated substring, or NULL if `start` is out of bounds or allocation fails.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_substr(const char* str, size_t start, size_t length) {
    if (!str) return NULL;
    size_t len = strlen(str);
    if (start > len) return NULL;

    size_t avail = len - start;
    size_t copy = (length > avail) ? avail : length;

    char* r = (char*)malloc(copy + 1);
    if (!r) return NULL;
    memcpy(r, str + start, copy);
    r[copy] = '\0';
    return r;
}

/**
 * @brief Repeats a string `n` times into a newly allocated buffer.
 *
 * @param[in] str String to repeat.
 * @param[in] n   Number of repetitions.
 * @return Newly allocated repeated string, or NULL on allocation error or size arithmetic overflow.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_repeat(const char* str, size_t n) {
    if (!str) return NULL;
    size_t slen = strlen(str);
    if (n > 0 && slen > (SIZE_MAX - 1) / n) return NULL; /* Overflow protection */
    size_t total = slen * n;

    char* r = (char*)malloc(total + 1);
    if (!r) return NULL;

    for (size_t i = 0; i < n; i++) memcpy(r + i * slen, str, slen);
    r[total] = '\0';
    return r;
}

/**
 * @brief Left-pads a string with a character to a minimum field length into a newly allocated buffer.
 *
 * @param[in] str       Source string.
 * @param[in] width     Total desired minimum field width.
 * @param[in] pad_char  Padding byte character.
 * @return Newly allocated padded string, or duplicate of string if already >= width, or NULL on allocation error.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_pad_left(const char* str, size_t width, char pad_char) {
    if (!str) return NULL;
    size_t len = strlen(str);
    if (len >= width) return str_dup(str);

    size_t pad = width - len;
    char* r = (char*)malloc(width + 1);
    if (!r) return NULL;

    memset(r, (unsigned char)pad_char, pad);
    memcpy(r + pad, str, len);
    r[width] = '\0';
    return r;
}

/**
 * @brief Right-pads a string with a character to a minimum field length into a newly allocated buffer.
 *
 * @param[in] str       Source string.
 * @param[in] width     Total desired minimum field width.
 * @param[in] pad_char  Padding byte character.
 * @return Newly allocated padded string, or duplicate of string if already >= width, or NULL on allocation error.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_pad_right(const char* str, size_t width, char pad_char) {
    if (!str) return NULL;
    size_t len = strlen(str);
    if (len >= width) return str_dup(str);

    size_t pad = width - len;
    char* r = (char*)malloc(width + 1);
    if (!r) return NULL;

    memcpy(r, str, len);
    memset(r + len, (unsigned char)pad_char, pad);
    r[width] = '\0';
    return r;
}

/**
 * @brief Centers a string within a field width with equal padding on both sides in a newly allocated buffer.
 *
 * @param[in] str       Source string.
 * @param[in] width     Target output width.
 * @param[in] pad_char  Padding byte character.
 * @return Newly allocated centered string, or duplicate if string length >= width, or NULL on failure.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_center(const char* str, size_t width, char pad_char) {
    if (!str) return NULL;
    size_t len = strlen(str);
    if (len >= width) return str_dup(str);

    size_t total_pad = width - len;
    size_t left_pad = total_pad / 2;
    size_t right_pad = total_pad - left_pad;

    char* r = (char*)malloc(width + 1);
    if (!r) return NULL;

    memset(r, (unsigned char)pad_char, left_pad);
    memcpy(r + left_pad, str, len);
    memset(r + left_pad + len, (unsigned char)pad_char, right_pad);
    r[width] = '\0';
    return r;
}

/**
 * @brief Internal helper to determine snake_case underscore injection points.
 *
 * Handles transitional cases:
 *  - `lowerUPPER` -> `lower_upper`
 *  - `UPPERUpper` -> `upper_upper` (e.g. `XMLParser` -> `xml_parser`)
 *
 * @param[in] str Input string.
 * @param[in] i   Current character index.
 * @param[in] len Total string length.
 * @return `true` if an underscore should be inserted before character `str[i]`.
 */
static inline bool str_snake_should_underscore(const char* str, size_t i, size_t len) {
    if (i == 0) return false;

    unsigned char c = (unsigned char)str[i];
    unsigned char prev = (unsigned char)str[i - 1];

    if (c == ' ' || c == '-' || c == '_' || prev == ' ' || prev == '-' || prev == '_') {
        return false;
    }

    bool curr_upper = (unsigned)(c - 'A') <= 25u;
    bool prev_lower = (unsigned)(prev - 'a') <= 25u || (unsigned)(prev - '0') <= 9u;
    bool prev_upper = (unsigned)(prev - 'A') <= 25u;

    if (curr_upper) {
        if (prev_lower) return true; /* lower -> UPPER (myVar -> my_var) */
        if (prev_upper && i + 1 < len) {
            unsigned char next = (unsigned char)str[i + 1];
            bool next_lower = (unsigned)(next - 'a') <= 25u;
            if (next_lower) return true; /* UPPER -> UPPER -> lower (XMLParser -> xml_parser) */
        }
    }
    return false;
}

/**
 * @brief Converts any camelCase, PascalCase, or delimiter-separated string into `snake_case`.
 *
 * Uses a zero-realloc two-pass algorithm:
 * Pass 1 inspects boundaries to count exact needed underscore allocations.
 * Pass 2 allocates precise heap target size and formats string without dynamic buffer resizing.
 *
 * @param[in] str Source string.
 * @return Newly allocated `snake_case` formatted string, or NULL on failure.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_to_snakecase(const char* str) {
    if (!str) return NULL;
    size_t orig = strlen(str);
    if (orig == 0) {
        char* empty = (char*)malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

    /* Pass 1: Pre-calculate exact memory buffer requirements without reallocations */
    size_t extra = 0;
    for (size_t i = 0; i < orig; i++) {
        if (str_snake_should_underscore(str, i, orig)) {
            extra++;
        }
    }

    if (extra > SIZE_MAX - orig - 1) return NULL;
    char* r = (char*)malloc(orig + extra + 1);
    if (!r) return NULL;

    /* Pass 2: Write converted payload directly to pre-sized allocation */
    size_t w = 0;
    bool last_was_underscore = false;

    for (size_t i = 0; i < orig; i++) {
        unsigned char c = (unsigned char)str[i];

        if (c == ' ' || c == '-' || c == '_') {
            if (!last_was_underscore && w > 0) {
                r[w++] = '_';
                last_was_underscore = true;
            }
            continue;
        }

        if (str_snake_should_underscore(str, i, orig)) {
            if (!last_was_underscore && w > 0) {
                r[w++] = '_';
            }
        }

        r[w++] = (char)((unsigned)(c - 'A') <= 25u ? (c | 0x20u) : c);
        last_was_underscore = false;
    }

    r[w] = '\0';
    return r;
}

/**
 * @brief Replaces the first match occurrence of `old_str` with `new_str`.
 *
 * @param[in] str      Haystack string.
 * @param[in] old_str  Substring target to match.
 * @param[in] new_str  Replacement payload string.
 * @return Newly allocated string with replacement performed, or string duplicate if unmatched/NULL.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_replace(const char* str, const char* old_str, const char* new_str) {
    if (!str) return NULL;
    if (!old_str || !new_str) return str_dup(str);

    size_t hlen = strlen(str);
    size_t old_len = strlen(old_str);
    if (old_len == 0) return str_dup(str);

    const char* found = str_search_impl(str, hlen, old_str, old_len);
    if (!found) return str_dup(str);

    size_t new_len = strlen(new_str);
    size_t prefix_len = (size_t)(found - str);
    size_t suffix_len = hlen - prefix_len - old_len;

    if (new_len > SIZE_MAX - prefix_len - suffix_len) return NULL;
    size_t result_len = prefix_len + new_len + suffix_len;

    char* r = (char*)malloc(result_len + 1);
    if (!r) return NULL;

    memcpy(r, str, prefix_len);
    memcpy(r + prefix_len, new_str, new_len);
    memcpy(r + prefix_len + new_len, found + old_len, suffix_len);
    r[result_len] = '\0';
    return r;
}

/**
 * @brief Replaces all occurrences of `old_sub` with `new_sub`.
 *
 * Optimized allocation strategy: Uses a fixed small-stack buffer (`STR_RA_STACK_CAP` = 64) to track match offsets
 * for short inputs, preventing heap overhead. Spills over to heap dynamic reallocations for complex/large matches.
 *
 * @param[in] str      Haystack source string.
 * @param[in] old_sub  Target pattern substring to find.
 * @param[in] new_sub  Replacement substring to inject.
 * @return Newly allocated string with replacements applied, or NULL on allocation error.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_replace_all(const char* str, const char* old_sub, const char* new_sub) {
    if (!str) return NULL;
    size_t hlen = strlen(str);
    if (!old_sub || !new_sub) return str_dup(str);

    size_t old_len = strlen(old_sub);
    if (old_len == 0) return str_dup(str);

    size_t new_len = strlen(new_sub);

#define STR_RA_STACK_CAP 64
    size_t stack_offs[STR_RA_STACK_CAP];
    size_t* offs = stack_offs;
    size_t offs_cap = STR_RA_STACK_CAP;
    size_t count = 0;

    const char* p = str;
    size_t rem = hlen;

    /* Step 1: Scan string and record match indices (stack buffer fast-path) */
    while ((p = str_search_impl(p, rem, old_sub, old_len)) != NULL) {
        if (count >= offs_cap) {
            if (offs_cap > SIZE_MAX / 2 / sizeof(size_t)) goto oom;
            size_t new_cap = offs_cap * 2;
            size_t* no;
            if (offs == stack_offs) {
                no = (size_t*)malloc(new_cap * sizeof(size_t));
                if (!no) goto oom;
                memcpy(no, stack_offs, count * sizeof(size_t));
            } else {
                no = (size_t*)realloc(offs, new_cap * sizeof(size_t));
                if (!no) goto oom;
            }
            offs = no;
            offs_cap = new_cap;
        }
        offs[count++] = (size_t)(p - str);
        p += old_len;
        rem = hlen - (size_t)(p - str);
    }

    if (count == 0) {
        if (offs != stack_offs) free(offs);
        return str_dup(str);
    }

    /* Step 2: Compute target memory bounds */
    size_t result_len;
    if (new_len >= old_len) {
        size_t diff = new_len - old_len;
        if (diff > 0 && count > (SIZE_MAX - hlen) / diff) goto oom;
        result_len = hlen + count * diff;
    } else {
        result_len = hlen - count * (old_len - new_len);
    }

    char* r = (char*)malloc(result_len + 1);
    if (!r) goto oom;

    /* Step 3: Stitch together target string in single copy pass */
    size_t wp = 0, sp = 0;
    for (size_t i = 0; i < count; i++) {
        size_t gap = offs[i] - sp;
        if (gap) {
            memcpy(r + wp, str + sp, gap);
            wp += gap;
        }
        if (new_len) {
            memcpy(r + wp, new_sub, new_len);
            wp += new_len;
        }
        sp = offs[i] + old_len;
    }
    size_t tail = hlen - sp;
    if (tail) {
        memcpy(r + wp, str + sp, tail);
        wp += tail;
    }
    r[wp] = '\0';

    if (offs != stack_offs) free(offs);
    return r;

oom:
    if (offs != stack_offs) free(offs);
    return NULL;
#undef STR_RA_STACK_CAP
}

/**
 * @brief Splits a string by a given delimiter into an array of newly allocated substrings.
 *
 * @param[in]  str        Source string to split.
 * @param[in]  delim      Delimiter string.
 * @param[out] count_out  Pointer receiving total array elements count (excluding NULL sentinel).
 * @return NULL-terminated array of dynamically allocated string pointers (`char**`), or NULL on error.
 * @note Caller must release allocated output using `str_free_split()`.
 */
static inline char** str_split(const char* str, const char* delim, size_t* count_out) {
    if (!count_out) return NULL;
    *count_out = 0;
    if (!str) return NULL;

    /* Empty or NULL delimiter returns single element array copy of entire input */
    if (!delim || !*delim) {
        char** r = (char**)malloc(2 * sizeof(char*));
        if (!r) return NULL;
        r[0] = str_dup(str);
        if (!r[0]) {
            free(r);
            return NULL;
        }
        r[1] = NULL;
        *count_out = 1;
        return r;
    }

    size_t dlen = strlen(delim);
    size_t cap = 8;
    char** result = (char**)malloc(cap * sizeof(char*));
    if (!result) return NULL;

    const char* start = str;
    size_t rem = strlen(str);
    size_t count = 0;

    if (dlen == 1) {
        /* Single-character SIMD fast path */
        unsigned char target = (unsigned char)delim[0];
        for (;;) {
            const char* match = (const char*)memchr(start, target, rem);
            size_t tok_len = match ? (size_t)(match - start) : rem;

            if (count + 1 >= cap) {
                if (cap > SIZE_MAX / 2 / sizeof(char*)) goto split_err;
                size_t new_cap = cap * 2;
                char** tmp = (char**)realloc(result, new_cap * sizeof(char*));
                if (!tmp) goto split_err;
                result = tmp;
                cap = new_cap;
            }

            result[count] = (char*)malloc(tok_len + 1);
            if (!result[count]) goto split_err;
            memcpy(result[count], start, tok_len);
            result[count][tok_len] = '\0';
            count++;

            if (!match) break;
            start = match + 1;
            rem -= (tok_len + 1);
        }
    } else {
        /* Multi-character substring search split path */
        const char* end = str + rem;
        for (;;) {
            const char* found = str_search_impl(start, (size_t)(end - start), delim, dlen);
            const char* tok_end = found ? found : end;

            if (count + 1 >= cap) {
                if (cap > SIZE_MAX / 2 / sizeof(char*)) goto split_err;
                size_t new_cap = cap * 2;
                char** tmp = (char**)realloc(result, new_cap * sizeof(char*));
                if (!tmp) goto split_err;
                result = tmp;
                cap = new_cap;
            }

            size_t tok_len = (size_t)(tok_end - start);
            result[count] = (char*)malloc(tok_len + 1);
            if (!result[count]) goto split_err;
            memcpy(result[count], start, tok_len);
            result[count][tok_len] = '\0';
            count++;

            if (!found) break;
            start = found + dlen;
        }
    }

    result[count] = NULL; /* Append mandatory NULL sentinel pointer */
    *count_out = count;
    return result;

split_err:
    for (size_t i = 0; i < count; i++) free(result[i]);
    free(result);
    return NULL;
}

/**
 * @brief Frees a string array produced by `str_split()`.
 *
 * Iterates through array elements until reaching NULL sentinel pointer and releases memory.
 *
 * @param[in,out] parts Pointer to split array.
 */
static inline void str_free_split(char** parts) {
    if (!parts) return;
    for (size_t i = 0; parts[i]; i++) free(parts[i]);
    free(parts);
}

/**
 * @brief Joins an array of strings into a single newly allocated string using a delimiter.
 *
 * @param[in] strings Array of string pointers to join.
 * @param[in] count   Number of elements in string array.
 * @param[in] delim   Delimiter string placed between adjacent elements (optional).
 * @return Newly allocated joined string, or NULL on error.
 * @note Caller must free the returned string using `free()`.
 */
static inline char* str_join(const char** strings, size_t count, const char* delim) {
    if (!strings || count == 0) {
        char* empty = (char*)malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

    if (count == 1) {
        return strings[0] ? str_dup(strings[0]) : NULL;
    }

    size_t dlen = delim ? strlen(delim) : 0;
    size_t total = 0;

    /* Calculate bounds and verify against size_t overflow */
    for (size_t i = 0; i < count; i++) {
        if (!strings[i]) return NULL;
        size_t slen = strlen(strings[i]);
        if (slen > SIZE_MAX - total) return NULL;
        total += slen;

        if (i + 1 < count && dlen) {
            if (dlen > SIZE_MAX - total) return NULL;
            total += dlen;
        }
    }

    char* r = (char*)malloc(total + 1);
    if (!r) return NULL;

    char* w = r;
    size_t first_len = strlen(strings[0]);
    if (first_len) {
        memcpy(w, strings[0], first_len);
        w += first_len;
    }

    /* Fast-path optimized byte copying based on delimiter length */
    if (dlen == 1) {
        char d_char = delim[0];
        for (size_t i = 1; i < count; i++) {
            *w++ = d_char;
            size_t slen = strlen(strings[i]);
            if (slen) {
                memcpy(w, strings[i], slen);
                w += slen;
            }
        }
    } else if (dlen > 1) {
        for (size_t i = 1; i < count; i++) {
            memcpy(w, delim, dlen);
            w += dlen;
            size_t slen = strlen(strings[i]);
            if (slen) {
                memcpy(w, strings[i], slen);
                w += slen;
            }
        }
    } else {
        for (size_t i = 1; i < count; i++) {
            size_t slen = strlen(strings[i]);
            if (slen) {
                memcpy(w, strings[i], slen);
                w += slen;
            }
        }
    }

    *w = '\0';
    return r;
}

/**
 * @brief Concatenates a variadic list of strings into a newly allocated buffer.
 *
 * @param[in] first  First string argument. Must be terminated with a trailing NULL argument.
 * @param[in] ...    Subsequent string arguments terminated by explicit NULL pointer.
 * @return Newly allocated concatenated string result, or NULL on allocation error or size overflow.
 * @note Caller must free the returned string using `free()`.
 * @warning The variadic call list MUST terminate with a NULL sentinel value: `str_concat(s1, s2, NULL);`
 */
static inline char* str_concat(const char* first, ...) {
    size_t total = 0;
    {
        va_list ap;
        va_start(ap, first);
        const char* s = first;
        while (s) {
            size_t len = strlen(s);
            if (len > SIZE_MAX - total) {
                va_end(ap);
                return NULL;
            }
            total += len;
            s = va_arg(ap, const char*);
        }
        va_end(ap);
    }

    char* r = (char*)malloc(total + 1);
    if (!r) return NULL;

    size_t pos = 0;
    {
        va_list ap;
        va_start(ap, first);
        const char* s = first;
        while (s) {
            size_t len = strlen(s);
            memcpy(r + pos, s, len);
            pos += len;
            s = va_arg(ap, const char*);
        }
        va_end(ap);
    }
    r[pos] = '\0';
    return r;
}

/**
 * @brief Calculates 32-bit FNV-1a (Fowler-Noll-Vo) non-cryptographic hash digest of a string.
 *
 * @param[in] str Target string.
 * @return Calculated 32-bit hash, or 0 if `str` is NULL.
 * @note Safe for concurrent use.
 */
static inline uint32_t str_hash(const char* str) {
    if (!str) return 0u;
    uint32_t h = 2166136261u; /* FNV-1a 32-bit initial offset basis */
    for (; *str; str++) {
        h ^= (unsigned char)*str;
        h *= 16777619u; /* FNV-1a 32-bit prime factor */
    }
    return h;
}

/* =========================================================================
 * Number -> String Conversions
 * ======================================================================= */

/**
 * @brief Formats a signed integer value into a caller-provided character buffer.
 *
 * @param[in]  value   Integer payload value to convert.
 * @param[out] buf     Destination buffer.
 * @param[in]  buflen  Capacity of output destination buffer in bytes.
 * @return Pointer to output destination `buf`, or NULL if truncated or invalid parameters.
 */
static inline char* str_from_int(int value, char* buf, size_t buflen) {
    if (!buf || buflen == 0) return NULL;
    int need = snprintf(buf, buflen, "%d", value);
    if (need < 0 || (size_t)need >= buflen) return NULL;
    return buf;
}

/**
 * @brief Formats a signed long value into a caller-provided character buffer.
 *
 * @param[in]  value   Long integer payload value to convert.
 * @param[out] buf     Destination buffer.
 * @param[in]  buflen  Capacity of output destination buffer in bytes.
 * @return Pointer to output destination `buf`, or NULL if truncated or invalid parameters.
 */
static inline char* str_from_long(long value, char* buf, size_t buflen) {
    if (!buf || buflen == 0) return NULL;
    int need = snprintf(buf, buflen, "%ld", value);
    if (need < 0 || (size_t)need >= buflen) return NULL;
    return buf;
}

/**
 * @brief Formats a double-precision floating point value into a caller-provided character buffer.
 *
 * @param[in]  value      Double floating point value to convert.
 * @param[in]  precision  Decimal fraction precision digits (capped between 0 and 64; default 6 if negative).
 * @param[out] buf        Destination buffer.
 * @param[in]  buflen     Capacity of output destination buffer in bytes.
 * @return Pointer to output destination `buf`, or NULL if truncated or invalid parameters.
 */
static inline char* str_from_double(double value, int precision, char* buf, size_t buflen) {
    if (!buf || buflen == 0) return NULL;
    if (precision < 0) precision = 6;
    if (precision > 64) precision = 64;
    int need = snprintf(buf, buflen, "%.*f", precision, value);
    if (need < 0 || (size_t)need >= buflen) return NULL;
    return buf;
}

/* =========================================================================
 * Legacy / MSVC Platform Helpers
 * ======================================================================= */

#if defined(_MSC_VER)
/**
 * @brief POSIX `strcasecmp` compatibility wrapper for MSVC targets.
 *
 * Performs case-insensitive comparison of two NUL-terminated strings.
 *
 * @param[in] s1 First string operand.
 * @param[in] s2 Second string operand.
 * @return Less than 0 if s1 < s2, 0 if s1 == s2, greater than 0 if s1 > s2.
 */
static inline int strcasecmp(const char* s1, const char* s2) {
    if (s1 == s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    return _stricmp(s1, s2);
}

/**
 * @brief POSIX `strncasecmp` compatibility wrapper for MSVC targets.
 *
 * Performs bounded case-insensitive comparison of two strings up to `n` characters.
 *
 * @param[in] s1 First string operand.
 * @param[in] s2 Second string operand.
 * @param[in] n  Maximum byte comparison limit.
 * @return Less than 0 if s1 < s2, 0 if s1 == s2, greater than 0 if s1 > s2.
 */
static inline int strncasecmp(const char* s1, const char* s2, size_t n) {
    if (n == 0) return 0;
    if (s1 == s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    return _strnicmp(s1, s2, n);
}

/**
 * @brief GNU `strcasestr` compatibility wrapper for MSVC targets.
 *
 * Performs case-insensitive substring search within a haystack string.
 *
 * @param[in] haystack Haystack string to search within.
 * @param[in] needle   Substring payload to locate.
 * @return Pointer to first case-insensitive substring match, or NULL if not found.
 */
static inline char* strcasestr(const char* haystack, const char* needle) {
    if (!needle || *needle == '\0') return (char*)haystack;
    if (!haystack) return NULL;
    const size_t nlen = strlen(needle);
    while (*haystack) {
        if (strncasecmp(haystack, needle, nlen) == 0) return (char*)haystack;
        haystack++;
    }
    return NULL;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* __STR_H__ */
