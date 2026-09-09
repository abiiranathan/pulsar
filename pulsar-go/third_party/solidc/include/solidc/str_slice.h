#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ─── Compiler Branch Hints ───────────────────────────────────────────────────

#if defined(__GNUC__) || defined(__clang__)
#define SS_LIKELY(x)   __builtin_expect(!!(x), 1)
#define SS_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define SS_LIKELY(x)   (x)
#define SS_UNLIKELY(x) (x)
#endif

// ─── Types ────────────────────────────────────────────────────────────────────

typedef struct {
    const char* data;  // pointer into external buffer
    size_t len;        // number of bytes in the view
} StrSlice;

typedef enum {
    SS_OK = 0,
    SS_NULL = 1,       // null data pointer
    SS_BOUNDS = 2,     // out-of-range indices
    SS_NOT_FOUND = 3,  // substring not found
    SS_OVERFLOW = 4,   // value exceeds target type's range
    SS_INVALID = 5,    // malformed input
} StrSliceErr;

// ss_from() wraps a pointer and length into a slice (does not copy).
static inline StrSlice ss_from(const char* data, size_t len) {
    return (StrSlice){.data = data, .len = len};
}

// Wrap a null-terminated C string (measures with strlen at call time).
static inline StrSlice ss_from_cstr(const char* cstr) {
    if (SS_UNLIKELY(!cstr)) return (StrSlice){0};
    return (StrSlice){.data = cstr, .len = strlen(cstr)};
}

#define SS_LIT(literal) ((StrSlice){.data = ("" literal), .len = sizeof(literal) - 1})

// Empty slice (len == 0, data may be NULL).
static inline StrSlice ss_empty(void) { return (StrSlice){0}; }

// Print a slice to stdout (for debugging).
static inline void ss_print(StrSlice s) {
    if (s.data) printf("%.*s", (int)s.len, s.data);
}

static inline void ss_println(StrSlice s) {
    ss_print(s);
    putchar('\n');
}

// A slice is valid if it has a non-null data pointer or zero length (empty view).
static inline bool ss_is_valid(StrSlice s) { return s.len == 0 || s.data != NULL; }

// A slice is empty if its length is zero, regardless of the data pointer.
static inline bool ss_is_empty(StrSlice s) { return s.len == 0; }

// O(1) length knowledge: direct allocation and copy without redundant strlen/strnlen
static inline char* ss_to_owned_cstr(StrSlice s) {
    if (SS_UNLIKELY(!ss_is_valid(s))) return NULL;
    char* out = (char*)malloc(s.len + 1);
    if (SS_UNLIKELY(!out)) return NULL;
    if (s.len > 0) memcpy(out, s.data, s.len);
    out[s.len] = '\0';
    return out;
}

// ─── Sub-slicing ──────────────────────────────────────────────────────────────

// Overflow-safe bounds check: avoids (start + len > s.len) wrapping bugs
static inline StrSlice ss_slice(StrSlice s, size_t start, size_t len, StrSliceErr* err) {
    if (SS_UNLIKELY(!ss_is_valid(s))) {
        if (err) *err = SS_NULL;
        return ss_empty();
    }
    if (SS_UNLIKELY(start > s.len || len > s.len - start)) {
        if (err) *err = SS_BOUNDS;
        return ss_empty();
    }
    if (err) *err = SS_OK;
    return (StrSlice){.data = s.data + start, .len = len};
}

// Chop off the first `n` bytes.
static inline StrSlice ss_skip(StrSlice s, size_t n) {
    if (n >= s.len) return ss_empty();
    return (StrSlice){.data = s.data + n, .len = s.len - n};
}

// Keep only the first `n` bytes.
static inline StrSlice ss_take(StrSlice s, size_t n) {
    if (n > s.len) n = s.len;
    return (StrSlice){.data = s.data, .len = n};
}

// ─── Comparison ───────────────────────────────────────────────────────────────

static inline bool ss_equal(StrSlice a, StrSlice b) {
    return a.len == b.len && (a.data == b.data || memcmp(a.data, b.data, a.len) == 0);
}

// Correct ASCII case-insensitive equality: fixes '@'/''`'' and '['/'{'' collision bugs
static inline bool ss_equal_nocase(StrSlice a, StrSlice b) {
    if (a.len != b.len) return false;
    if (a.data == b.data) return true;

    const unsigned char* pa = (const unsigned char*)a.data;
    const unsigned char* pb = (const unsigned char*)b.data;
    size_t len = a.len;

    for (size_t i = 0; i < len; ++i) {
        unsigned char ca = pa[i];
        unsigned char cb = pb[i];
        if (ca == cb) continue;  // Fast-path identical characters
        // ASCII letter case-flip check
        if (((ca ^ cb) != 0x20) || (unsigned)((ca | 0x20) - 'a') > ('z' - 'a')) {
            return false;
        }
    }
    return true;
}

static inline bool ss_starts_with(StrSlice s, StrSlice prefix) {
    return s.len >= prefix.len &&
           (s.data == prefix.data || memcmp(s.data, prefix.data, prefix.len) == 0);
}

static inline bool ss_ends_with(StrSlice s, StrSlice suffix) {
    return s.len >= suffix.len && memcmp(s.data + s.len - suffix.len, suffix.data, suffix.len) == 0;
}

// Returns the byte offset of the first occurrence of `needle`, or (size_t)-1.
static inline size_t ss_find(StrSlice haystack, StrSlice needle) {
    if (SS_UNLIKELY(needle.len == 0)) return 0;
    if (SS_UNLIKELY(needle.len > haystack.len)) return (size_t)-1;

    const char* h = haystack.data;
    const char* n = needle.data;
    size_t n_len = needle.len;

    // Single character fast-path: 100% vectorized SIMD memchr
    if (n_len == 1) {
        const char* p = (const char*)memchr(h, n[0], haystack.len);
        return p ? (size_t)(p - h) : (size_t)-1;
    }

    char first = n[0];
    size_t max_idx = haystack.len - n_len;

    for (size_t i = 0; i <= max_idx;) {
        const char* p = (const char*)memchr(h + i, first, max_idx - i + 1);
        if (!p) return (size_t)-1;
        i = (size_t)(p - h);
        if (memcmp(p + 1, n + 1, n_len - 1) == 0) {
            return i;
        }
        ++i;
    }
    return (size_t)-1;
}

static inline bool ss_contains(StrSlice s, StrSlice needle) {
    return ss_find(s, needle) != (size_t)-1;
}

// Split at the first occurrence of `sep`.
// On success: *head = everything before sep, *tail = everything after sep.
// Returns SS_NOT_FOUND (and leaves *head/*tail unchanged) if sep absent.
static inline StrSliceErr ss_split_on(StrSlice s, StrSlice sep, StrSlice* head, StrSlice* tail) {
    size_t pos = ss_find(s, sep);
    if (pos == (size_t)-1) return SS_NOT_FOUND;
    *head = ss_take(s, pos);
    *tail = ss_skip(s, pos + sep.len);
    return SS_OK;
}

// ─── Trimming (Branchless Bitmask) ────────────────────────────────────────────

// 9='\t', 10='\n', 13='\r', 32=' '. Zero branches: compiles to `bt` or `shr + and`.
static inline bool _ss_is_space(char c) {
    unsigned char uc = (unsigned char)c;
    return (uc <= 32) && ((0x100002600ULL >> uc) & 1ULL);
}

static inline StrSlice ss_trim(StrSlice s) {
    size_t lo = 0, hi = s.len;
    while (lo < hi && _ss_is_space(s.data[lo])) ++lo;
    while (hi > lo && _ss_is_space(s.data[hi - 1])) --hi;
    return (StrSlice){.data = s.data + lo, .len = hi - lo};
}

static inline bool ss_get(StrSlice s, size_t i, char* out) {
    if (i >= s.len) return false;
    *out = s.data[i];
    return true;
}

// ─── Parsing: Integer (Division-Free) ─────────────────────────────────────────

static inline StrSliceErr ss_to_int(StrSlice s, int* out) {
    if (SS_UNLIKELY(!out)) return SS_NULL;

    size_t i = 0;
    bool neg = false;

    if (i < s.len) {
        if (s.data[i] == '-') {
            neg = true;
            ++i;
        } else if (s.data[i] == '+') {
            ++i;
        }
    }

    if (SS_UNLIKELY(i >= s.len || (unsigned)(s.data[i] - '0') > 9)) return SS_NOT_FOUND;

    // Accumulate in 64-bit register: eliminates division inside loop entirely
    uint64_t acc = 0;
    for (; i < s.len; ++i) {
        unsigned char d = (unsigned char)(s.data[i] - '0');
        if (d > 9) break;
        acc = acc * 10 + d;
        // 2147483648 is max magnitude (INT_MIN = -2147483648)
        if (SS_UNLIKELY(acc > 2147483648ULL)) return SS_OVERFLOW;
    }

    if (neg) {
        if (SS_UNLIKELY(acc > 2147483648ULL)) return SS_OVERFLOW;
        *out = (int)(-(int64_t)acc);
    } else {
        if (SS_UNLIKELY(acc > 2147483647ULL)) return SS_OVERFLOW;
        *out = (int)acc;
    }
    return SS_OK;
}

// ─── Parsing: Double (O(1) Two-Level Scale Lookup) ────────────────────────────

static inline StrSliceErr ss_to_double(StrSlice s, double* out) {
    if (SS_UNLIKELY(!out)) return SS_NULL;

    size_t i = 0;
    bool neg = false;

    if (i < s.len) {
        if (s.data[i] == '-') {
            neg = true;
            ++i;
        } else if (s.data[i] == '+') {
            ++i;
        }
    }

    uint64_t mantissa = 0;
    int dec_shift = 0;
    bool seen_dot = false;
    bool has_digits = false;
    bool saturated = false;

    for (; i < s.len; ++i) {
        char c = s.data[i];
        if (c >= '0' && c <= '9') {
            has_digits = true;
            if (!saturated) {
                uint64_t d = (uint64_t)(c - '0');
                // Branchless division constant check: UINT64_MAX / 10 = 1844674407370955161ULL
                if (SS_UNLIKELY(mantissa >= 1844674407370955161ULL &&
                                (mantissa > 1844674407370955161ULL || d > 5))) {
                    saturated = true;
                    if (!seen_dot) ++dec_shift;
                } else {
                    mantissa = mantissa * 10ull + d;
                    if (seen_dot) --dec_shift;
                }
            } else if (!seen_dot) {
                ++dec_shift;
            }
        } else if (c == '.' && !seen_dot) {
            seen_dot = true;
        } else {
            break;
        }
    }

    if (SS_UNLIKELY(!has_digits)) return SS_NOT_FOUND;

    int exp_shift = 0;
    if (i < s.len && (s.data[i] == 'e' || s.data[i] == 'E')) {
        ++i;
        bool exp_neg = false;
        if (i < s.len) {
            if (s.data[i] == '-') {
                exp_neg = true;
                ++i;
            } else if (s.data[i] == '+') {
                ++i;
            }
        }

        if (SS_UNLIKELY(i >= s.len || s.data[i] < '0' || s.data[i] > '9')) return SS_INVALID;

        for (; i < s.len && s.data[i] >= '0' && s.data[i] <= '9'; ++i) {
            if (exp_shift < 10000) exp_shift = exp_shift * 10 + (s.data[i] - '0');
        }
        if (exp_neg) exp_shift = -exp_shift;
    }

    int total_exp = dec_shift + exp_shift;

    // Two-level O(1) table: covers IEEE 754 limits (10^±308) in 1 multiplication
    static const double _p10_low[16] = {1e0, 1e1, 1e2,  1e3,  1e4,  1e5,  1e6,  1e7,
                                        1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15};
    static const double _p10_high[20] = {1e0,   1e16,  1e32,  1e48,  1e64,  1e80,  1e96,
                                         1e112, 1e128, 1e144, 1e160, 1e176, 1e192, 1e208,
                                         1e224, 1e240, 1e256, 1e272, 1e288, 1e304};

    double result = (double)mantissa;
    if (total_exp != 0) {
        int abs_exp = total_exp < 0 ? -total_exp : total_exp;
        if (abs_exp > 308) abs_exp = 308;

        double scale = _p10_low[abs_exp & 15] * _p10_high[(abs_exp >> 4)];
        result = (total_exp < 0) ? result / scale : result * scale;
    }

    *out = neg ? -result : result;
    return SS_OK;
}

// ─── Parsing: Boolean (Length-Indexed O(1) Jump) ───────────────────────────────

static inline StrSliceErr ss_to_bool(StrSlice s, bool* out) {
    if (SS_UNLIKELY(!out)) return SS_NULL;

    // Fast switch based on slice length completely avoids multiple full-string scans
    switch (s.len) {
        case 1:
            if (s.data[0] == '1') {
                *out = true;
                return SS_OK;
            }
            if (s.data[0] == '0') {
                *out = false;
                return SS_OK;
            }
            break;
        case 2:
            if ((s.data[0] | 0x20) == 'o' && (s.data[1] | 0x20) == 'n') {
                *out = true;
                return SS_OK;
            }
            if ((s.data[0] | 0x20) == 'n' && (s.data[1] | 0x20) == 'o') {
                *out = false;
                return SS_OK;
            }
            break;
        case 3:
            if (ss_equal_nocase(s, SS_LIT("yes"))) {
                *out = true;
                return SS_OK;
            }
            if (ss_equal_nocase(s, SS_LIT("off"))) {
                *out = false;
                return SS_OK;
            }
            break;
        case 4:
            if (ss_equal_nocase(s, SS_LIT("true"))) {
                *out = true;
                return SS_OK;
            }
            break;
        case 5:
            if (ss_equal_nocase(s, SS_LIT("false"))) {
                *out = false;
                return SS_OK;
            }
            break;
        default:
            break;
    }
    return SS_INVALID;
}

#if defined(__cplusplus)
}
#endif
