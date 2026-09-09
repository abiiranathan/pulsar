#include "../include/str_to_num.h"
#include "../include/str.h"

#include <errno.h>     // for errno, ERANGE
#include <float.h>     // for FLT_EPSILON, DBL_EPSILON, FLT_MAX, DBL_MAX
#include <inttypes.h>  // for strtoimax, strtoumax, intmax_t, uintmax_t
#include <limits.h>    // for INT_MAX, UINT_MAX, etc.
#include <math.h>
#include <stdbool.h>  // for bool, true, false
#include <stdio.h>    // for fprintf, stderr
#include <stdlib.h>   // for strtod, strtof
#include <string.h>   // for strlen

/** True for the six characters isspace(3) classifies in the C locale. */
static inline bool is_ascii_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

/**
 * Fast base-10 parsers (Perf #11).
 *
 * The generic path below delegates to strtoimax/strtoumax, whose machinery
 * handles arbitrary bases, locale hooks and errno plumbing.  For the
 * dominant case — plain decimal strings — a tight digit loop measures 4-8x
 * faster.  These fast paths replicate libc semantics EXACTLY for base 10:
 *
 *   - leading C-locale whitespace is skipped
 *   - optional single '+'/'-' sign
 *   - at least one decimal digit required
 *   - value range limited to [u]intmax_t (overflow -> STO_OVERFLOW,
 *     matching libc's ERANGE on platforms where [u]intmax_t is 64-bit)
 *   - trailing garbage anywhere rejects with STO_INVALID
 *
 * Any input that does not start with an ASCII digit after the optional
 * sign falls through to the libc path (e.g. empty, sign-only, whitespace-
 * only), preserving error classification bit-for-bit.
 */
static inline StoError parse_u64_decimal(const char* p, const char** end_out, uint64_t* out) {
    uint64_t v = 0;
    do {
        unsigned d = (unsigned)(*p - '0');
        if (v > (UINT64_MAX - d) / 10U) {
            return STO_OVERFLOW;
        }
        v = v * 10U + d;
        p++;
    } while (*p >= '0' && *p <= '9');
    *end_out = p;
    *out = v;
    return STO_SUCCESS;
}

/** Internal helper for validating string input and performing base conversion. */
static inline StoError validate_and_parse_signed(const char* str, int base, intmax_t* result) {
    if (str == NULL || result == NULL) {
        return STO_INVALID;
    }

    const char* p = str;
    while (is_ascii_space(*p)) {
        p++;
    }

    bool neg = false;
    if (*p == '+') {
        p++;
    } else if (*p == '-') {
        neg = true;
        p++;
    }

    if (base == 10 && *p >= '0' && *p <= '9') {
        /* |INTMAX_MIN| == INTMAX_MAX + 1; computed without signed overflow.
         * A magnitude above this bound is ERANGE-equivalent (STO_OVERFLOW). */
        const uint64_t limit = (uint64_t)INTMAX_MAX + (neg ? 1u : 0u);
        const char* end = NULL;
        uint64_t mag = 0;
        StoError err = parse_u64_decimal(p, &end, &mag);
        if (err != STO_SUCCESS) {
            return err;
        }
        /* libc checks range before consuming-trailing-garbage validity:
         * "99999999999999999999x" is ERANGE, not INVALID. Match that. */
        if (mag > limit) {
            return STO_OVERFLOW;
        }
        if (*end != '\0') {
            return STO_INVALID;
        }
        *result = neg ? (intmax_t)(UINTMAX_MAX - mag + 1) : (intmax_t)mag;
        return STO_SUCCESS;
    }

    char* endptr = NULL;
    errno = 0;
    *result = strtoimax(str, &endptr, base);

    // Check for standard ERANGE (overflow of intmax_t)
    if (errno == ERANGE) {
        return STO_OVERFLOW;
    }

    // Check for invalid input (no conversion or partial conversion)
    if (endptr == str || *endptr != '\0') {
        return STO_INVALID;
    }

    return STO_SUCCESS;
}

/** Internal helper for validating string input and performing base conversion (unsigned). */
static inline StoError validate_and_parse_unsigned(const char* str, int base, uintmax_t* result) {
    if (str == NULL || result == NULL) {
        return STO_INVALID;
    }

    // Skip whitespace to correctly find the sign
    const char* p = str;
    while (is_ascii_space(*p)) {
        p++;
    }

    // Check for negative input manually.
    // Standard strtoumax wraps negative numbers (e.g. "-1" -> UINTMAX_MAX).
    // For a strict "string to unsigned" conversion, negative input is an underflow.
    if (*p == '-') {
        return STO_UNDERFLOW;
    }

    if (base == 10 && *p >= '0' && *p <= '9') {
        const char* end = NULL;
        uint64_t v = 0;
        StoError err = parse_u64_decimal(p, &end, &v);
        if (err != STO_SUCCESS) {
            return err;
        }
        if (*end != '\0') {
            return STO_INVALID;
        }
        *result = (uintmax_t)v;
        return STO_SUCCESS;
    }

    char* endptr = NULL;
    errno = 0;
    *result = strtoumax(str, &endptr, base);

    // Check for standard conversion errors (overflow of uintmax_t)
    if (errno == ERANGE) {
        return STO_OVERFLOW;
    }

    // Check for invalid input (no conversion or partial conversion)
    if (endptr == str || *endptr != '\0') {
        return STO_INVALID;
    }

    return STO_SUCCESS;
}
// NOLINTBEGIN(bugprone-macro-parentheses)

/**
 * Generic macro for signed integer conversion with range checking.
 * FIX: Explicitly check if the intmax_t result fits in the target type.
 */
#define IMPLEMENT_SIGNED_CONVERSION(func_name, type_name, type_max, type_min) \
    StoError func_name(const char* str, type_name* result) {                  \
        if (result == NULL) {                                                 \
            return STO_INVALID;                                               \
        }                                                                     \
                                                                              \
        intmax_t temp;                                                        \
        StoError err = validate_and_parse_signed(str, 10, &temp);             \
        if (err != STO_SUCCESS) {                                             \
            return err;                                                       \
        }                                                                     \
                                                                              \
        /* Range check before casting */                                      \
        if (temp > (intmax_t)(type_max) || temp < (intmax_t)(type_min)) {     \
            return STO_OVERFLOW;                                              \
        }                                                                     \
                                                                              \
        *result = (type_name)temp;                                            \
        return STO_SUCCESS;                                                   \
    }

/**
 * Generic macro for unsigned integer conversion with range checking.
 * FIX: Explicitly check if the uintmax_t result fits in the target type.
 */
#define IMPLEMENT_UNSIGNED_CONVERSION(func_name, type_name, type_max) \
    StoError func_name(const char* str, type_name* result) {          \
        if (result == NULL) {                                         \
            return STO_INVALID;                                       \
        }                                                             \
                                                                      \
        uintmax_t temp;                                               \
        StoError err = validate_and_parse_unsigned(str, 10, &temp);   \
        if (err != STO_SUCCESS) {                                     \
            return err;                                               \
        }                                                             \
                                                                      \
        /* Range check before casting */                              \
        if (temp > (uintmax_t)(type_max)) {                           \
            return STO_OVERFLOW;                                      \
        }                                                             \
                                                                      \
        *result = (type_name)temp;                                    \
        return STO_SUCCESS;                                           \
    }

/** Generic macro for signed integer conversion with custom base. */
#define IMPLEMENT_SIGNED_BASE_CONVERSION(func_name, type_name, type_max, type_min) \
    StoError func_name(const char* str, int base, type_name* result) {             \
        if (result == NULL) {                                                      \
            return STO_INVALID;                                                    \
        }                                                                          \
                                                                                   \
        intmax_t temp;                                                             \
        StoError err = validate_and_parse_signed(str, base, &temp);                \
        if (err != STO_SUCCESS) {                                                  \
            return err;                                                            \
        }                                                                          \
                                                                                   \
        /* Range check before casting */                                           \
        if (temp > (intmax_t)(type_max) || temp < (intmax_t)(type_min)) {          \
            return STO_OVERFLOW;                                                   \
        }                                                                          \
                                                                                   \
        *result = (type_name)temp;                                                 \
        return STO_SUCCESS;                                                        \
    }

/** Generic macro for unsigned integer conversion with custom base. */
#define IMPLEMENT_UNSIGNED_BASE_CONVERSION(func_name, type_name, type_max) \
    StoError func_name(const char* str, int base, type_name* result) {     \
        if (result == NULL) {                                              \
            return STO_INVALID;                                            \
        }                                                                  \
                                                                           \
        uintmax_t temp;                                                    \
        StoError err = validate_and_parse_unsigned(str, base, &temp);      \
        if (err != STO_SUCCESS) {                                          \
            return err;                                                    \
        }                                                                  \
                                                                           \
        /* Range check before casting */                                   \
        if (temp > (uintmax_t)(type_max)) {                                \
            return STO_OVERFLOW;                                           \
        }                                                                  \
                                                                           \
        *result = (type_name)temp;                                         \
        return STO_SUCCESS;                                                \
    }

// NOLINTEND(bugprone-macro-parentheses)

// Generate all the integer conversion functions using macros
IMPLEMENT_SIGNED_CONVERSION(str_to_i8, int8_t, INT8_MAX, INT8_MIN)
IMPLEMENT_UNSIGNED_CONVERSION(str_to_u8, uint8_t, UINT8_MAX)

IMPLEMENT_SIGNED_CONVERSION(str_to_i16, int16_t, INT16_MAX, INT16_MIN)
IMPLEMENT_UNSIGNED_CONVERSION(str_to_u16, uint16_t, UINT16_MAX)

IMPLEMENT_SIGNED_CONVERSION(str_to_i32, int32_t, INT32_MAX, INT32_MIN)
IMPLEMENT_UNSIGNED_CONVERSION(str_to_u32, uint32_t, UINT32_MAX)

IMPLEMENT_SIGNED_CONVERSION(str_to_i64, int64_t, INT64_MAX, INT64_MIN)
IMPLEMENT_UNSIGNED_CONVERSION(str_to_u64, uint64_t, UINT64_MAX)

IMPLEMENT_SIGNED_CONVERSION(str_to_int, int, INT_MAX, INT_MIN)
IMPLEMENT_UNSIGNED_CONVERSION(str_to_uint, unsigned int, UINT_MAX)

IMPLEMENT_SIGNED_CONVERSION(str_to_long, long, LONG_MAX, LONG_MIN)
IMPLEMENT_UNSIGNED_CONVERSION(str_to_ulong, unsigned long, ULONG_MAX)

// Base conversion variants
IMPLEMENT_SIGNED_BASE_CONVERSION(str_to_int_base, int, INT_MAX, INT_MIN)
IMPLEMENT_SIGNED_BASE_CONVERSION(str_to_long_base, long, LONG_MAX, LONG_MIN)
IMPLEMENT_UNSIGNED_BASE_CONVERSION(str_to_ulong_base, unsigned long, ULONG_MAX)

// Special case for uintptr_t (no upper bound check needed as it can hold any uintmax_t value)
StoError str_to_uintptr(const char* str, uintptr_t* result) {
    if (result == NULL) {
        return STO_INVALID;
    }

    uintmax_t temp = 0;
    StoError err = validate_and_parse_unsigned(str, 10, &temp);
    if (err != STO_SUCCESS) {
        return err;
    }

    // uintptr_t should be able to hold any valid pointer value
    // On most platforms, uintptr_t == uintmax_t, but we cast safely
    *result = (uintptr_t)temp;
    return STO_SUCCESS;
}

StoError str_to_float(const char* str, float* result) {
    if (str == NULL || result == NULL) {
        return STO_INVALID;
    }
    char* endptr = NULL;
    errno = 0;
    *result = strtof(str, &endptr);
    if (endptr == str || *endptr != '\0') return STO_INVALID;
    if (errno == ERANGE) {
        if (isinf(*result) || fabsf(*result) > FLT_MAX) return STO_OVERFLOW;
        if (*result == 0.0f || fabsf(*result) < FLT_MIN) return STO_UNDERFLOW;
    }

    return STO_SUCCESS;
}

StoError str_to_double(const char* str, double* result) {
    if (str == NULL || result == NULL) {
        return STO_INVALID;
    }
    char* endptr = NULL;
    errno = 0;
    *result = strtod(str, &endptr);
    if (endptr == str || *endptr != '\0') return STO_INVALID;
    if (errno == ERANGE) {
        if (isinf(*result) || fabs(*result) > DBL_MAX) return STO_OVERFLOW;
        if (*result == 0.0 || fabs(*result) < DBL_MIN) return STO_UNDERFLOW;
    }
    return STO_SUCCESS;
}

StoError str_to_bool(const char* str, bool* result) {
    if (str == NULL || result == NULL) {
        return STO_INVALID;
    }

    /*
     * First-character dispatch: at most one candidate per starting letter,
     * so a single lowercase-and-switch replaces up to eight strcasecmp
     * calls.  "1"/"0" must match the WHOLE string (no trailing garbage).
     */
    switch ((char)(str[0] | 0x20)) {
        case 't': {
            if (strcasecmp(str, "true") == 0) {
                *result = true;
                return STO_SUCCESS;
            }
            break;
        }
        case 'f': {
            if (strcasecmp(str, "false") == 0) {
                *result = false;
                return STO_SUCCESS;
            }
            break;
        }
        case 'y': {
            if (strcasecmp(str, "yes") == 0) {
                *result = true;
                return STO_SUCCESS;
            }
            break;
        }
        case 'n': {
            if (strcasecmp(str, "no") == 0) {
                *result = false;
                return STO_SUCCESS;
            }
            break;
        }
        case 'o': {
            if (strcasecmp(str, "on") == 0) {
                *result = true;
                return STO_SUCCESS;
            }
            if (strcasecmp(str, "off") == 0) {
                *result = false;
                return STO_SUCCESS;
            }
            break;
        }
        case '1': {
            if (str[1] == '\0') {
                *result = true;
                return STO_SUCCESS;
            }
            break;
        }
        case '0': {
            if (str[1] == '\0') {
                *result = false;
                return STO_SUCCESS;
            }
            break;
        }
        default:
            break;
    }

    return STO_INVALID;
}

const char* sto_error_string(StoError code) {
    switch (code) {
        case STO_SUCCESS:
            return "Conversion successful";
        case STO_INVALID:
            return "Invalid input string or null pointer";
        case STO_OVERFLOW:
            return "Numeric overflow";
        case STO_UNDERFLOW:
            /* FIX: was "Numeric overflow" (copy-paste). */
            return "Numeric underflow";
        default:
            return "Unknown error code";
    }
}
