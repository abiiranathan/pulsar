/**
 * @file unicode.c
 * @brief Implementation of the solidc UTF-8 / Unicode handling library.
 *
 * Design notes for maintainers:
 *
 * - Every "modify in place" function on a `utf8_string*` keeps `length`
 *   (bytes, excluding the NUL) and `count` (codepoints) in sync. Treat
 *   these two fields as derived state: if you add a new mutator, update
 *   both or you will corrupt later operations that trust them.
 *
 * - "Length" almost always means *valid* UTF-8 byte length, computed via
 *   utf8_valid_byte_count(), not strlen(). This matters because malformed
 *   trailing bytes (e.g. a truncated multi-byte sequence at the end of a
 *   buffer) are silently dropped by this library rather than rejected
 *   outright. utf8_copy() is what performs that filtering on construction.
 *
 * - Functions that take raw `char*` (utf8_ltrim, utf8_tolower, etc.) work
 *   directly on caller-owned, NUL-terminated buffers and use strlen()
 *   internally, since there is no utf8_string metadata to maintain.
 *
 * - wchar_t is only guaranteed by C11 to hold values your platform's
 *   wide-character set supports. On Linux/macOS this is effectively a full
 *   32-bit Unicode scalar value in the C/UTF-8 locales solidc targets, but
 *   on Windows wchar_t is 16 bits (UTF-16 code unit). utf8_tolower() and
 *   utf8_toupper() guard against passing codepoints outside what wchar_t
 *   can represent into towlower()/towupper(), since doing so is undefined
 *   behavior per the C standard. See the WCHAR_MAX check in those two
 *   functions.
 */

#include "../include/unicode.h"
#include "macros.h"

#if defined(__SSE2__)
    #include <emmintrin.h>
#endif

#include <stdint.h>  // for SIZE_MAX
#include <stdio.h>   // for fopen, fread, fwrite, fseek, ftell, fclose, printf
#include <stdlib.h>  // for malloc, realloc, free
#include <string.h>  // for memcpy, memmove, memcmp, strstr, strcmp, strlen
#include <wchar.h>   // for WCHAR_MAX
#include <wctype.h>  // for iswspace, iswdigit, iswalpha, iswalnum, iswpunct,
// iswupper, iswlower, towlower, towupper (SOLIDC_CTZ comes from macros.h)

typedef struct {
    size_t valid_bytes;
    size_t codepoints;
} utf8_analysis_t;

/**
 * @brief Performs validation, byte length, and codepoint counting in a single pass.
 *
 * Perf (Perf #15): ASCII runs — the bulk of most real text — are skipped
 * 16 bytes at a time with SSE2 (movemask finds the first non-ASCII byte),
 * falling back to the exact per-sequence scalar classifier otherwise.
 * Classification semantics are byte-for-byte identical to the scalar loop.
 */
/**
 * Returns the byte length of a FULLY valid UTF-8 sequence starting at u,
 * where len bytes are available in the buffer, or 0 if the sequence is
 * malformed or invalid (overlong encodings, surrogate halves
 * U+D800..U+DFFF, and codepoints above U+10FFFF are all rejected).
 *
 * Semantics match utf8_to_codepoint(): a sequence is accepted only when it
 * decodes to a legal scalar value, not merely when its continuation bytes
 * have the right shape.
 */
static inline unsigned utf8_seq_length(const unsigned char* u, size_t len) {
    unsigned char b = u[0];
    uint32_t cp;

    if ((b & 0x80) == 0) {
        return 1;
    }

    if ((b & 0xE0) == 0xC0) {
        if (len < 2 || (u[1] & 0xC0) != 0x80) {
            return 0;
        }
        cp = (((uint32_t)b & 0x1FU) << 6) | (u[1] & 0x3F);
        if (cp < 0x80) {
            return 0; /* overlong */
        }
        return 2;
    }
    if ((b & 0xF0) == 0xE0) {
        if (len < 3 || (u[1] & 0xC0) != 0x80 || (u[2] & 0xC0) != 0x80) {
            return 0;
        }
        cp = (((uint32_t)b & 0x0FU) << 12) | (((uint32_t)u[1] & 0x3F) << 6) | (u[2] & 0x3F);
        if (cp < 0x800) {
            return 0; /* overlong */
        }
        if (cp >= 0xD800 && cp <= 0xDFFF) {
            return 0; /* surrogate */
        }
        return 3;
    }
    if ((b & 0xF8) == 0xF0) {
        if (len < 4 || (u[1] & 0xC0) != 0x80 || (u[2] & 0xC0) != 0x80 || (u[3] & 0xC0) != 0x80) {
            return 0;
        }
        cp = (((uint32_t)b & 0x07U) << 18) | (((uint32_t)u[1] & 0x3F) << 12) | (((uint32_t)u[2] & 0x3F) << 6) |
             (u[3] & 0x3F);
        if (cp < 0x10000 || cp > UNICODE_MAX_CODEPOINT) {
            return 0; /* overlong / out of range */
        }
        return 4;
    }
    return 0; /* lone continuation byte or invalid leading byte */
}

static inline utf8_analysis_t utf8_analyze(const char* s) {
    utf8_analysis_t analysis = {0, 0};
    if (!s) return analysis;

#if defined(__SSE2__)
    /*
     * Two-mode scanner:
     *   SIMD mode  - skips whole 16-byte ASCII runs (movemask finds the
     *                first non-ASCII byte instantly).
     *   Scalar mode- classifies one UTF-8 sequence per iteration using the
     *                exact full-validation logic, then re-arms SIMD mode as
     *                soon as the next byte is ASCII again.
     * strlen() bounds the vector loads so they never cross the NUL.
     * Classification results are byte-for-byte identical to the pure
     * scalar loop below.
     */
    size_t len = strlen(s);
    size_t i = 0;
    int try_simd = 1;

    while (i < len) {
        if (try_simd && i + 16 <= len) {
            __m128i v = _mm_loadu_si128((const __m128i*)(s + i));
            uint32_t hi = (uint32_t)_mm_movemask_epi8(v); /* set where byte >= 0x80 */
            if (hi == 0) {
                analysis.valid_bytes += 16;
                analysis.codepoints += 16;
                i += 16;
                continue; /* still a candidate run: stay in SIMD mode */
            }
            int pos = SOLIDC_CTZ(hi); /* first non-ASCII byte in this block */
            analysis.valid_bytes += (size_t)pos;
            analysis.codepoints += (size_t)pos;
            i += (size_t)pos;
            try_simd = 0; /* hand off to the scalar classifier */
            continue;
        }

        /* ---- scalar classification of exactly one sequence ---- */
        try_simd = 0;

        unsigned seq = utf8_seq_length((const unsigned char*)s + i, len - i);
        if (seq > 0) {
            analysis.valid_bytes += seq;
            analysis.codepoints++;
            i += seq;
        } else {
            i++; /* malformed or invalid sequence: skip one leading byte */
        }

        if (i < len && ((unsigned char)s[i] & 0x80) == 0) {
            try_simd = 1;
        }
    }
    return analysis;
#else
    size_t len = strlen(s);
    size_t i = 0;
    while (i < len) {
        unsigned seq = utf8_seq_length((const unsigned char*)s + i, len - i);
        if (seq > 0) {
            analysis.valid_bytes += seq;
            analysis.codepoints++;
            i += seq;
        } else {
            i++;
        }
    }
    return analysis;
#endif
}

/* ============================================================================
 * Core Encoding/Decoding Functions
 * ============================================================================ */

/**
 * Converts a Unicode codepoint to its UTF-8 byte sequence representation.
 *
 * UTF-8 encoding uses 1-4 bytes per codepoint:
 * - 1 byte:  U+0000 to U+007F    (0xxxxxxx)
 * - 2 bytes: U+0080 to U+07FF    (110xxxxx 10xxxxxx)
 * - 3 bytes: U+0800 to U+FFFF    (1110xxxx 10xxxxxx 10xxxxxx)
 * - 4 bytes: U+10000 to U+10FFFF (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
 *
 * @param codepoint The Unicode codepoint to convert (must be <= 0x10FFFF).
 * @param utf8 Output buffer that receives the UTF-8 bytes. Must be at least 5 bytes
 *             (4 bytes for max UTF-8 sequence + 1 for null terminator).
 *             Buffer is always null-terminated on success.
 * @note Invalid codepoints (> 0x10FFFF) result in no output and utf8[0] = '\0'.
 * @note This function does not validate surrogate pairs (0xD800-0xDFFF); callers
 *       that need strict validation should check is_valid_codepoint() and surrogate
 *       range separately before calling this function.
 */
void ucp_to_utf8(uint32_t codepoint, char utf8[UTF8_MAX_LEN]) {
    if (!utf8) {
        return;
    }

    if (codepoint <= 0x7F) {
        utf8[0] = (char)codepoint;
        utf8[1] = '\0';
    } else if (codepoint <= 0x7FF) {
        utf8[0] = (char)(0xC0 | (codepoint >> 6));
        utf8[1] = (char)(0x80 | (codepoint & 0x3F));
        utf8[2] = '\0';
    } else if (codepoint <= 0xFFFF) {
        utf8[0] = (char)(0xE0 | (codepoint >> 12));
        utf8[1] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
        utf8[2] = (char)(0x80 | (codepoint & 0x3F));
        utf8[3] = '\0';
    } else if (codepoint <= UNICODE_MAX_CODEPOINT) {
        utf8[0] = (char)(0xF0 | (codepoint >> 18));
        utf8[1] = (char)(0x80 | ((codepoint >> 12) & 0x3F));
        utf8[2] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
        utf8[3] = (char)(0x80 | (codepoint & 0x3F));
        utf8[4] = '\0';
    } else {
        /* Codepoint out of range: produce an empty string rather than garbage. */
        utf8[0] = '\0';
    }
}

/**
 * Decodes a UTF-8 byte sequence to its Unicode codepoint.
 *
 * Validates the UTF-8 sequence for:
 * - Correct continuation byte patterns (10xxxxxx)
 * - Overlong encodings (rejects sequences using more bytes than necessary)
 * - Surrogate pairs (0xD800-0xDFFF, invalid in UTF-8)
 * - Out-of-range values (> 0x10FFFF)
 *
 * @param utf8 Pointer to UTF-8 encoded byte sequence. Must not be NULL.
 * @return The decoded Unicode codepoint, or 0xFFFD (replacement character)
 *         if the sequence is invalid or malformed.
 * @note Only the first complete UTF-8 sequence is examined; trailing bytes
 *       are ignored.
 * @note Relies on short-circuit evaluation of `&&` to avoid reading past a
 *       NUL terminator: if a continuation byte check fails because the byte
 *       is '\0', later operands referencing subsequent bytes are never
 *       evaluated. Do not reorder the conjuncts below without preserving
 *       that property.
 */
uint32_t utf8_to_codepoint(const char* utf8) {
    if (!utf8) {
        return 0xFFFD;  // replacement character
    }

    uint32_t codepoint = 0;
    const uint8_t* u = (const uint8_t*)utf8;

    if ((u[0] & 0x80) == 0) {
        /* 1-byte ASCII sequence. */
        codepoint = u[0];
    } else if ((u[0] & 0xE0) == 0xC0) {
        /* 2-byte sequence. */
        if ((u[1] & 0xC0) == 0x80) {
            codepoint = ((u[0] & 0x1FU) << 6) | (u[1] & 0x3F);
            if (codepoint < 0x80) {
                return 0xFFFD;  // overlong encoding
            }
        } else {
            return 0xFFFD;
        }
    } else if ((u[0] & 0xF0) == 0xE0) {
        /* 3-byte sequence. */
        if ((u[1] & 0xC0) == 0x80 && (u[2] & 0xC0) == 0x80) {
            codepoint = ((u[0] & 0x0FU) << 12) | ((u[1] & 0x3FU) << 6) | (u[2] & 0x3F);
            if (codepoint < 0x800) {
                return 0xFFFD;  // overlong encoding
            }
            if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
                return 0xFFFD;  // surrogate halves are invalid in UTF-8
            }
        } else {
            return 0xFFFD;
        }
    } else if ((u[0] & 0xF8) == 0xF0) {
        /* 4-byte sequence. */
        if ((u[1] & 0xC0) == 0x80 && (u[2] & 0xC0) == 0x80 && (u[3] & 0xC0) == 0x80) {
            codepoint = ((u[0] & 0x07U) << 18) | ((u[1] & 0x3FU) << 12) | ((u[2] & 0x3FU) << 6) | (u[3] & 0x3F);
            if (codepoint < 0x10000) {
                return 0xFFFD;  // overlong encoding
            }
            if (codepoint > UNICODE_MAX_CODEPOINT) {
                return 0xFFFD;
            }
        } else {
            return 0xFFFD;
        }
    } else {
        /* Lone continuation byte or invalid leading byte (0xF8-0xFF). */
        return 0xFFFD;
    }

    return codepoint;
}

/**
 * Counts the number of Unicode codepoints in a UTF-8 string.
 *
 * A codepoint is counted at each UTF-8 leading byte, i.e. any byte that does
 * NOT match the continuation byte pattern (10xxxxxx). This includes ASCII
 * bytes (0xxxxxxx) and the leading bytes of 2/3/4-byte sequences.
 *
 * @param s The null-terminated UTF-8 string. NULL returns 0.
 * @return The number of Unicode codepoints (characters) in the string.
 * @note Malformed input may produce a count that does not match what
 *       utf8_valid_byte_count() would accept; this function only classifies
 *       bytes, it does not perform full structural validation.
 */
size_t utf8_count_codepoints(const char* s) {
    if (!s) {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; s[i] != '\0'; i++) {
        if (((unsigned char)s[i] & 0xC0) != 0x80) {
            count++;
        }
    }
    return count;
}

/**
 * Counts the number of valid UTF-8 bytes in a string.
 *
 * Validates each UTF-8 sequence by checking:
 * - Correct leading byte patterns
 * - Presence of all expected continuation bytes before the NUL terminator
 * - Proper continuation byte format (10xxxxxx)
 *
 * Invalid sequences are skipped one byte at a time (counted as 0 bytes for
 * that position), allowing the scan to recover and keep processing the
 * remainder of a partially corrupted buffer.
 *
 * @param s The null-terminated string to validate. NULL returns 0.
 * @return The total number of bytes belonging to valid UTF-8 sequences.
 * @note This does NOT reject overlong encodings or surrogate codepoints;
 *       use is_valid_utf8() for full structural validation.
 */
size_t utf8_valid_byte_count(const char* s) {
    if (!s) {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; s[i] != '\0';) {
        unsigned char byte = (unsigned char)s[i];
        if ((byte & 0x80) == 0) {
            count++;
            i++;
        } else if ((byte & 0xE0) == 0xC0 && s[i + 1] != '\0') {
            if (((unsigned char)s[i + 1] & 0xC0) == 0x80) {
                count += 2;
                i += 2;
            } else {
                i++;
            }
        } else if ((byte & 0xF0) == 0xE0 && s[i + 1] != '\0' && s[i + 2] != '\0') {
            if (((unsigned char)s[i + 1] & 0xC0) == 0x80 && ((unsigned char)s[i + 2] & 0xC0) == 0x80) {
                count += 3;
                i += 3;
            } else {
                i++;
            }
        } else if ((byte & 0xF8) == 0xF0 && s[i + 1] != '\0' && s[i + 2] != '\0' && s[i + 3] != '\0') {
            if (((unsigned char)s[i + 1] & 0xC0) == 0x80 && ((unsigned char)s[i + 2] & 0xC0) == 0x80 &&
                ((unsigned char)s[i + 3] & 0xC0) == 0x80) {
                count += 4;
                i += 4;
            } else {
                i++;
            }
        } else {
            i++;
        }
    }
    return count;
}

/**
 * Determines the byte length of a UTF-8 character from its first byte.
 *
 * UTF-8 character lengths by leading byte:
 * - 0x00-0x7F: 1 byte  (ASCII)
 * - 0xC2-0xDF: 2 bytes
 * - 0xE0-0xEF: 3 bytes
 * - 0xF0-0xF4: 4 bytes
 *
 * @param str Pointer to the first byte of a UTF-8 character. Must not be NULL.
 * @return The byte length (1-4), or 0 if the byte cannot start a valid
 *         UTF-8 sequence: lone continuation bytes (0x80-0xBF), the always-
 *         overlong 0xC0/0xC1, out-of-range 0xF5-0xF7, and 0xF8-0xFF.
 * @note This only inspects the leading byte; it does not verify that the
 *       expected continuation bytes are actually present and well-formed.
 */
size_t utf8_char_length(const char* str) {
    if (!str) {
        return 0;
    }

    uint8_t b = (uint8_t)*str;
    if (b < 0x80) {
        return 1;
    }
    /* 0xC0/0xC1 would decode to an overlong sequence; 0x80-0xBF are
     * continuation bytes; 0xF5-0xF7 exceed U+10FFFF; 0xF8-0xFF are invalid. */
    if ((b & 0xE0) == 0xC0) {
        return b >= 0xC2 ? 2 : 0;
    }
    if ((b & 0xF0) == 0xE0) {
        return 3;
    }
    if ((b & 0xF8) == 0xF0) {
        return b <= 0xF4 ? 4 : 0;
    }
    return 0;
}

/* ============================================================================
 * Validation Functions
 * ============================================================================ */

/**
 * Validates whether a codepoint is within the valid Unicode range.
 *
 * @param codepoint The Unicode codepoint to validate.
 * @return true if codepoint is in range [0, 0x10FFFF], false otherwise.
 * @note This does NOT check for surrogate halves; a surrogate codepoint
 *       passes this check but is still invalid for UTF-8 encoding purposes.
 */
bool is_valid_codepoint(uint32_t codepoint) { return codepoint <= UNICODE_MAX_CODEPOINT; }

/**
 * Comprehensively validates a UTF-8 encoded string.
 *
 * Validation checks include:
 * - Correct UTF-8 byte sequence structure
 * - Valid continuation bytes (10xxxxxx)
 * - No overlong encodings (shortest form requirement)
 * - No surrogate halves (0xD800-0xDFFF)
 * - Codepoints within the valid Unicode range
 *
 * @param utf8 The null-terminated UTF-8 string to validate. NULL returns false.
 * @return true if the entire string is valid UTF-8, false otherwise.
 * @note An empty string is considered valid.
 */
bool is_valid_utf8(const char* utf8) {
    if (!utf8) {
        return false;
    }

    for (size_t i = 0; utf8[i] != '\0';) {
        unsigned char byte = (unsigned char)utf8[i];
        if ((byte & 0x80) == 0) {
            i++;
        } else if ((byte & 0xE0) == 0xC0) {
            if (utf8[i + 1] == '\0' || ((unsigned char)utf8[i + 1] & 0xC0) != 0x80) {
                return false;
            }
            uint32_t codepoint = ((uint32_t)(byte & 0x1F) << 6) | ((unsigned char)utf8[i + 1] & 0x3F);
            if (codepoint < 0x80) {
                return false;  // overlong encoding
            }
            i += 2;
        } else if ((byte & 0xF0) == 0xE0) {
            if (utf8[i + 1] == '\0' || utf8[i + 2] == '\0' || ((unsigned char)utf8[i + 1] & 0xC0) != 0x80 ||
                ((unsigned char)utf8[i + 2] & 0xC0) != 0x80) {
                return false;
            }
            uint32_t codepoint = ((uint32_t)(byte & 0x0F) << 12) |
                                 ((uint32_t)((unsigned char)utf8[i + 1] & 0x3F) << 6) |
                                 ((unsigned char)utf8[i + 2] & 0x3F);
            if (codepoint < 0x800 || (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
                return false;  // overlong encoding or surrogate half
            }
            i += 3;
        } else if ((byte & 0xF8) == 0xF0) {
            if (utf8[i + 1] == '\0' || utf8[i + 2] == '\0' || utf8[i + 3] == '\0' ||
                ((unsigned char)utf8[i + 1] & 0xC0) != 0x80 || ((unsigned char)utf8[i + 2] & 0xC0) != 0x80 ||
                ((unsigned char)utf8[i + 3] & 0xC0) != 0x80) {
                return false;
            }
            uint32_t codepoint =
                ((uint32_t)(byte & 0x07) << 18) | ((uint32_t)((unsigned char)utf8[i + 1] & 0x3F) << 12) |
                ((uint32_t)((unsigned char)utf8[i + 2] & 0x3F) << 6) | ((unsigned char)utf8[i + 3] & 0x3F);
            if (codepoint < 0x10000 || codepoint > UNICODE_MAX_CODEPOINT) {
                return false;  // overlong encoding or out of range
            }
            i += 4;
        } else {
            return false;  // lone continuation byte or invalid leading byte
        }
    }
    return true;
}

/* ============================================================================
 * Character Classification Functions
 * ============================================================================ */

/**
 * Checks if a Unicode codepoint represents whitespace.
 *
 * @param codepoint The Unicode codepoint to test.
 * @return true if the codepoint is whitespace per the current locale.
 * @note Uses iswspace(), which is only well-defined for values representable
 *       in wint_t/wchar_t under the active locale. See the file-level note
 *       about WCHAR_MAX for platforms with a 16-bit wchar_t.
 */
bool is_codepoint_whitespace(uint32_t codepoint) {
#if WCHAR_MAX < UNICODE_MAX_CODEPOINT
    if (codepoint > (uint32_t)WCHAR_MAX) {
        return false;
    }
#endif
    return iswspace((wint_t)codepoint) != 0;
}

/**
 * Checks if a UTF-8 character represents whitespace.
 *
 * @param utf8 Pointer to a UTF-8 encoded character. Must not be NULL.
 * @return true if the character is whitespace, false otherwise or on error.
 */
bool is_utf8_whitespace(const char* utf8) {
    if (!utf8) {
        return false;
    }
    return is_codepoint_whitespace(utf8_to_codepoint(utf8));
}

/**
 * Checks if a Unicode codepoint represents a digit.
 *
 * @param codepoint The Unicode codepoint to test.
 * @return true if the codepoint is a digit character per the current locale.
 */
bool is_codepoint_digit(uint32_t codepoint) {
#if WCHAR_MAX < UNICODE_MAX_CODEPOINT
    if (codepoint > (uint32_t)WCHAR_MAX) {
        return false;
    }
#endif
    return iswdigit((wint_t)codepoint) != 0;
}

/**
 * Checks if a UTF-8 character represents a digit.
 *
 * @param utf8 Pointer to a UTF-8 encoded character. Must not be NULL.
 * @return true if the character is a digit, false otherwise or on error.
 */
bool is_utf8_digit(const char* utf8) {
    if (!utf8) {
        return false;
    }
    return is_codepoint_digit(utf8_to_codepoint(utf8));
}

/**
 * Checks if a Unicode codepoint represents an alphabetic character.
 *
 * @param codepoint The Unicode codepoint to test.
 * @return true if the codepoint is alphabetic per the current locale.
 */
bool is_codepoint_alpha(uint32_t codepoint) {
#if WCHAR_MAX < UNICODE_MAX_CODEPOINT
    if (codepoint > (uint32_t)WCHAR_MAX) {
        return false;
    }
#endif
    return iswalpha((wint_t)codepoint) != 0;
}

/**
 * Checks if a UTF-8 character represents an alphabetic character.
 *
 * @param utf8 Pointer to a UTF-8 encoded character. Must not be NULL.
 * @return true if the character is alphabetic, false otherwise or on error.
 */
bool is_utf8_alpha(const char* utf8) {
    if (!utf8) {
        return false;
    }
    return is_codepoint_alpha(utf8_to_codepoint(utf8));
}

/**
 * Checks if a Unicode codepoint represents an alphanumeric character.
 *
 * @param codepoint The Unicode codepoint to test.
 * @return true if the codepoint is alphanumeric per the current locale.
 */
bool is_codepoint_alnum(uint32_t codepoint) {
#if WCHAR_MAX < UNICODE_MAX_CODEPOINT
    if (codepoint > (uint32_t)WCHAR_MAX) {
        return false;
    }
#endif
    return iswalnum((wint_t)codepoint) != 0;
}

/**
 * Checks if a UTF-8 character represents an alphanumeric character.
 *
 * @param utf8 Pointer to a UTF-8 encoded character. Must not be NULL.
 * @return true if the character is alphanumeric, false otherwise or on error.
 */
bool is_utf8_alnum(const char* utf8) {
    if (!utf8) {
        return false;
    }
    return is_codepoint_alnum(utf8_to_codepoint(utf8));
}

/**
 * Checks if a Unicode codepoint represents a punctuation character.
 *
 * @param codepoint The Unicode codepoint to test.
 * @return true if the codepoint is punctuation per the current locale.
 */
bool is_codepoint_punct(uint32_t codepoint) {
#if WCHAR_MAX < UNICODE_MAX_CODEPOINT
    if (codepoint > (uint32_t)WCHAR_MAX) {
        return false;
    }
#endif
    return iswpunct((wint_t)codepoint) != 0;
}

/**
 * Checks if a UTF-8 character represents a punctuation character.
 *
 * @param utf8 Pointer to a UTF-8 encoded character. Must not be NULL.
 * @return true if the character is punctuation, false otherwise or on error.
 */
bool is_utf8_punct(const char* utf8) {
    if (!utf8) {
        return false;
    }
    return is_codepoint_punct(utf8_to_codepoint(utf8));
}

/* ============================================================================
 * Internal allocation helpers (not part of the public API)
 * ============================================================================ */

/**
 * Allocates a utf8_string and its data buffer as a single block.
 *
 * The struct and its data live in one malloc'd region: `data` is set to
 * point immediately past the struct within that same block. This halves
 * the allocator overhead and pointer-chasing cost of utf8_new() and
 * utf8_new_with_capacity() compared to allocating the struct and its
 * buffer separately, at the cost of `data` no longer being independently
 * reallocatable or freeable (see utf8_string_grow() for how mutators must
 * grow the buffer instead).
 *
 * @param data_capacity Bytes to reserve for `data`, excluding the implicit
 *                       NUL terminator (one extra byte is always added).
 * @return A newly allocated utf8_string with `data` pointing into the same
 *         block, `data[0] == '\0'`, `length == 0`, `count == 0`, and
 *         `capacity == data_capacity`. NULL on allocation failure.
 */
static utf8_string* utf8_string_alloc(size_t data_capacity) {
    /* Guard against overflow: sizeof(utf8_string) + data_capacity + 1 must
     * not wrap around on platforms with a small size_t. */
    if (data_capacity > SIZE_MAX - sizeof(utf8_string) - 1) {
        return NULL;
    }

    utf8_string* s = (utf8_string*)malloc(sizeof(*s) + data_capacity + 1);
    if (!s) {
        return NULL;
    }

    s->data = (char*)s + sizeof(*s);
    s->data[0] = '\0';
    s->length = 0;
    s->count = 0;
    s->capacity = data_capacity;
    return s;
}

/**
 * Grows a utf8_string's data buffer to at least `min_capacity` bytes,
 * preserving existing content, and fixes up `data` after the underlying
 * realloc().
 *
 * Mutators (utf8_append, utf8_insert, utf8_replace, utf8_replace_all) must
 * call this instead of `realloc(s->data, ...)`, because `s->data` is an
 * interior pointer into the same block as `s` and is therefore not a
 * pointer realloc() may legally be called on by itself.
 *
 * Growth is amortized: when growing is necessary, the new capacity is at
 * least double the old one (subject to the requested minimum), so a
 * sequence of small appends does not degrade to O(n^2) reallocation.
 *
 * @param s_ptr Address of the utf8_string* to grow. On success, *s_ptr is
 *              updated to the (possibly moved) new block; the caller must
 *              use *s_ptr afterward and must not dereference the old
 *              pointer value.
 * @param min_capacity The minimum data capacity (excluding NUL) required.
 * @return true on success, false on allocation failure, in which case
 *         *s_ptr is left pointing at the original, still-valid block.
 */
static bool utf8_string_grow(utf8_string** s_ptr, size_t min_capacity) {
    utf8_string* s = *s_ptr;
    if (s->capacity >= min_capacity) {
        return true;  // already large enough
    }

    size_t new_capacity = s->capacity * 2;
    if (new_capacity < min_capacity) {
        new_capacity = min_capacity;
    }

    if (new_capacity > SIZE_MAX - sizeof(*s) - 1) {
        return false;  // would overflow the allocation size computation
    }

    utf8_string* new_s = (utf8_string*)realloc(s, sizeof(*s) + new_capacity + 1);
    if (!new_s) {
        return false;  // *s_ptr unchanged; original block still valid
    }

    new_s->data = (char*)new_s + sizeof(*new_s);
    new_s->capacity = new_capacity;
    *s_ptr = new_s;
    return true;
}

/* ============================================================================
 * String Object Lifecycle Functions
 * ============================================================================ */

/**
 * Creates a copy of a UTF-8 string containing only valid UTF-8 sequences.
 *
 * @param data The null-terminated UTF-8 string to copy. NULL returns NULL.
 * @return A newly allocated copy of the valid UTF-8 portion, or NULL on
 *         allocation failure.
 * @note Caller must free the returned string using free().
 * @note This returns a plain heap buffer, not a utf8_string, so it is
 *       unrelated to the single-allocation utf8_string layout described in
 *       utf8_string_alloc(); free() remains correct here.
 */
char* utf8_copy(const char* data) {
    if (!data) {
        return NULL;
    }

    size_t length = utf8_valid_byte_count(data);
    char* copy = (char*)malloc(length + 1);
    if (!copy) {
        return NULL;
    }

    memcpy(copy, data, length);
    copy[length] = '\0';
    return copy;
}

/**
 * Creates a new utf8_string object from a C string.
 *
 * Only the valid UTF-8 prefix of `data` (per utf8_valid_byte_count) is
 * stored; malformed trailing bytes are silently dropped.
 *
 * @param data The null-terminated UTF-8 string. NULL returns NULL.
 * @return A newly allocated utf8_string object, or NULL on allocation
 *         failure or NULL input.
 * @note Caller must free the returned object using utf8_free().
 * @note The struct and its data buffer are allocated as a single block;
 *       see utf8_string_alloc().
 */
utf8_string* utf8_new(const char* data) {
    if (!data) {
        return NULL;
    }

    utf8_analysis_t analysis = utf8_analyze(data);

    utf8_string* s = utf8_string_alloc(analysis.valid_bytes);
    if (!s) {
        return NULL;
    }

    memcpy(s->data, data, analysis.valid_bytes);
    s->data[analysis.valid_bytes] = '\0';
    s->length = analysis.valid_bytes;
    s->count = analysis.codepoints;
    return s;
}

/**
 * Creates an empty utf8_string with preallocated capacity.
 *
 * @param capacity The initial byte capacity to allocate (excluding the
 *                  implicit NUL terminator byte).
 * @return A newly allocated empty utf8_string, or NULL on allocation
 *         failure.
 * @note Caller must free the returned object using utf8_free().
 * @note The struct and its data buffer are allocated as a single block;
 *       see utf8_string_alloc().
 */
utf8_string* utf8_new_with_capacity(size_t capacity) { return utf8_string_alloc(capacity); }

/**
 * Frees all resources associated with a utf8_string.
 *
 * @param s The utf8_string to free. NULL is safely ignored.
 * @note After calling this function, the pointer s is invalid and must not
 *       be dereferenced or freed again.
 * @note A single free() suffices: s->data points into the same allocation
 *       as s itself and must not be freed separately.
 */
void utf8_free(utf8_string* s) { free(s); }

/**
 * Duplicates a utf8_string object.
 *
 * @param s The utf8_string to duplicate. Must not be NULL.
 * @return A newly allocated copy, or NULL on allocation failure or if
 *         s->data is NULL.
 * @note Caller must free the returned object using utf8_free().
 */
utf8_string* utf8_clone(const utf8_string* s) {
    if (!s || !s->data) {
        return NULL;
    }
    return utf8_new(s->data);
}

/* ============================================================================
 * String Access and Information Functions
 * ============================================================================ */

/**
 * Returns a pointer to the internal UTF-8 data buffer.
 *
 * @param s The utf8_string object. Must not be NULL.
 * @return Pointer to the internal null-terminated UTF-8 string, or NULL if
 *         s is NULL.
 * @note The returned pointer is owned by the utf8_string; do not free it
 *       directly and do not retain it past the lifetime of s.
 */
const char* utf8_data(const utf8_string* s) {
    if (!s) {
        return NULL;
    }
    return s->data;
}

/**
 * Prints the UTF-8 string content to stdout followed by a newline.
 *
 * @param s The utf8_string to print. Must not be NULL.
 */
void utf8_print(const utf8_string* s) {
    if (!s || !s->data) {
        return;
    }
    printf("%s\n", s->data);
}

/**
 * Prints metadata about the UTF-8 string to stdout.
 *
 * @param s The utf8_string to inspect. Must not be NULL.
 */
void utf8_print_info(const utf8_string* s) {
    if (!s) {
        return;
    }
    printf("Byte Length: %zu\n", s->length);
    printf("Code Points: %zu\n", s->count);
}

/**
 * Prints the Unicode codepoints of the string in U+XXXX format.
 *
 * @param s The utf8_string to print. Must not be NULL.
 */
void utf8_print_codepoints(const utf8_string* s) {
    if (!s || !s->data) {
        return;
    }

    for (size_t i = 0; s->data[i] != '\0';) {
        uint32_t codepoint = utf8_to_codepoint(&s->data[i]);
        printf("U+%04X ", codepoint);

        size_t len = utf8_char_length(&s->data[i]);
        if (len == 0) {
            break;  // stop at the first byte that cannot start a valid sequence
        }
        i += len;
    }
    printf("\n");
}

/* ============================================================================
 * String Search and Comparison Functions
 * ============================================================================ */

/**
 * Finds the byte index of the first occurrence of a substring.
 *
 * @param s The utf8_string to search in. Must not be NULL.
 * @param utf8 The substring to search for. Must not be NULL.
 * @return The byte index of the first occurrence, or -1 if not found or on
 *         error.
 */
int utf8_index_of(const utf8_string* s, const char* utf8) {
    if (!s || !s->data || !utf8) {
        return -1;
    }

    const char* found = strstr(s->data, utf8);
    if (!found) {
        return -1;
    }
    return (int)(found - s->data);
}

/**
 * Finds the byte index of the last occurrence of a substring.
 *
 * @param s The utf8_string to search in. Must not be NULL.
 * @param utf8 The substring to search for. Must not be NULL.
 * @return The byte index of the last occurrence, or -1 if not found, if the
 *         needle is empty/longer than the haystack, or on error.
 * @note Scans byte positions in descending order rather than relying on a
 *       library reverse-search function, since none of strrstr/memrchr is
 *       portable across the POSIX/C11 targets this library supports.
 */
int utf8_last_index_of(const utf8_string* s, const char* utf8) {
    if (!s || !s->data || !utf8) {
        return -1;
    }

    size_t needle_len = utf8_valid_byte_count(utf8);
    if (needle_len == 0 || needle_len > s->length) {
        return -1;
    }

    /* i is the highest byte offset at which the needle could still fit;
     * scan downward so the first match found is the last occurrence. */
    size_t i = s->length - needle_len;
    for (;;) {
        if (memcmp(&s->data[i], utf8, needle_len) == 0) {
            return (int)i;
        }
        if (i == 0) {
            break;
        }
        i--;
    }
    return -1;
}

/**
 * Checks if a string starts with a given prefix.
 *
 * @param str The null-terminated UTF-8 string to check. Must not be NULL.
 * @param prefix The prefix to test for. Must not be NULL.
 * @return true if str starts with prefix, false otherwise.
 * @note Comparison stops as soon as str's bytes diverge from prefix's, so
 *       this is safe to call even if str is shorter than prefix: the
 *       mismatch (or str's own NUL) is hit before reading past str's end.
 */
bool utf8_starts_with(const char* str, const char* prefix) {
    if (!str || !prefix) {
        return false;
    }

    size_t len = utf8_valid_byte_count(prefix);
    for (size_t i = 0; i < len; i++) {
        if (str[i] != prefix[i]) {
            return false;
        }
        if (str[i] == '\0') {
            /* str ended before prefix did; only a match if prefix also ended,
             * which would have been caught by len == i in a well-formed
             * prefix, but guard explicitly for safety. */
            return false;
        }
    }
    return true;
}

/**
 * Checks if a string ends with a given suffix.
 *
 * @param str The null-terminated UTF-8 string to check. Must not be NULL.
 * @param suffix The suffix to test for. Must not be NULL.
 * @return true if str ends with suffix, false otherwise.
 */
bool utf8_ends_with(const char* str, const char* suffix) {
    if (!str || !suffix) {
        return false;
    }

    size_t len = utf8_valid_byte_count(str);
    size_t suf_len = utf8_valid_byte_count(suffix);
    if (suf_len > len) {
        return false;
    }
    return memcmp(&str[len - suf_len], suffix, suf_len) == 0;
}

/**
 * Checks if a string contains a substring.
 *
 * @param str The null-terminated UTF-8 string to search in. Must not be NULL.
 * @param substr The substring to search for. Must not be NULL.
 * @return true if substr is found in str, false otherwise.
 */
bool utf8_contains(const char* str, const char* substr) {
    if (!str || !substr) {
        return false;
    }
    return strstr(str, substr) != NULL;
}

/**
 * Compares two UTF-8 strings lexicographically by byte value.
 *
 * @param s1 First UTF-8 string. NULL is treated as an empty string.
 * @param s2 Second UTF-8 string. NULL is treated as an empty string.
 * @return 0 if equal, a negative value if s1 < s2, a positive value if
 *         s1 > s2.
 */
int utf8_compare(const char* s1, const char* s2) {
    if (!s1 && !s2) {
        return 0;
    }
    if (!s1) {
        return -1;
    }
    if (!s2) {
        return 1;
    }
    return strcmp(s1, s2);
}

/**
 * Compares two UTF-8 strings for equality.
 *
 * @param s1 First UTF-8 string. Must not be NULL.
 * @param s2 Second UTF-8 string. Must not be NULL.
 * @return true if strings are byte-for-byte identical, false otherwise.
 * @note If either argument is NULL, returns true only if both are NULL
 *       (i.e. both pointers are equal), since there is no string content
 *       to compare.
 */
bool utf8_equals(const char* s1, const char* s2) {
    if (!s1 || !s2) {
        return s1 == s2;
    }
    return strcmp(s1, s2) == 0;
}

/* ============================================================================
 * String Modification Functions
 * ============================================================================ */

/**
 * Appends UTF-8 data to the end of a utf8_string.
 *
 * @param s_ptr Address of the utf8_string to append to. Must not be NULL,
 *              and *s_ptr must not be NULL. On success, *s_ptr is updated
 *              to the (possibly relocated) string.
 * @param data The null-terminated UTF-8 string to append. NULL is safely
 *             ignored.
 * @return true on success, false on allocation failure.
 * @note Only the valid UTF-8 prefix of data (per utf8_valid_byte_count) is
 *       appended; malformed trailing bytes are silently dropped, matching
 *       the behavior of utf8_new()/utf8_copy() elsewhere in this library.
 */
bool utf8_append(utf8_string** s_ptr, const char* data) {
    if (!s_ptr || !*s_ptr || !data) {
        return false;
    }

    utf8_string* s = *s_ptr;
    utf8_analysis_t analysis = utf8_analyze(data);
    if (analysis.valid_bytes == 0) {
        return true;
    }

    if (!utf8_string_grow(s_ptr, s->length + analysis.valid_bytes)) {
        return false;
    }
    s = *s_ptr;

    memcpy(&s->data[s->length], data, analysis.valid_bytes);
    s->length += analysis.valid_bytes;
    s->count += analysis.codepoints;
    s->data[s->length] = '\0';
    return true;
}

/**
 * Extracts a substring by byte range.
 *
 * @param s The source utf8_string. Must not be NULL.
 * @param index The starting byte index. Must be < s->length.
 * @param utf8_byte_len The number of bytes to extract. Clamped to the
 *                       remaining length of s if it would otherwise read
 *                       past the end.
 * @return A newly allocated substring, or NULL on allocation failure or
 *         invalid parameters.
 * @note Caller must free the returned string using free().
 * @note Does not validate that the byte range aligns with UTF-8 character
 *       boundaries; callers extracting on codepoint boundaries must compute
 *       index and utf8_byte_len themselves (e.g. via utf8_char_length()).
 */
char* utf8_substr(const utf8_string* s, size_t index, size_t utf8_byte_len) {
    if (!s || !s->data || index >= s->length || utf8_byte_len == 0) {
        return NULL;
    }

    if (index + utf8_byte_len > s->length) {
        utf8_byte_len = s->length - index;
    }

    char* substr = (char*)malloc(utf8_byte_len + 1);
    if (!substr) {
        return NULL;
    }

    memcpy(substr, &s->data[index], utf8_byte_len);
    substr[utf8_byte_len] = '\0';
    return substr;
}

/**
 * Inserts UTF-8 data at a specific byte index.
 *
 * @param s_ptr Address of the utf8_string to modify. Must not be NULL, and
 *              *s_ptr must not be NULL. On success, *s_ptr is updated to
 *              the (possibly relocated) string.
 * @param index The byte index at which to insert. Must be <= (*s_ptr)->length.
 * @param data The null-terminated UTF-8 string to insert. NULL is safely
 *             ignored.
 * @return true on success, false on allocation failure or invalid index.
 */
bool utf8_insert(utf8_string** s_ptr, size_t index, const char* data) {
    if (!s_ptr || !*s_ptr || !(*s_ptr)->data || !data || index > (*s_ptr)->length) {
        return false;
    }

    utf8_string* s = *s_ptr;
    utf8_analysis_t analysis = utf8_analyze(data);
    if (analysis.valid_bytes == 0) {
        return true;
    }

    if (!utf8_string_grow(s_ptr, s->length + analysis.valid_bytes)) {
        return false;
    }
    s = *s_ptr;

    memmove(&s->data[index + analysis.valid_bytes], &s->data[index], s->length - index + 1);
    memcpy(&s->data[index], data, analysis.valid_bytes);
    s->length += analysis.valid_bytes;
    s->count += analysis.codepoints;
    return true;
}

/**
 * Removes a specified number of codepoints starting at a byte index.
 *
 * @param s The utf8_string to modify. Must not be NULL.
 * @param index The starting byte index. Must be < s->length.
 * @param count The number of codepoints (not bytes) to remove. Must be > 0.
 * @return true on success, false if parameters are invalid.
 * @note If fewer than `count` codepoints remain from `index` to the end of
 *       the string, only the codepoints that actually exist are removed;
 *       s->count is decremented by that actual number, not by the
 *       caller-requested `count`, to avoid underflowing the unsigned
 *       codepoint counter.
 */
bool utf8_remove(utf8_string* s, size_t index, size_t count) {
    if (!s || !s->data || index >= s->length || count == 0) {
        return false;
    }

    size_t i = index;
    size_t removed = 0;  // actual codepoints removed, may be less than `count`
    for (; removed < count && i < s->length; removed++) {
        size_t len = utf8_char_length(&s->data[i]);
        if (len == 0) {
            break;  // malformed byte; stop removing here
        }
        i += len;
    }

    if (i > s->length) {
        i = s->length;
    }

    memmove(&s->data[index], &s->data[i], s->length - i + 1);
    s->length -= (i - index);
    s->count -= removed;
    return true;
}

/**
 * Replaces the first occurrence of a substring with another string.
 *
 * @param s_ptr Address of the utf8_string to modify. Must not be NULL, and
 *              *s_ptr must not be NULL. On success, *s_ptr is updated to
 *              the (possibly relocated) string.
 * @param old_str The substring to find and replace. Must not be NULL.
 * @param new_str The replacement string. Must not be NULL.
 * @return true if a replacement occurred, false if old_str was not found,
 *         on allocation failure, or on invalid parameters.
 */
bool utf8_replace(utf8_string** s_ptr, const char* old_str, const char* new_str) {
    if (!s_ptr || !*s_ptr || !(*s_ptr)->data || !old_str || !new_str) {
        return false;
    }

    utf8_string* s = *s_ptr;
    char* found = strstr(s->data, old_str);
    if (!found) {
        return false;
    }

    size_t old_byte_len = utf8_valid_byte_count(old_str);
    size_t new_byte_len = utf8_valid_byte_count(new_str);
    size_t old_count = utf8_count_codepoints(old_str);
    size_t new_count = utf8_count_codepoints(new_str);
    size_t offset = (size_t)(found - s->data);

    if (new_byte_len > old_byte_len) {
        /* Growing: the result is longer than the original, so the buffer
         * may need to expand (and the block may relocate). */
        if (!utf8_string_grow(s_ptr, s->length - old_byte_len + new_byte_len)) {
            return false;  // *s_ptr is left untouched and still valid on failure
        }
        s = *s_ptr;  // utf8_string_grow() may have relocated the block
    }

    memmove(&s->data[offset + new_byte_len], &s->data[offset + old_byte_len], s->length - offset - old_byte_len + 1);
    memcpy(&s->data[offset], new_str, new_byte_len);
    s->length = s->length - old_byte_len + new_byte_len;
    s->count = s->count - old_count + new_count;
    return true;
}

/**
 * Replaces all occurrences of a substring with another string.
 *
 * @param s The utf8_string to modify. Must not be NULL.
 * @param old_str The substring to find and replace. Must not be NULL or
 *                empty.
 * @param new_str The replacement string. Must not be NULL (may be empty to
 *                delete each occurrence of old_str).
 * @return The number of replacements made, or 0 if none found, old_str is
 *         empty, or on error.
 * @note If an allocation fails partway through, the function stops and
 *       returns the count of replacements completed so far; s remains in a
 *       valid (if partially updated) state.
 */
/**
 * Replaces all occurrences of a substring with another string.
 *
 * @param s_ptr Address of the utf8_string to modify. Must not be NULL, and
 *              *s_ptr must not be NULL. On success, *s_ptr is updated to
 *              the (possibly relocated) string.
 * @param old_str The substring to find and replace. Must not be NULL or
 *                empty.
 * @param new_str The replacement string. Must not be NULL (may be empty to
 *                delete each occurrence of old_str).
 * @return The number of replacements made, or 0 if none found, old_str is
 *         empty, or on error.
 * @note If an allocation fails partway through, the function stops and
 *       returns the count of replacements completed so far; *s_ptr remains
 *       valid, reflecting every replacement completed before the failure.
 */
size_t utf8_replace_all(utf8_string** s_ptr, const char* old_str, const char* new_str) {
    if (!s_ptr || !*s_ptr || !(*s_ptr)->data || !old_str || !new_str) {
        return 0;
    }

    size_t old_byte_len = utf8_valid_byte_count(old_str);
    if (old_byte_len == 0) {
        return 0;  // refuse to "replace" an empty needle; that would loop forever
    }

    size_t new_byte_len = utf8_valid_byte_count(new_str);
    size_t old_count = utf8_count_codepoints(old_str);
    size_t new_count = utf8_count_codepoints(new_str);
    size_t replacements = 0;

    utf8_string* s = *s_ptr;
    char* cursor = s->data;
    while ((cursor = strstr(cursor, old_str)) != NULL) {
        size_t offset = (size_t)(cursor - s->data);

        if (new_byte_len > old_byte_len) {
            /* Growing: may need more capacity, which may relocate the block. */
            if (!utf8_string_grow(s_ptr, s->length - old_byte_len + new_byte_len)) {
                return replacements;  // stop here; *s_ptr still valid for prior replacements
            }
            s = *s_ptr;  // utf8_string_grow() may have relocated the block
        }
        cursor = s->data + offset;  // re-derive: s->data may differ even without growth

        memmove(&s->data[offset + new_byte_len], &s->data[offset + old_byte_len],
                s->length - offset - old_byte_len + 1);
        memcpy(&s->data[offset], new_str, new_byte_len);
        s->length = s->length - old_byte_len + new_byte_len;
        s->count = s->count - old_count + new_count;

        cursor += new_byte_len;
        replacements++;
    }

    return replacements;
}

/**
 * Reverses a UTF-8 string by codepoints (not bytes).
 *
 * Each complete UTF-8 character is treated as an atomic unit and its
 * internal byte order is preserved; only the order of characters within
 * the string is reversed.
 *
 * @param s The utf8_string to reverse. Must not be NULL.
 * @return A newly allocated, reversed utf8_string on success, or NULL on failure.
 * @note If a malformed byte sequence is encountered mid-scan, the function
 *       aborts and leaves s unmodified rather than producing a corrupted
 *       result.
 */
utf8_string* utf8_reverse(const utf8_string* s) {
    if (!s || !s->data || s->length == 0) {
        return NULL;
    }

    utf8_string* scratch = utf8_new_with_capacity(s->length);
    if (!scratch) {
        return NULL;
    }

    const char* src = s->data;
    char* dst = scratch->data;
    size_t write_pos = s->length;

    for (size_t i = 0; i < s->length;) {
        size_t len = utf8_char_length(&src[i]);
        if (len == 0 || write_pos < len) {
            free(scratch);
            return NULL;
        }
        write_pos -= len;
        memcpy(&dst[write_pos], &src[i], len);
        i += len;
    }

    dst[s->length] = '\0';
    scratch->length = s->length;
    scratch->count = s->count;

    return scratch;
}

/**
 * Concatenates two utf8_string objects into a new string.
 *
 * @param s1 First utf8_string. Must not be NULL.
 * @param s2 Second utf8_string. Must not be NULL.
 * @return A newly allocated utf8_string containing s1's content followed
 *         by s2's content, or NULL on error.
 * @note Caller must free the returned object using utf8_free().
 */
utf8_string* utf8_concat(const utf8_string* s1, const utf8_string* s2) {
    if (!s1 || !s1->data || !s2 || !s2->data) {
        return NULL;
    }

    utf8_string* result = utf8_new_with_capacity(s1->length + s2->length);
    if (!result) {
        return NULL;
    }

    memcpy(result->data, s1->data, s1->length);
    memcpy(result->data + s1->length, s2->data, s2->length);
    result->data[s1->length + s2->length] = '\0';
    result->length = s1->length + s2->length;
    result->count = s1->count + s2->count;

    return result;
}

/* ============================================================================
 * String Transformation Functions (In-Place)
 * ============================================================================ */

/**
 * Removes leading whitespace from a UTF-8 string in-place.
 *
 * Whitespace is determined by is_utf8_whitespace(), which uses locale
 * settings.
 *
 * @param str The null-terminated UTF-8 string to modify. NULL is safely
 *            ignored.
 */
void utf8_ltrim(char* str) {
    if (!str) {
        return;
    }

    size_t len = strlen(str);
    size_t i = 0;
    while (i < len && is_utf8_whitespace(&str[i])) {
        size_t char_len = utf8_char_length(&str[i]);
        if (char_len == 0) {
            break;  // malformed byte; stop trimming rather than looping
        }
        i += char_len;
    }

    if (i > 0) {
        memmove(str, &str[i], len - i + 1);  // +1 to also move the NUL terminator
    }
}

/**
 * Removes trailing whitespace from a UTF-8 string in-place.
 *
 * Whitespace is determined by is_utf8_whitespace(), which uses locale
 * settings.
 *
 * @param str The null-terminated UTF-8 string to modify. NULL is safely
 *            ignored.
 */
void utf8_rtrim(char* str) {
    if (!str) {
        return;
    }

    size_t len = strlen(str);
    size_t i = len;

    while (i > 0) {
        /* Walk back to the start of the character ending at position i by
         * skipping continuation bytes (10xxxxxx). */
        size_t char_start = i - 1;
        while (char_start > 0 && ((unsigned char)str[char_start] & 0xC0) == 0x80) {
            char_start--;
        }

        size_t char_len = utf8_char_length(&str[char_start]);
        if (char_len > 0 && char_start + char_len == i && is_utf8_whitespace(&str[char_start])) {
            i = char_start;
        } else {
            break;
        }
    }

    str[i] = '\0';
}

/**
 * Removes leading and trailing whitespace from a UTF-8 string in-place.
 *
 * @param str The null-terminated UTF-8 string to modify. NULL is safely
 *            ignored.
 */
void utf8_trim(char* str) {
    if (!str) {
        return;
    }
    utf8_ltrim(str);
    utf8_rtrim(str);
}

/**
 * Removes leading and trailing characters from a UTF-8 string in-place.
 *
 * Any codepoint appearing in `chars` is trimmed from both ends of `str`.
 *
 * @param str The null-terminated UTF-8 string to modify. NULL is safely
 *            ignored.
 * @param chars String containing codepoints to trim. NULL is safely
 *              ignored.
 * @note At most 256 distinct trim codepoints are tracked; additional
 *       distinct codepoints in `chars` beyond that are ignored. This limit
 *       comfortably covers realistic call sites (a handful of punctuation
 *       or bracket characters) while keeping the working set on the stack.
 */
void utf8_trim_chars(char* str, const char* chars) {
    if (!str || !chars) {
        return;
    }

    enum { MAX_TRIM_CODEPOINTS = 256 };
    uint32_t trim_codepoints[MAX_TRIM_CODEPOINTS];
    size_t num_trim_chars = 0;
    size_t chars_len = strlen(chars);

    /* Build the de-duplicated set of codepoints to trim. */
    for (size_t k = 0; k < chars_len && num_trim_chars < MAX_TRIM_CODEPOINTS;) {
        size_t current_char_len = utf8_char_length(&chars[k]);
        if (current_char_len == 0 || k + current_char_len > chars_len) {
            k++;
            continue;
        }

        uint32_t codepoint = utf8_to_codepoint(&chars[k]);
        if (codepoint != 0xFFFD) {
            bool found = false;
            for (size_t idx = 0; idx < num_trim_chars; idx++) {
                if (trim_codepoints[idx] == codepoint) {
                    found = true;
                    break;
                }
            }
            if (!found && num_trim_chars < MAX_TRIM_CODEPOINTS) {
                trim_codepoints[num_trim_chars++] = codepoint;
            }
        }
        k += current_char_len;
    }

    size_t len = strlen(str);

    /* Trim from the front. */
    size_t i = 0;
    while (i < len) {
        size_t current_char_len = utf8_char_length(&str[i]);
        if (current_char_len == 0 || i + current_char_len > len) {
            break;
        }

        uint32_t codepoint = utf8_to_codepoint(&str[i]);
        bool should_trim = false;
        if (codepoint != 0xFFFD) {
            for (size_t j = 0; j < num_trim_chars; j++) {
                if (codepoint == trim_codepoints[j]) {
                    should_trim = true;
                    break;
                }
            }
        }

        if (!should_trim) {
            break;
        }
        i += current_char_len;
    }

    if (i > 0) {
        memmove(str, &str[i], len - i + 1);
        len -= i;
    }

    /* Trim from the back. */
    i = len;
    while (i > 0) {
        size_t char_start = i - 1;
        while (char_start > 0 && ((unsigned char)str[char_start] & 0xC0) == 0x80) {
            char_start--;
        }

        if (((unsigned char)str[char_start] & 0xC0) == 0x80) {
            /* Could not find a leading byte; the buffer is malformed near
             * its end. Stop rather than misinterpret a continuation byte
             * as a character start. */
            break;
        }

        size_t char_len = utf8_char_length(&str[char_start]);
        if (char_len == 0 || char_start + char_len != i) {
            break;
        }

        uint32_t codepoint = utf8_to_codepoint(&str[char_start]);
        bool should_trim = false;
        if (codepoint != 0xFFFD) {
            for (size_t j = 0; j < num_trim_chars; j++) {
                if (codepoint == trim_codepoints[j]) {
                    should_trim = true;
                    break;
                }
            }
        }

        if (!should_trim) {
            break;
        }
        i = char_start;
    }

    str[i] = '\0';
}

/**
 * Removes leading and trailing occurrences of a single character.
 *
 * @param str The null-terminated UTF-8 string to modify. NULL is safely
 *            ignored.
 * @param c The ASCII character to trim. Only single-byte characters are
 *          supported; this function does not interpret multi-byte UTF-8
 *          sequences.
 */
void utf8_trim_char(char* str, char c) {
    if (!str) {
        return;
    }

    size_t len = strlen(str);
    size_t i = 0;
    while (i < len && str[i] == c) {
        i++;
    }

    if (i > 0) {
        memmove(str, &str[i], len - i + 1);
        len -= i;
    }

    while (len > 0 && str[len - 1] == c) {
        len--;
    }
    str[len] = '\0';
}

/**
 * Converts all uppercase characters in a UTF-8 string to lowercase in-place.
 *
 * @param str The null-terminated UTF-8 string to modify. NULL is safely
 *            ignored.
 * @note May change the byte length of the string if a case-converted
 *       codepoint re-encodes to a different number of UTF-8 bytes (this is
 *       rare but possible for certain scripts).
 * @note Codepoints above what this platform's wchar_t can represent are
 *       left unchanged rather than passed to towlower(), since doing so
 *       would be undefined behavior on platforms with a 16-bit wchar_t
 *       (e.g. Windows). On platforms with a 32-bit wchar_t (Linux, macOS)
 *       this restriction never triggers and every codepoint is handled.
 */
void utf8_tolower(char* str) {
    if (!str) {
        return;
    }

    for (size_t i = 0; str[i] != '\0';) {
        unsigned char byte = (unsigned char)str[i];

        /* ---- ASCII fast path (covers the vast majority of real text) ---- */
        if (byte < 0x80u) {
            /* Branchless lowercase: set bit 5 only when byte is 'A'..'Z'. */
            unsigned int is_upper = (unsigned int)(byte - 'A' + 1u <= 26u);
            str[i] = (char)(byte | (is_upper << 5));
            i++;
            continue;
        }

        /* ---- Multibyte path ---- */
        uint32_t codepoint = utf8_to_codepoint(&str[i]);
        size_t old_len = utf8_char_length(&str[i]);
        if (old_len == 0) {
            break;  // malformed byte; stop rather than loop on it
        }

#if WCHAR_MAX < UNICODE_MAX_CODEPOINT
        if (codepoint > (uint32_t)WCHAR_MAX) {
            i += old_len;  // outside what towlower() can safely accept here
            continue;
        }
#endif

        if (iswupper((wint_t)codepoint)) {
            char utf8[UTF8_MAX_LEN] = {0};
            ucp_to_utf8((uint32_t)towlower((wint_t)codepoint), utf8);
            size_t new_len = utf8_valid_byte_count(utf8);

            if (new_len != old_len) {
                size_t remaining = strlen(&str[i + old_len]);
                memmove(&str[i + new_len], &str[i + old_len], remaining + 1);
            }
            memcpy(&str[i], utf8, new_len);
            i += new_len;
        } else {
            i += old_len;
        }
    }
}

/**
 * Converts all lowercase characters in a UTF-8 string to uppercase in-place.
 *
 * @param str The null-terminated UTF-8 string to modify. NULL is safely
 *            ignored.
 * @note May change the byte length of the string if a case-converted
 *       codepoint re-encodes to a different number of UTF-8 bytes.
 * @note See utf8_tolower() for the WCHAR_MAX safety note; the same
 *       reasoning applies here with towupper()/iswlower().
 */
void utf8_toupper(char* str) {
    if (!str) {
        return;
    }

    for (size_t i = 0; str[i] != '\0';) {
        unsigned char byte = (unsigned char)str[i];

        /* ---- ASCII fast path ---- */
        if (byte < 0x80u) {
            /* Branchless uppercase: clear bit 5 only when byte is 'a'..'z'. */
            unsigned int is_lower = (unsigned int)(byte - 'a' + 1u <= 26u);
            str[i] = (char)(byte & (unsigned char)~(is_lower << 5));
            i++;
            continue;
        }

        /* ---- Multibyte path ---- */
        uint32_t codepoint = utf8_to_codepoint(&str[i]);
        size_t old_len = utf8_char_length(&str[i]);
        if (old_len == 0) {
            break;  // malformed byte; stop rather than loop on it
        }

#if WCHAR_MAX < UNICODE_MAX_CODEPOINT
        if (codepoint > (uint32_t)WCHAR_MAX) {
            i += old_len;  // outside what towupper() can safely accept here
            continue;
        }
#endif

        if (iswlower((wint_t)codepoint)) {
            char utf8[UTF8_MAX_LEN] = {0};
            ucp_to_utf8((uint32_t)towupper((wint_t)codepoint), utf8);
            size_t new_len = utf8_valid_byte_count(utf8);

            if (new_len != old_len) {
                size_t remaining = strlen(&str[i + old_len]);
                memmove(&str[i + new_len], &str[i + old_len], remaining + 1);
            }
            memcpy(&str[i], utf8, new_len);
            i += new_len;
        } else {
            i += old_len;
        }
    }
}

/* ============================================================================
 * String Splitting and Array Functions
 * ============================================================================ */

/**
 * Builds a utf8_string from a raw byte span in one allocation.
 *
 * Used by utf8_split(): the source span comes from an already-analyzed
 * utf8_string, so re-running full validation would be wasted work.  The
 * codepoint count is computed with the cheap leading-byte classification
 * (same rule as utf8_count_codepoints).
 */
static utf8_string* utf8_span_to_string(const char* start, size_t len) {
    utf8_string* part = utf8_string_alloc(len);
    if (!part) {
        return NULL;
    }

    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        part->data[i] = start[i];
        if (((unsigned char)start[i] & 0xC0) != 0x80) {
            count++;
        }
    }
    part->data[len] = '\0';
    part->length = len;
    part->count = count;
    return part;
}

/**
 * Splits a UTF-8 string into parts using a delimiter.
 *
 * The string is divided at each occurrence of the delimiter. Empty parts
 * (when the delimiter appears consecutively, or at the start/end of the
 * string) are included in the result.
 *
 * @param str The utf8_string to split. Must not be NULL.
 * @param delim The delimiter string. Must not be NULL or empty.
 * @param num_parts Output parameter receiving the number of parts. Must not
 *                  be NULL. Set to 0 on any error.
 * @return Array of utf8_string pointers, or NULL on error.
 * @note Caller must free using utf8_split_free().
 * @note If an allocation fails partway through building the result, every
 *       part allocated so far is freed and the function returns NULL with
 *       *num_parts set to 0, rather than returning a partially-populated
 *       array containing NULL holes.
 */
utf8_string** utf8_split(const utf8_string* str, const char* delim, size_t* num_parts) {
    if (!num_parts) {
        return NULL;
    }
    *num_parts = 0;

    if (!str || !str->data || !delim) {
        return NULL;
    }

    size_t delim_len = utf8_valid_byte_count(delim);
    if (delim_len == 0) {
        return NULL;
    }

    /* First pass: count how many parts the split will produce. */
    size_t count = 1;
    size_t len = str->length;
    for (size_t i = 0; i < len;) {
        if (i + delim_len <= len && memcmp(&str->data[i], delim, delim_len) == 0) {
            count++;
            i += delim_len;
        } else {
            size_t char_len = utf8_char_length(&str->data[i]);
            if (char_len == 0) {
                break;  // malformed byte; stop scanning, finish with what we have
            }
            i += char_len;
        }
    }

    utf8_string** parts = (utf8_string**)malloc(count * sizeof(*parts));
    if (!parts) {
        return NULL;
    }

    /* Second pass: carve each part straight into its own single-block
     * utf8_string — no temporary buffer, no re-validation (Perf #14). */
    size_t index = 0;
    size_t start = 0;
    for (size_t i = 0; i < len;) {
        if (i + delim_len <= len && memcmp(&str->data[i], delim, delim_len) == 0) {
            parts[index] = utf8_span_to_string(&str->data[start], i - start);
            if (!parts[index]) {
                goto split_alloc_failed;
            }
            index++;

            i += delim_len;
            start = i;
        } else {
            size_t char_len = utf8_char_length(&str->data[i]);
            if (char_len == 0) {
                break;
            }
            i += char_len;
        }
    }

    /* Final trailing part, from `start` to the end of the string. */
    {
        parts[index] = utf8_span_to_string(&str->data[start], len - start);
        if (!parts[index]) {
            goto split_alloc_failed;
        }
        index++;
    }

    *num_parts = index;
    return parts;

split_alloc_failed:
    /* Clean up every part successfully built so far, then the array itself,
     * so the caller never has to special-case a partially-filled result. */
    for (size_t k = 0; k < index; k++) {
        utf8_free(parts[k]);
    }
    free(parts);
    *num_parts = 0;
    return NULL;
}

/**
 * Frees an array of utf8_string objects returned by utf8_split().
 *
 * @param str The array of utf8_string pointers. NULL is safely ignored.
 * @param size The number of elements in the array.
 */
void utf8_split_free(utf8_string** str, size_t size) {
    if (!str) {
        return;
    }

    for (size_t i = 0; i < size; i++) {
        utf8_free(str[i]);
    }
    free(str);
}

/**
 * Removes an element from a utf8_string array and frees it.
 *
 * Elements after the removed index are shifted down by one position; the
 * caller is responsible for tracking that the logical size of the array
 * has decreased by one after this call.
 *
 * @param array The array of utf8_string pointers. Must not be NULL.
 * @param size The current size of the array.
 * @param index The index to remove. Must be < size.
 */
void utf8_array_remove(utf8_string** array, size_t size, size_t index) {
    if (!array || index >= size) {
        return;
    }

    utf8_free(array[index]);
    for (size_t i = index; i < size - 1; i++) {
        array[i] = array[i + 1];
    }
    array[size - 1] = NULL;
}

/* ============================================================================
 * File I/O Functions
 * ============================================================================ */

/**
 * Writes a utf8_string to a file.
 *
 * @param s The utf8_string to write. Must not be NULL.
 * @param filename The file path. Existing files are overwritten. Must not
 *                 be NULL.
 * @return The number of bytes written, or -1 on error (including a short
 *         write).
 */
long utf8_writeto(const utf8_string* s, const char* filename) {
    if (!s || !s->data || !filename) {
        return -1;
    }

    FILE* file = fopen(filename, "w");
    if (!file) {
        return -1;
    }

    size_t bytes = fwrite(s->data, 1, s->length, file);
    int close_rc = fclose(file);

    if (bytes != s->length || close_rc != 0) {
        return -1;
    }

    return (long)bytes;
}

/**
 * Reads a UTF-8 string from a file.
 *
 * @param filename The file path to read from. Must not be NULL.
 * @return A newly allocated utf8_string containing the file contents, or
 *         NULL on error (including I/O failure or allocation failure).
 * @note Caller must free the returned object using utf8_free().
 */
utf8_string* utf8_readfrom(const char* filename) {
    if (!filename) {
        return NULL;
    }

    FILE* file = fopen(filename, "r");
    if (!file) {
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }

    long length = ftell(file);
    if (length < 0) {
        fclose(file);
        return NULL;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }

    /*
     * Perf: read directly into the final single-allocation block instead
     * of a temporary buffer + utf8_new() copy.  The valid-prefix analysis
     * still runs (same contract as utf8_new): the string is truncated at
     * the first malformed sequence, and capacity reflects the full read.
     */
    utf8_string* s = utf8_string_alloc((size_t)length);
    if (!s) {
        fclose(file);
        return NULL;
    }

    size_t bytes = fread(s->data, 1, (size_t)length, file);
    fclose(file);
    s->data[bytes] = '\0';

    utf8_analysis_t analysis = utf8_analyze(s->data);
    s->data[analysis.valid_bytes] = '\0';
    s->length = analysis.valid_bytes;
    s->count = analysis.codepoints;
    return s;
}
